<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Connection;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\GrantApplications;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Query\Enums\ColumnKind;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;

/**
 * Reads the policies attached to records of the model's type that hold in the
 * scope a class of rows is decided in, and compiles, for each, the condition a
 * row meets when the policy is attached to its record (C7, §6): an `EXISTS`
 * over the attachments, matching the policy, the type and the row's key, and
 * the scope's tenant chain and application, written by the same query builders
 * the resolver reads attachments with (`TenantChain::grants()`,
 * `GrantApplications::only()`), so it is the resolver's own predicate on the
 * row; and the key one an attachment can name, at most 191 bytes, not `*` (as
 * `ResourcePolicyResolver` stores no other).
 *
 * The key's text is compared with the attachment's under the attachment
 * column's own collation, as the resolver's comparison with that text is: byte
 * for byte on SQLite and PostgreSQL, whose column must compare so, and under
 * the column's collation on MySQL. The policies are read once per class, with
 * no query per row, at most `authorization.query_scoping.max_attachments` of
 * them.
 *
 * Refused: a document that cannot be read (`invalid_policy`); more policies
 * than allowed (`too_many_attachments`); and, only when a policy is attached,
 * attachments kept on another connection than the model's
 * (`attachment_connection`), an attachment column whose collation the key's
 * text cannot be compared under (`attachment_collation`), and an integer key
 * that may hold what PHP reads otherwise (`column_type`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecordAttachments
{
    /** @var string The alias the attachments table is read under. */
    private const string ALIAS = 'authz_rp';

    /** @var string The column holding an attached record's key. */
    private const string KEY_COLUMN = 'resource_id';

    /**
     * Create a new reader of record attachments.
     *
     * @param  \SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver  $resolver
     * @param  \SineMacula\Laravel\Authorization\Query\ResourceShape  $shape
     * @param  \SineMacula\Laravel\Authorization\Query\SchemaInspector  $inspector
     * @param  int  $limit
     */
    public function __construct(

        /** Reads the policies attached to records. */
        private ResourcePolicyResolver $resolver,

        /** The model queried. */
        private ResourceShape $shape,

        /** Describes the attachments table. */
        private SchemaInspector $inspector,

        /** The most policies one scope may attach to records of the type. */
        private int $limit,
    ) {}

    /**
     * Return each policy attached to records of the type in the current scope
     * that names the action, with the condition a row meets when it is attached
     * to the row's record, and whether only its denies count, keeping a refusal
     * when the attachments cannot be compiled.
     *
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Query\StatementScreen  $screen
     * @param  bool  $isDenyOnly
     * @return list<array{\SineMacula\Laravel\Authorization\Evaluation\Policy, string, bool}>
     */
    public function inScope(string $action, StatementScreen $screen, bool $isDenyOnly): array
    {
        try {
            $policies = $this->resolver->recordPoliciesFor($this->shape->type, $action, $this->limit);
        } catch (InvalidPolicyDocumentException) {
            $screen->refuse(new Refusal(RefusalReason::INVALID_POLICY, null, null, null, 'a policy attached to a record cannot be read'));

            return [];
        }

        $keyText = $policies === [] ? null : $this->keyTextOr($screen, \count($policies) > $this->limit);

        if ($keyText === null) {
            return [];
        }

        $chain       = TenantScope::currentChain();
        $application = TenantScope::currentApplication();
        $attached    = [];

        foreach ($policies as $policy) {
            $attached[] = [$policy, Conditions::all([$this->existsFor($policy, $keyText, $chain, $application), $this->storable()]), $isDenyOnly];
        }

        return $attached;
    }

    /**
     * Return the condition an attachment's key column meets when it holds the
     * row's key's text, or null, keeping a refusal, when there are more
     * policies than allowed or the attachments cannot be compared with the key.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\StatementScreen  $screen
     * @param  bool  $isOverLimit
     * @return string|null
     */
    private function keyTextOr(StatementScreen $screen, bool $isOverLimit): ?string
    {
        $connection = $this->shape->connection;
        $keyText    = $connection === null ? null : $this->keyTextOn($connection);

        $reason = match (true) {
            $isOverLimit                                                                 => RefusalReason::TOO_MANY_ATTACHMENTS,
            $connection?->getName() !== AuthorizationConnection::connection()->getName() => RefusalReason::ATTACHMENT_CONNECTION,
            $keyText === null                                                            => RefusalReason::ATTACHMENT_COLLATION,
            default                                                                      => $this->shape->keyRefusal,
        };

        if ($reason !== null) {
            $screen->refuse(new Refusal($reason, null, null, $reason === RefusalReason::COLUMN_TYPE ? $this->shape->keyName : self::KEY_COLUMN));
        }

        return $reason === null ? $keyText : null;
    }

    /**
     * Return the condition an attachment's key column, on the connection, meets
     * when it holds the row's key's text, under the column's own collation; or
     * null when the column is missing or its collation cannot be applied to the
     * key's text.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return string|null
     */
    private function keyTextOn(Connection $connection): ?string
    {
        $table   = self::table();
        $column  = $this->inspector->columns($connection, $table)[self::KEY_COLUMN] ?? null;
        $isExact = $this->inspector->isExactCollation($connection, $this->shape->dialect, $table, self::KEY_COLUMN);
        $wrapped = $connection->getQueryGrammar()->wrap(self::ALIAS . '.' . self::KEY_COLUMN);

        return $column === null ? null : $this->shape->dialect->equalsKeyText($wrapped, $this->shape->key, $column, $isExact);
    }

    /**
     * Return the condition a row meets when the policy is attached to its
     * record in the scope: the resolver's predicate, written by its builders
     * and inlined.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $policy
     * @param  string  $keyText
     * @param  \SineMacula\Laravel\Authorization\Support\TenantChain  $chain
     * @param  string|null  $application
     * @return string
     */
    private function existsFor(Policy $policy, string $keyText, TenantChain $chain, ?string $application): string
    {
        /** @var \Illuminate\Database\Connection $connection */
        $connection = $this->shape->connection;

        $table = self::table();
        $alias = self::ALIAS;

        $query = $connection->query()->from("{$table} as {$alias}")->selectRaw('1')
            ->where("{$alias}.resource_type", $this->shape->type)
            ->where("{$alias}.policy_id", (string) $policy->id)
            ->whereRaw($keyText)
            ->where(static function (Builder $query) use ($chain, $application, $alias): void {
                $chain->grants($query, $alias);
                GrantApplications::only($query, $alias, $application);
            });

        // Each value is inlined as the connection escapes it, a boolean as the
        // database writes one, never cast to an integer first.
        return 'EXISTS (' . $query->getGrammar()->substituteBindingsIntoRawSql($query->toSql(), $query->getBindings()) . ')';
    }

    /**
     * Return the condition a row's key meets when an attachment can name it: at
     * most the bytes the table stores, and not `*`; every row's when the key's
     * kind bounds it.
     *
     * @return string
     */
    private function storable(): string
    {
        $shape  = $this->shape;
        $length = $shape->dialect->keyLength($shape->key, $shape->keyKind, $shape->isIntegerCast);

        if ($length === null || $shape->keyKind !== ColumnKind::STRING) {
            return QueryAuthorizer::EVERY_ROW;
        }

        return Conditions::all([$length . ' <= ' . Reference::MAX_BYTES, Conditions::not($shape->dialect->equalsBytes($shape->key, '*'))]);
    }

    /**
     * Return the attachments table, as `authorization.tables` names it.
     *
     * @return string
     */
    private static function table(): string
    {
        /** @var string */
        return config('authorization.tables.resource_policies', 'resource_policies');
    }
}
