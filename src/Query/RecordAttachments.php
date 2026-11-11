<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Connection;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\ComposedExpression;
use SineMacula\Laravel\Authorization\Database\GrantApplications;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Query\Enums\ColumnKind;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;
use SineMacula\Laravel\Authorization\Support\TenantColumns;

/**
 * Reads the policies attached to records of the model's type that hold in the
 * scope a class of rows is decided in, and compiles, for each, the condition a
 * row meets when the policy is attached to its record: an `EXISTS` over the
 * attachments, matching the policy, the type and the row's key, and the scope's
 * tenant chain and application, written by the same query builders the resolver
 * reads attachments with (`TenantChain::grants()`,
 * `GrantApplications::only()`), so it is the resolver's own predicate on the
 * row; and the key one an attachment can name, at most 191 bytes, not `*` (as
 * `ResourcePolicyResolver` stores no other). A policy whose denies count on the
 * type's records in every scope, as the resolver reads them (N130, see
 * `inScope()`), is compiled with what attaches it so; with no such policy, each
 * policy is compiled once, with the scope's own predicate alone. Every value of
 * that predicate is inlined as the dialect writes a bound value
 * (`InlinedQuery`), never through the connection's escaping.
 *
 * The key's text is compared with the attachment's under the attachment
 * column's own collation, as the resolver's comparison with that text is: byte
 * for byte on SQLite and PostgreSQL, whose column must compare so, and under
 * the column's collation on MySQL. The policies are read with no query per row,
 * once for each scope a compile decides classes in, at most
 * `authorization.query_scoping.max_attachments` of them that name the action,
 * and at most four times as many in all.
 *
 * Refused: a document that cannot be read (`invalid_policy`); more policies
 * than allowed (`too_many_attachments`); and, only when a policy is attached,
 * attachments kept on another connection than the model's
 * (`attachment_connection`), an attachment column whose collation the key's
 * text cannot be compared under (`attachment_collation`), an integer key that
 * may hold what PHP reads otherwise (`column_type`), and a value that cannot be
 * inlined as the database reads it bound (`inline_value`). Where the query
 * carrying the condition runs, on the write connection as `check()` reads, is
 * the scope's to settle (`AuthorizedQuery`), since the alias the attachments
 * are read under tells it the condition reads them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordAttachments
{
    /** @var string The alias the attachments table is read under, by which a condition reading them is told. */
    public const string ALIAS = 'authz_rp';

    /** @var string The column holding an attached record's key. */
    private const string KEY_COLUMN = 'resource_id';

    /** @var array<string, array{list<\SineMacula\Laravel\Authorization\Evaluation\Policy>|null, array<string, bool>}> The policies read in each scope, null for more than allowed, with those whose denies count everywhere, by the scope's chain and application. */
    private array $read = [];

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
        private readonly ResourcePolicyResolver $resolver,

        /** The model queried. */
        private readonly ResourceShape $shape,

        /** Describes the attachments table. */
        private readonly SchemaInspector $inspector,

        /** The most policies one scope may attach to records of the type. */
        private readonly int $limit,
    ) {}

    /**
     * Return each policy attached to records of the type in the current scope
     * that names the action, with the condition a row meets when it is attached
     * to the row's record, and whether only its denies count, keeping a refusal
     * when the attachments cannot be compiled.
     *
     * A policy whose denies count on records of the type in every scope (see
     * `ResourcePolicyResolver::recordPoliciesFor()`) is read so: a policy
     * naming half a tenant, its denies alone, with the condition a row meets
     * when it is attached to the row's record in any tenant; a policy attached
     * to records by a row naming half a tenant, as any other, and, when it
     * denies the action, with its denies alone, with the condition a row meets
     * when such a row attaches it to the row's record, in one condition with
     * the scope's own when the policy only denies. Every other policy is read
     * with the one condition, as it would be with no such row.
     *
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Query\StatementScreen  $screen
     * @param  bool  $isDenyOnly
     * @return list<array{\SineMacula\Laravel\Authorization\Evaluation\Policy, string, bool}>
     */
    public function inScope(string $action, StatementScreen $screen, bool $isDenyOnly): array
    {
        $chain       = TenantScope::currentChain();
        $application = TenantScope::currentApplication();

        try {
            [$policies, $everywhere] = $this->policiesIn($chain, $application, $action);
        } catch (InvalidPolicyDocumentException) {
            $screen->refuse(new Refusal(RefusalReason::INVALID_POLICY, null, null, null, 'a policy attached to a record cannot be read'));

            return [];
        }

        $keyText = $policies === [] ? null : $this->keyTextOr($screen, $policies === null);

        if ($keyText === null || $policies === null) {
            return [];
        }

        $attached = [];

        foreach ($policies as $policy) {
            $isHalf = $everywhere[$policy->id] ?? null;

            foreach ($this->tenantsOf($policy, $action, $chain, $isHalf) as $index => $tenants) {
                $exists     = $this->existsFor($policy, $keyText, $application, $tenants) ?? $this->refuseInline($screen);
                $attached[] = [$index === 0 ? $policy : $policy->denies(), Conditions::all([$exists, $this->storable()]), $isDenyOnly || $isHalf === true || $index > 0];
            }
        }

        return $attached;
    }

    /**
     * Return the policies attached to records of the type in the scope that
     * name the action, or null for more than allowed, with whether each policy
     * whose denies count on them in every scope names half a tenant itself,
     * read once for each scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\TenantChain  $chain
     * @param  string|null  $application
     * @param  string  $action
     * @return array{list<\SineMacula\Laravel\Authorization\Evaluation\Policy>|null, array<string, bool>}
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    private function policiesIn(TenantChain $chain, ?string $application, string $action): array
    {
        $key = \serialize([$application, $chain->isBelow, $chain->tenants]);

        if (!\array_key_exists($key, $this->read)) {
            $everywhere       = [];
            $policies         = $this->resolver->recordPoliciesFor($this->shape->type, $action, $this->limit, $everywhere);
            $this->read[$key] = [$policies, $everywhere];
        }

        return $this->read[$key];
    }

    /**
     * Return the tenants of the attachments each condition of the policy reads,
     * each a callback limiting a query of the attachments, read under the
     * alias: the scope's own, then, for a policy attached to records by a row
     * naming half a tenant and denying the action, those rows; in one condition
     * when the policy only denies. A policy naming half a tenant itself counts
     * for its denies in every tenant (see `inScope()`).
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $policy
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Support\TenantChain  $chain
     * @param  bool|null  $isHalf
     * @return list<\Closure(\Illuminate\Contracts\Database\Query\Builder, string): mixed>
     */
    private function tenantsOf(Policy $policy, string $action, TenantChain $chain, ?bool $isHalf): array
    {
        $own = static fn (Builder $query, string $alias): Builder => $chain->grants($query, $alias);

        if ($isHalf !== false) {
            return [$isHalf === null ? $own : static fn (Builder $query): Builder => $query];
        }

        $denies       = $policy->denies()->statements;
        $isDenying    = \array_filter($denies, static fn (Statement $deny): bool => $deny->coversAction($action)) !== [];
        $isOnlyDenies = \count($denies) === \count($policy->statements);
        $either       = static fn (Builder $query, string $alias): Builder => TenantColumns::restricting($chain, $query, $alias);
        $halfTenant   = static fn (Builder $query, string $alias): Builder => TenantColumns::whereHalf($query, $alias . '.tenant_type', $alias . '.tenant_id');

        return match (true) {
            !$isDenying   => [$own],
            $isOnlyDenies => [$either],
            default       => [$own, $halfTenant],
        };
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
     * record by an attachment of the tenants given, in the application: the
     * resolver's predicate, written by its builders, with every value inlined
     * as the dialect writes it bound; or null when a value cannot be.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $policy
     * @param  string  $keyText
     * @param  string|null  $application
     * @param  \Closure(\Illuminate\Contracts\Database\Query\Builder, string): mixed  $tenants
     * @return string|null
     */
    private function existsFor(Policy $policy, string $keyText, ?string $application, \Closure $tenants): ?string
    {
        /** @var \Illuminate\Database\Connection $connection */
        $connection = $this->shape->connection;

        $table = self::table();
        $alias = self::ALIAS;

        $query = $connection->query()->from("{$table} as {$alias}")->selectRaw('1')
            ->where("{$alias}.resource_type", $this->shape->type)
            ->where("{$alias}.policy_id", $policy->id)
            ->whereRaw(new ComposedExpression($keyText))
            ->where(static function (Builder $query) use ($tenants, $application, $alias): void {
                $tenants($query, $alias);
                GrantApplications::only($query, $alias, $application);
            });

        $sql = InlinedQuery::sqlOf($query, $this->shape->dialect);

        return $sql === null ? null : 'EXISTS (' . $sql . ')';
    }

    /**
     * Keep the refusal of a value the attachments' predicate cannot inline, and
     * return the condition no row meets.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\StatementScreen  $screen
     * @return string
     */
    private function refuseInline(StatementScreen $screen): string
    {
        $screen->refuse(new Refusal(RefusalReason::INLINE_VALUE, null, null, self::KEY_COLUMN, 'a value of an attachment cannot be inlined'));

        return QueryAuthorizer::NO_ROW;
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
        $shape = $this->shape;

        if ($shape->keyKind !== ColumnKind::STRING) {
            return QueryAuthorizer::EVERY_ROW;
        }

        $length = $shape->dialect->keyLength($shape->key, $shape->keyKind, $shape->isIntegerCast);

        if ($length === null) {
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
        return TableNames::get('resource_policies');
    }
}
