<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Config\ConfigValue;
use SineMacula\Laravel\Authorization\Config\ModelClasses;
use SineMacula\Laravel\Authorization\Config\SwitchConfigValidator;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\DependencyPhase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\StatementValidator;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The principals and identities a change to a shared definition reaches (see
 * `Impact`), read set by set, never holder by holder: the grantees of a role
 * and of every role below it, the grantees of a permission and the holders of
 * every role carrying it, the subjects a policy is attached to, the holders of
 * every role it is attached to, the subjects it bounds, and the principals its
 * allows name when it is attached to a resource, the holders of a role a
 * selector names included.
 *
 * Each set is read in one query, on the write connection, outside every tenant
 * scope, whatever tenant or application the grant holds in and whether or not
 * it has expired, since re-arming a grant restores what it carried; the roles
 * below a role in one recursive query. The read is bounded by
 * `authorization.administration.max_impact` (1000 by default), counted in
 * distinct holders: each query asks for its distinct holders, at most one more
 * than the limit, whatever the sets read before it hold, so a holder named
 * twice, by one set or by two, never uses up the room of one not yet read.
 * Every query then reads either all its holders, or more than the limit alone
 * holds, and once the holders of every set, merged, are more than the limit,
 * the set is over its limit, and the change it would weigh cannot be proved
 * (see `Impact`), so the reach of a change is never approximated. A principal
 * named by a document that cannot be read puts the set over its limit too.
 *
 * Inside a delegated operation, every set within the limit has its rows locked
 * and pinned, and is read from the rows as locked (see `DependencyPins`), the
 * roles named, and with the hierarchy those below them and every role whose
 * parent is one of them, so a holder granted, or a role re-parented below,
 * meanwhile has the operation tried again rather than written past it. A set
 * over the limit is never locked: the change is refused as it is. A role's row
 * is locked whether or not the hierarchy is on, so a change that reaches a
 * role's holders, such as a resource policy naming the role, and a concurrent
 * grant of that role, which locks the same row, never both commit unseen.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AffectedHolders
{
    /** @var int The most holders a change is weighed against when none is configured. */
    public const int DEFAULT_LIMIT = 1000;

    /** @var string The name the recursive query gives the roles it walks down to. */
    private const string BELOW = 'authorization_roles_below';

    /** @var array<string, \SineMacula\Laravel\Authorization\Support\Reference> The holders read so far, by type and key. */
    private array $holders = [];

    /** @var bool Whether more holders were found than the limit allows, or some could not be read. */
    private bool $isOver = false;

    /**
     * Create an empty set of holders.
     *
     * @param  int  $limit
     */
    private function __construct(

        /** The most holders the set may hold. */
        private readonly int $limit,
    ) {}

    /**
     * Return an empty set, bounded by
     * `authorization.administration.max_impact`.
     *
     * @return self
     */
    public static function none(): self
    {
        return new self(self::limit());
    }

    /**
     * Return the most rows a read of what a change reaches takes:
     * `authorization.administration.max_impact`, or the default when it is left
     * out, refusing one that is not a whole number of at least one.
     *
     * @return int
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function limit(): int
    {
        return ConfigValue::integer('administration.max_impact', self::DEFAULT_LIMIT, 1);
    }

    /**
     * Add the grantees of the roles with the keys, and of every role below them
     * when the hierarchy is enabled.
     *
     * @param  list<string>  $keys
     * @return self
     */
    public function ofRoles(array $keys): self
    {
        if ($keys === [] || $this->isOver) {
            return $this;
        }

        $this->addFrom(self::table('authorizable_roles')->whereIn('role_id', self::withRolesBelow($keys)));

        return $this;
    }

    /**
     * Add the grantees of the permission, and the holders of every role that
     * carries it.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @return self
     */
    public function ofPermission(Permission $permission): self
    {
        $this->addFrom(self::table('authorizable_permissions')->where('permission_id', $permission->getKey()));

        return $this->ofRoles($this->keysFrom(self::table('role_permissions')->where('permission_id', $permission->getKey()), 'role_id'));
    }

    /**
     * Add the subjects the policy is attached to or bounds, the holders of
     * every role it is attached to, and, when it is attached to a resource, the
     * principals the allows of each document name, its own and any it is to be
     * given.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\Policy|null>  $documents
     * @return self
     */
    public function ofPolicy(Policy $policy, array $documents): self
    {
        $key  = $policy->getKey();
        $role = self::roleType();

        $this->addFrom(self::table('authorizable_policies')->where('policy_id', $key)->where('authorizable_type', '!=', $role));
        $this->addFrom(self::table('authorizable_boundaries')->where('policy_id', $key));
        $this->ofRoles($this->keysFrom(self::table('authorizable_policies')->where('policy_id', $key)->where('authorizable_type', $role), 'authorizable_id'));

        if (!self::isAttachedToResource($key)) {
            return $this;
        }

        foreach ($documents as $document) {
            $this->ofPrincipals($document);
        }

        return $this;
    }

    /**
     * Add the principals the allows of the document name, the holders of each
     * role a selector names included; a document that cannot be read puts the
     * set over its limit.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy|null  $document
     * @return self
     */
    public function ofPrincipals(?EvaluationPolicy $document): self
    {
        $roles = [];

        foreach ($document === null ? [] : $document->statements as $statement) {
            foreach ($statement->effect === PolicyEffect::ALLOW ? $statement->principals ?? [] : [] as $selector) {
                [$type, $id] = \explode(':', $selector, 2);

                if ($type === StatementValidator::ROLE_SELECTOR) {
                    $roles[] = $id;

                    continue;
                }

                $this->add(new Reference($type, $id));
            }
        }

        $this->isOver = $this->isOver || $document === null;

        return $this->ofRoles($roles);
    }

    /**
     * Return the holders, each once, or null when there are more than the limit
     * allows, or some could not be read.
     *
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>|null
     */
    public function holders(): ?array
    {
        return $this->isOver ? null : \array_values($this->holders);
    }

    /**
     * Add the distinct grantees the query of a grant table selects, at most one
     * more than the limit, whatever holders the set already has: a query that
     * finds more than the limit puts the set over it alone, and one that finds
     * no more reads every holder it selects.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @return void
     */
    private function addFrom(Builder $query): void
    {
        if ($this->isOver) {
            return;
        }

        foreach ($this->within($query, ['authorizable_type', 'authorizable_id']) as $row) {
            /** @var array{authorizable_type: string, authorizable_id: int|string} $columns */
            $columns = $row;

            $this->add(new Reference($columns['authorizable_type'], (string) $columns['authorizable_id']));
        }
    }

    /**
     * Return the keys in the column the query selects, each once, at most one
     * more than the limit, so a set reaching that many roles is over its limit;
     * a set already over it reads none.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $column
     * @return list<string>
     */
    private function keysFrom(Builder $query, string $column): array
    {
        if ($this->isOver) {
            return [];
        }

        /** @var list<string> $keys */
        $keys = \array_column($this->within($query, [$column]), $column);

        $this->isOver = \count($keys) > $this->limit;

        return $keys;
    }

    /**
     * Return the distinct values of the columns in the rows the query selects,
     * at most one more than the limit. Inside a delegated operation, a set
     * within the limit is then locked and pinned (see `DependencyPins`), and
     * the values are those of the rows as locked, so the decision reads what
     * the locks hold and a holder granted meanwhile is either seen or noticed
     * before the write; a set over the limit is refused as it is, never locked,
     * so a change reaching more holders than the limit never locks them all.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  list<string>  $columns
     * @return list<array<array-key, mixed>>
     *
     * @throws \LogicException
     */
    private function within(Builder $query, array $columns): array
    {
        $rows = [];
        $pins = OperationScope::pins();

        foreach ((clone $query)->distinct()->limit($this->limit + 1)->get($columns) as $row) {
            $rows[] = (array) $row;
        }

        if ($pins === null || \count($rows) > $this->limit) {
            return $rows;
        }

        $distinct = [];

        foreach ($pins->lock(DependencyPhase::HOLDERS, $query) as $row) {
            $values = \array_intersect_key($row, \array_flip($columns));

            $distinct[\serialize($values)] = $values;
        }

        return \array_values($distinct);
    }

    /**
     * Determine whether the policy is attached to any resource; inside a
     * delegated operation, one attachment, if any, is locked and pinned, so a
     * last attachment detached or a first one made meanwhile is noticed before
     * the write, without locking every attachment of the policy.
     *
     * @param  mixed  $policy
     * @return bool
     *
     * @throws \LogicException
     */
    private static function isAttachedToResource(mixed $policy): bool
    {
        $query = self::table('resource_policies')->where('policy_id', $policy);
        $pins  = OperationScope::pins();

        return $pins === null ? $query->exists() : $pins->lock(DependencyPhase::HOLDERS, $query->select('policy_id')->limit(1)) !== [];
    }

    /**
     * Add the holder, once, putting the set over its limit when it is one too
     * many.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $holder
     * @return void
     */
    private function add(Reference $holder): void
    {
        $this->holders[\serialize([$holder->type, $holder->id])] = $holder;

        $this->isOver = $this->isOver || \count($this->holders) > $this->limit;
    }

    /**
     * Return the keys of the roles and of every role below them, each once, as
     * one recursive query that ignores the tenant scope reads them; with the
     * hierarchy disabled, the roles alone, without a query. A key that names no
     * role names no grant either, so the query, which reads the roles that
     * exist, leaves it out.
     *
     * `union` rather than `union all` drops a row already produced, so a cycle
     * in the stored hierarchy ends the recursion.
     *
     * @param  list<string>  $keys
     * @return list<mixed>
     */
    private static function withRolesBelow(array $keys): array
    {
        $hierarchy = SwitchConfigValidator::isEnabled('hierarchy');

        if (!$hierarchy) {
            self::pin(self::table('roles')->whereIn('id', $keys));

            return $keys;
        }

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $class */
        $class      = ModelClasses::get('role');
        $model      = new $class;
        $connection = $model->getConnection();
        $grammar    = $connection->getQueryGrammar();
        $table      = $grammar->wrapTable($model->getTable());
        $key        = $grammar->wrap($model->getKeyName());
        $parent     = $grammar->wrap('parent_id');
        $below      = $grammar->wrap(self::BELOW);
        $marks      = \implode(', ', \array_map(static fn (): string => '?', $keys));

        $rows = $connection->selectFromWriteConnection(
            "with recursive {$below} ({$key}) as ("
                . "select {$key} from {$table} where {$key} in ({$marks})"
                . " union select {$table}.{$key} from {$table}"
                . " inner join {$below} on {$table}.{$parent} = {$below}.{$key}"
                . ") select {$key} from {$below}",
            $keys,
        );

        $below = \array_column($rows, $model->getKeyName());

        self::pin(self::table('roles')->whereIn($model->getKeyName(), $below)->orWhereIn('parent_id', $below));

        return $below;
    }

    /**
     * Lock and pin the rows of the roles the query selects, when the operation
     * whose work is running is delegated (see `DependencyPins`), so a role
     * re-parented in or out meanwhile is noticed before the change is written,
     * and a concurrent grant of one of them, which locks its row too, waits for
     * the operation or is seen by it.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @return void
     *
     * @throws \LogicException
     */
    private static function pin(Builder $query): void
    {
        OperationScope::pins()?->lock(DependencyPhase::HOLDERS, $query);
    }

    /**
     * Return a query of the table the config names under the key, on the
     * package's connection and its write connection.
     *
     * @param  string  $key
     * @return \Illuminate\Database\Query\Builder
     */
    private static function table(string $key): Builder
    {
        $table = TableNames::get($key);

        return AuthorizationConnection::connection()->table($table)->useWritePdo();
    }

    /**
     * Return the morph type of the configured role model.
     *
     * @return string
     */
    private static function roleType(): string
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $class */
        $class = ModelClasses::get('role');

        return (new $class)->getMorphClass();
    }
}
