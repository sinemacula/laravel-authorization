<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\DependencyPhase;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\RoleGraph;

/**
 * The rows that make up authority, gathered for one part of a delegated
 * operation's dependencies and locked through its pins (see `DependencyPins`)
 * in one fixed order, so every operation takes its locks alike:
 *
 * 1. the grant rows of each grantee named, table by table: its roles, its
 *    permissions, its policies and its boundaries;
 * 2. the chain of each tenant named, read afresh, and the guardrails on the
 *    platform and on every tenant of those chains;
 * 3. the resource policies of each resource type named;
 * 4. the roles named or held and every role above them, then the permissions
 *    those roles carry, then the policies attached to them;
 * 5. the permissions named, held or carried;
 * 6. the policies named, attached, bounding, guarding or attached to a resource
 *    type, whose documents the decision reads.
 *
 * Keys are sorted within each query, and every query reads on the write
 * connection, outside every tenant scope, whether or not a grant has expired,
 * so a re-armed grant's authority is pinned too.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AuthorityRows
{
    /** @var array<string, \SineMacula\Laravel\Authorization\Support\Reference> The grantees whose grant rows are locked, by type and key. */
    private array $grantees = [];

    /** @var list<\SineMacula\Laravel\Authorization\Support\Reference|null>|null The tenants whose chains and guardrails are locked, null for the platform; null when guardrails are not locked at all. */
    private ?array $tenants = null;

    /** @var list<string> The resource types whose resource policies are locked. */
    private array $resources = [];

    /** @var list<string> The keys of the roles whose chains are locked. */
    private array $roles = [];

    /** @var list<string> The keys of the permissions whose rows are locked. */
    private array $permissions = [];

    /** @var list<string> The keys of the policies whose rows are locked. */
    private array $policies = [];

    /**
     * Create an empty gathering for the part.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\DependencyPins  $pins
     * @param  \SineMacula\Laravel\Authorization\Enums\DependencyPhase  $phase
     */
    private function __construct(

        /** The pins the rows are locked through. */
        private readonly DependencyPins $pins,

        /** The part of the operation's dependencies the rows are locked for. */
        private readonly DependencyPhase $phase,
    ) {}

    /**
     * Return an empty gathering for the part, locked through the pins.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\DependencyPins  $pins
     * @param  \SineMacula\Laravel\Authorization\Enums\DependencyPhase  $phase
     * @return self
     */
    public static function in(DependencyPins $pins, DependencyPhase $phase): self
    {
        return new self($pins, $phase);
    }

    /**
     * Add the grant rows of the grantees, and what they hold.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  ...$grantees
     * @return self
     */
    public function grantees(Reference ...$grantees): self
    {
        foreach ($grantees as $grantee) {
            $this->grantees[\serialize([$grantee->type, $grantee->id])] = $grantee;
        }

        return $this;
    }

    /**
     * Add the chains of the tenants, null for the platform, and the guardrails
     * on the platform and on every tenant of those chains.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  ...$tenants
     * @return self
     */
    public function tenants(?Reference ...$tenants): self
    {
        $this->tenants = [...$this->tenants ?? [], ...\array_values($tenants)];

        return $this;
    }

    /**
     * Add the resource policies attached to the resource type, to its records
     * or to the whole type.
     *
     * @param  string  $type
     * @return self
     */
    public function resources(string $type): self
    {
        $this->resources[] = $type;

        return $this;
    }

    /**
     * Add the roles, every role above them, and what they carry.
     *
     * @param  string  ...$keys
     * @return self
     */
    public function roles(string ...$keys): self
    {
        $this->roles = [...$this->roles, ...\array_values($keys)];

        return $this;
    }

    /**
     * Add the permissions' rows.
     *
     * @param  string  ...$keys
     * @return self
     */
    public function permissions(string ...$keys): self
    {
        $this->permissions = [...$this->permissions, ...\array_values($keys)];

        return $this;
    }

    /**
     * Add the policies' rows.
     *
     * @param  string  ...$keys
     * @return self
     */
    public function policies(string ...$keys): self
    {
        $this->policies = [...$this->policies, ...\array_values($keys)];

        return $this;
    }

    /**
     * Add what a change changes: the chain of the tenant it holds in and the
     * guardrails there; for a grant or a removal, the grantee's grant rows, or
     * a role grantee's chain, or the resource policies of the resource type a
     * policy is attached to, and the role, permission or policy handed out or
     * taken away; for a definition, the record and, for a parent set, the new
     * parent's chain.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $change
     * @return self
     */
    public function change(OperationResource $change): self
    {
        $this->tenants($change->tenant);

        $grant = $change->change;

        if ($grant !== null) {
            $this->grantee($change->action, $grant->grantee)->record($grant->target);
        }

        $parent = $change->definition?->values['parent'] ?? null;

        $this->record($change->definition?->record)->roles(...(\is_string($parent) ? [$parent] : []));

        return $this;
    }

    /**
     * Lock every row gathered, in the documented order.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function lock(): void
    {
        $this->lockGrants();
        $this->lockGuardrails();

        if ($this->resources !== []) {
            $this->policies(...$this->lockKeys(self::table('resource_policies')->whereIn('resource_type', self::sorted($this->resources)), 'policy_id'));
        }

        $this->lockRoles();
        $this->lockRecords('permissions', $this->permissions);
        $this->lockRecords('policies', $this->policies);
    }

    /**
     * Add the grantee of a grant or a removal under the action: the resource
     * type a resource policy is attached to, a role, or a subject.
     *
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return self
     */
    private function grantee(string $action, Reference $grantee): self
    {
        if (\in_array($action, [PackagePermissions::RESOURCE_POLICY_ATTACH, PackagePermissions::RESOURCE_POLICY_DETACH], true)) {
            return $this->resources($grantee->type);
        }

        return OperationGrantee::isRole($grantee) ? $this->roles($grantee->id) : $this->grantees($grantee);
    }

    /**
     * Add a saved role, permission or policy by its key; anything else, or a
     * record not saved yet, adds nothing.
     *
     * @param  \Illuminate\Database\Eloquent\Model|null  $record
     * @return self
     */
    private function record(?Model $record): self
    {
        $key = $record?->getKey();

        if (!\is_scalar($key)) {
            return $this;
        }

        return match (true) {
            $record instanceof Role       => $this->roles((string) $key),
            $record instanceof Permission => $this->permissions((string) $key),
            $record instanceof Policy     => $this->policies((string) $key),
            default                       => $this,
        };
    }

    /**
     * Lock the grant rows of every grantee, table by table, and add the roles,
     * permissions and policies they name.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function lockGrants(): void
    {
        if ($this->grantees === []) {
            return;
        }

        \ksort($this->grantees, \SORT_STRING);

        $grantees = \array_values($this->grantees);
        $pairs    = static fn (Builder $query): Builder => self::pairs($query, 'authorizable_type', 'authorizable_id', $grantees);

        $this->roles(...$this->lockKeys($pairs(self::table('authorizable_roles')), 'role_id'));
        $this->permissions(...$this->lockKeys($pairs(self::table('authorizable_permissions')), 'permission_id'));
        $this->policies(...$this->lockKeys($pairs(self::table('authorizable_policies')), 'policy_id'));
        $this->policies(...$this->lockKeys($pairs(self::table('authorizable_boundaries')), 'policy_id'));
    }

    /**
     * Pin the chain of every tenant, then lock the guardrails on the platform
     * and on every tenant of those chains, and add their policies.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function lockGuardrails(): void
    {
        if ($this->tenants === null) {
            return;
        }

        $chained = [];

        foreach ($this->pins->lockChains($this->phase, ...$this->tenants) as $tenant) {
            $chained[\serialize([$tenant->type, $tenant->id])] = $tenant;
        }

        \ksort($chained, \SORT_STRING);

        $query = self::table('guardrails')->where(static function (Builder $where) use ($chained): void {
            $where->where(static fn (Builder $platform): Builder => $platform->whereNull('tenant_type')->whereNull('tenant_id'));

            self::pairs($where, 'tenant_type', 'tenant_id', \array_values($chained), 'or');
        });

        $this->policies(...$this->lockKeys($query, 'policy_id'));
    }

    /**
     * Lock the roles gathered and every role above them, then the permissions
     * they carry and the policies attached to them, adding both.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function lockRoles(): void
    {
        if ($this->roles === []) {
            return;
        }

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $class */
        $class = config('authorization.models.role', Role::class);
        $chain = self::sorted(\array_map(\strval(...), \array_keys(RoleGraph::reach(self::sorted($this->roles)))));
        $type  = (new $class)->getMorphClass();

        $this->pins->lock($this->phase, self::table('roles')->whereIn('id', $chain));

        $this->permissions(...$this->lockKeys(self::table('role_permissions')->whereIn('role_id', $chain), 'permission_id'));
        $this->policies(...$this->lockKeys(self::table('authorizable_policies')->where('authorizable_type', $type)->whereIn('authorizable_id', $chain), 'policy_id'));
    }

    /**
     * Lock the rows of the table with the keys.
     *
     * @param  string  $table
     * @param  list<string>  $keys
     * @return void
     *
     * @throws \LogicException
     */
    private function lockRecords(string $table, array $keys): void
    {
        if ($keys === []) {
            return;
        }

        $this->pins->lock($this->phase, self::table($table)->whereIn('id', self::sorted($keys)));
    }

    /**
     * Limit the query to the rows of the references, each matched on the type
     * and key columns, joined to what the query holds already by the boolean.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $type
     * @param  string  $id
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $references
     * @param  string  $boolean
     * @return \Illuminate\Database\Query\Builder
     */
    private static function pairs(Builder $query, string $type, string $id, array $references, string $boolean = 'and'): Builder
    {
        return $query->where(static function (Builder $where) use ($type, $id, $references): void {
            foreach ($references as $reference) {
                $where->orWhere(static fn (Builder $pair): Builder => $pair->where($type, $reference->type)->where($id, $reference->id));
            }
        }, boolean: $boolean);
    }

    /**
     * Return a query of the table the config names under the key, on the
     * package's connection.
     *
     * @param  string  $key
     * @return \Illuminate\Database\Query\Builder
     */
    private static function table(string $key): Builder
    {
        /** @var string $table */
        $table = config('authorization.tables.' . $key, $key);

        return AuthorizationConnection::connection()->table($table);
    }

    /**
     * Lock the rows the query selects and return the keys in their column, each
     * once.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $column
     * @return list<string>
     *
     * @throws \LogicException
     */
    private function lockKeys(Builder $query, string $column): array
    {
        /** @var list<int|string> $keys */
        $keys = \array_column($this->pins->lock($this->phase, $query), $column);

        return \array_values(\array_unique(\array_map(\strval(...), $keys)));
    }

    /**
     * Return the keys, each once, sorted.
     *
     * @param  list<string>  $keys
     * @return list<string>
     */
    private static function sorted(array $keys): array
    {
        $keys = \array_values(\array_unique($keys));

        \sort($keys, \SORT_STRING);

        return $keys;
    }
}
