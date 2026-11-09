<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use Carbon\CarbonImmutable;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\LiveGrants;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Reviews\Enums\ScopeSelection;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Support\GrantRoots;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;

/**
 * One run of an access review: its scope, as the tenant tree answers it once
 * for the whole run, and the instant it is made at, against which every expiry
 * is read, frozen so the run reads one instant throughout.
 *
 * The structural rules are those a check reads (D22), never a second evaluator:
 * a grant counts while it is live (see `LiveGrants`), and applies in a tenant
 * as `TenantChain::grants()` reads it; a role or permission counts in a tenant
 * only when the tenant sees it (`TenantChain::owners()`), as the definition
 * models' tenant scope reads them; and a grant is rooted within a tenant as
 * `GrantRoots::within()` reads it, the tree's subtree query nested whole, never
 * loaded.
 *
 * A role's policy attachment reaches a holder of the role only where both the
 * role's grant and the attachment hold, as `RolePolicies` reads them in a
 * check: in a review of a scope a check is decided in, both apply there, so
 * only their applications must meet; in any other review, their tenants must
 * meet too (see `intersects()`), the tree asked once for each pair of tenants.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReviewRun
{
    /** @var string The column of a definition or grant row naming its tenant's type. */
    private const string TENANT_TYPE = '.tenant_type';

    /** @var string The column of a definition or grant row naming its tenant's key. */
    private const string TENANT_ID = '.tenant_id';

    /** @var array<string, bool> Whether one tenant is within another, as the tree answered, by the pair's key. */
    private array $within = [];

    /**
     * Create a new run.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewScope  $scope
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authorization\Support\TenantChain|null  $chain
     * @param  (\Closure(\Illuminate\Database\Query\Builder, string): void)|null  $rooted
     */
    private function __construct(

        /** The scope the review reads. */
        public readonly ReviewScope $scope,

        /** The instant the review is made at, in UTC. */
        public readonly CarbonImmutable $now,

        /** The chain of the tenant a review of what applies there reads, or the platform's; null for any other review. */
        private readonly ?TenantChain $chain,

        /** The condition a row rooted within the reviewed tenant meets; null for any other review. */
        private readonly ?\Closure $rooted,
    ) {}

    /**
     * Return a run of a review of the scope, made now, reading the tenant tree
     * once for it.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewScope  $scope
     * @return self
     *
     * @throws \UnexpectedValueException
     */
    public static function of(ReviewScope $scope): self
    {
        $now = CarbonImmutable::now('UTC');

        return match ($scope->selection) {
            ScopeSelection::APPLIES_IN    => new self($scope, $now, TenantChain::of($scope->tenant, TenantChain::tree()), null),
            ScopeSelection::ROOTED_WITHIN => new self($scope, $now, null, self::rootedWithin($scope)),
            ScopeSelection::EVERYWHERE    => new self($scope, $now, null, null),
        };
    }

    /**
     * Determine whether the review reads what applies where a check is decided,
     * a tenant or the platform.
     *
     * @return bool
     */
    public function isApplicability(): bool
    {
        return $this->scope->selection === ScopeSelection::APPLIES_IN;
    }

    /**
     * Limit a grant query to the rows of the table the scope selects: those
     * that apply in the reviewed tenant, or at the platform, or those rooted
     * within the reviewed tenant, or every row; and of those, the rows that
     * hold in the application selected.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $table
     * @return \Illuminate\Database\Query\Builder
     */
    public function constrain(Builder $query, string $table): Builder
    {
        $this->chain?->grants($query, $table);

        if ($this->rooted !== null) {
            $rooted = $this->rooted;

            $query->where(static fn (Builder $row) => $rooted($row, $table));
        }

        return $this->scope->application->constrain($query, $table);
    }

    /**
     * Limit a query of the table's rows to those still live at the run's
     * instant.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $table
     * @return \Illuminate\Database\Query\Builder
     */
    public function live(Builder $query, string $table): Builder
    {
        return LiveGrants::only($query, $table, Carbon::instance($this->now));
    }

    /**
     * Limit a query of grant rows naming roles or permissions to those whose
     * definition the reviewed tenant sees, in a review of what applies there;
     * leave any other review's alone. The definition table is matched on the
     * row's key column.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $target
     * @param  string  $column
     * @return \Illuminate\Database\Query\Builder
     */
    public function visible(Builder $query, GrantTarget $target, string $column): Builder
    {
        $chain = $this->chain;

        if ($chain === null || $target === GrantTarget::POLICY) {
            return $query;
        }

        [$table, $key] = Definitions::tableOf($target);

        return $query->whereExists(static function (Builder $definition) use ($chain, $table, $key, $column): void {
            $definition->selectRaw('1')->from($table)->whereColumn($table . '.' . $key, $column);

            $chain->owners($definition, $table . self::TENANT_TYPE, $table . self::TENANT_ID);
        });
    }

    /**
     * Limit a query of policy attachments to roles to those whose role the
     * reviewed tenant sees, in a review of what applies there, as a check
     * reaches a role's policies only through a role it sees; leave any other
     * review's alone. The role's key is matched, as text, on the row's grantee
     * key.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $table
     * @return \Illuminate\Database\Query\Builder
     */
    public function visibleRoles(Builder $query, string $table): Builder
    {
        $chain = $this->chain;

        if ($chain === null) {
            return $query;
        }

        [$roles, $key] = Definitions::tableOf(GrantTarget::ROLE);

        return $query->whereExists(static function (Builder $role) use ($chain, $roles, $key, $table): void {
            $grantee = $role->getGrammar()->wrap($table . '.authorizable_id');

            $role->selectRaw('1')->from($roles)->whereRaw(Definitions::keyAsText($role, $roles . '.' . $key) . ' = ' . $grantee);

            $chain->owners($role, $roles . self::TENANT_TYPE, $roles . self::TENANT_ID);
        });
    }

    /**
     * Determine whether the reviewed tenant sees the role or permission with
     * the key, in a review of what applies there: it exists and its owner is
     * the platform, the tenant or an ancestor; a policy, and any definition in
     * any other review, always.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $target
     * @param  string  $id
     * @return bool
     */
    public function seesDefinition(GrantTarget $target, string $id): bool
    {
        if ($this->chain === null || $target === GrantTarget::POLICY) {
            return true;
        }

        [$table, $key] = Definitions::tableOf($target);

        $query = AuthorizationConnection::connection()->table($table)->useWritePdo()->where($table . '.' . $key, $id);

        return $this->chain->owners($query, $table . self::TENANT_TYPE, $table . self::TENANT_ID)->exists();
    }

    /**
     * Limit a query of a definition table to the definitions the scope selects
     * by their owner: those the reviewed tenant sees, those owned within the
     * reviewed tenant, or every one.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $table
     * @return \Illuminate\Database\Query\Builder
     */
    public function owned(Builder $query, string $table): Builder
    {
        $this->chain?->owners($query, $table . self::TENANT_TYPE, $table . self::TENANT_ID);

        if ($this->rooted !== null) {
            $rooted = $this->rooted;

            $query->where(static fn (Builder $row) => $rooted($row, $table));
        }

        return $query;
    }

    /**
     * Determine whether the reviewed tenant sees a definition owned by the
     * tenant given, or by the platform for none: always, but in a review of
     * what applies in a tenant, only a definition the platform, the tenant or
     * an ancestor owns.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $owner
     * @return bool
     */
    public function sees(?Reference $owner): bool
    {
        if ($this->chain === null || $owner === null) {
            return true;
        }

        foreach ($this->chain->tenants as $tenant) {
            if ($tenant->type === $owner->type && $tenant->id === $owner->id) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine whether a role's grant and a policy attachment to the role hold
     * together anywhere: their applications meet (either for every application,
     * or the same one), and, outside a review of a scope a check is decided in,
     * their tenants do too.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $grant
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $attachment
     * @return bool
     */
    public function intersects(GrantScope $grant, GrantScope $attachment): bool
    {
        if ($grant->application !== null && $attachment->application !== null && $grant->application !== $attachment->application) {
            return false;
        }

        return $this->isApplicability() || $this->tenantsMeet($grant, $attachment);
    }

    /**
     * Return the condition a row rooted within the scope's tenant meets, the
     * tree's subtree nested whole.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewScope  $scope
     * @return \Closure(\Illuminate\Database\Query\Builder, string): void
     *
     * @throws \UnexpectedValueException
     */
    private static function rootedWithin(ReviewScope $scope): \Closure
    {
        return GrantRoots::within($scope->tenant ?? throw new \UnexpectedValueException('A review rooted within a tenant names one.'), TenantChain::tree());
    }

    /**
     * Determine whether two scopes hold in some tenant together: either is
     * platform-wide, both name one tenant, or one reaches below a tenant the
     * other names or is below.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $one
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $other
     * @return bool
     */
    private function tenantsMeet(GrantScope $one, GrantScope $other): bool
    {
        $first  = $one->tenant;
        $second = $other->tenant;

        if ($first === null || $second === null || ($first->type === $second->type && $first->id === $second->id)) {
            return true;
        }

        return ($one->includeSubtree && $this->isWithin($second, $first)) || ($other->includeSubtree && $this->isWithin($first, $second));
    }

    /**
     * Determine whether the tenant is the ancestor or below it, asking the tree
     * once for each pair in the run.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
     * @return bool
     */
    private function isWithin(Reference $tenant, Reference $ancestor): bool
    {
        $key = ReviewOrder::key([$tenant->type, $tenant->id, $ancestor->type, $ancestor->id]);

        return $this->within[$key] ??= TenantChain::isWithin($tenant, $ancestor);
    }
}
