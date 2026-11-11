<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use Carbon\CarbonImmutable;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\ComposedExpression;
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
 * A row that names half a tenant, a tenant type without a key or a key without
 * a type, which the package never writes (N99), is listed exactly where a check
 * reads it: a key without a type at the platform, by its missing type alone,
 * and a type without a key nowhere. A review of everywhere, which needs
 * platform-wide admission, lists a type without a key too; a review rooted
 * within a tenant never does, since it cannot be shown to lie within the tenant
 * and a scoped review never discloses another tenant's holders (N96). Either is
 * marked `malformed`, its origin scope as stored (see `GrantRow` and
 * `Enums\GrantState`).
 *
 * A role's policy attachment reaches a holder of the role only where both the
 * role's grant and the attachment hold, as `RolePolicies` reads them in a
 * check: in a review of a scope a check is decided in, both apply there, so
 * only their applications must meet; in any other review, their tenants must
 * meet too (see `intersects()`), the tree asked in a fixed number of queries
 * for the grants and attachments read together (see `TenantRelations`), never
 * once for each holder or each tenant a grant is held in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ReviewRun
{
    /** @var string The column of a definition or grant row naming its tenant's type. */
    private const string TENANT_TYPE = '.tenant_type';

    /** @var string The column of a definition or grant row naming its tenant's key. */
    private const string TENANT_ID = '.tenant_id';

    /**
     * Create a new run.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewScope  $scope
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authorization\Support\TenantChain|null  $chain
     * @param  (\Closure(\Illuminate\Database\Query\Builder, string): void)|null  $rooted
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\TenantRelations  $relations
     */
    private function __construct(

        /** The scope the review reads. */
        public ReviewScope $scope,

        /** The instant the review is made at, in UTC. */
        public CarbonImmutable $now,

        /** The chain of the tenant a review of what applies there reads, or the platform's; null for any other review. */
        private ?TenantChain $chain,

        /** The condition a row rooted within the reviewed tenant meets; null for any other review. */
        private ?\Closure $rooted,

        /** Whether grants and attachments read in the run meet in some tenant, as the tree answered. */
        private TenantRelations $relations = new TenantRelations,
    ) {}

    /**
     * Return a run of a review of the scope, made at the instant given, frozen
     * for a later page of a review begun then, or now, reading the tenant tree
     * once for it.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewScope  $scope
     * @param  \Carbon\CarbonImmutable|null  $at
     * @return self
     *
     * @throws \UnexpectedValueException
     */
    public static function of(ReviewScope $scope, ?CarbonImmutable $at = null): self
    {
        $now = $at?->utc() ?? CarbonImmutable::now('UTC');

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

            $query->where(static function (Builder $row) use ($rooted, $table): void {
                $rooted($row, $table);
            });
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

            $role->selectRaw('1')->from($roles)->whereRaw(new ComposedExpression(Definitions::keyAsText($role, $roles . '.' . $key) . ' = ' . $grantee));

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

        return $this->isApplicability() || $this->relations->canHoldTogether($grant, $attachment);
    }

    /**
     * Return where a role's grant and a policy attachment to the role that hold
     * together somewhere (see `intersects()`) hold together: the narrower of
     * their tenant reaches, the reach below their tenant only when both reach
     * below it where they name the same one, and the application one names,
     * else every application. The tenant chain of the run, or of the
     * attachment's tenant as settled (see `settle()`), says which tenant lies
     * below the other, so this asks the tree nothing more.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $grant
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $attachment
     * @return \SineMacula\Laravel\Authorization\Support\GrantScope
     */
    public function overlap(GrantScope $grant, GrantScope $attachment): GrantScope
    {
        $outer = $grant->tenant;
        $inner = $attachment->tenant;

        $narrower = match (true) {
            $inner       === null                                      => $grant,
            $outer       === null                                      => $attachment,
            $outer->type === $inner->type && $outer->id === $inner->id => new GrantScope($outer, null, $grant->includeSubtree && $attachment->includeSubtree),
            $this->isAbove($outer, $inner)                             => $attachment,
            default                                                    => $grant,
        };

        return new GrantScope($narrower->tenant, $grant->application ?? $attachment->application, $narrower->includeSubtree);
    }

    /**
     * Limit a query of a role's grants to the rows of the table that hold
     * together with the attachment somewhere, as `intersects()` weighs them:
     * their applications meet, and, outside a review of a scope a check is
     * decided in, their tenants do too (see `TenantRelations::constrain()`).
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $table
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $attachment
     * @return \Illuminate\Database\Query\Builder
     */
    public function meeting(Builder $query, string $table, GrantScope $attachment): Builder
    {
        $application = $attachment->application;

        if ($application !== null) {
            $query->where(static fn (Builder $meets): Builder => $meets->whereNull($table . '.application')->orWhere($table . '.application', $application));
        }

        return $this->isApplicability() ? $query : $this->relations->constrain($query, $table, $attachment);
    }

    /**
     * Learn, in a fixed number of queries, whether each of the role grants read
     * meets each of the attachments read in some tenant, so weighing them asks
     * the tree nothing more; a review of a scope a check is decided in needs
     * nothing.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>  $grants
     * @param  array<array-key, list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>>  $attachments
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    public function settle(array $grants, array $attachments): void
    {
        if ($this->isApplicability()) {
            return;
        }

        $scopes = static fn (array $rows): array => \array_values(\array_filter(\array_map(static fn (GrantRow $row): ?GrantScope => $row->scope, $rows)));

        $this->relations->settle($scopes($grants), $scopes(\array_merge([], ...\array_values($attachments))));
    }

    /**
     * Determine whether the tenant lies above the other: it comes later in the
     * run's chain, in a review of what applies in a tenant, where both lie on
     * it; else it is an ancestor of the other in the other's chain.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $other
     * @return bool
     */
    private function isAbove(Reference $tenant, Reference $other): bool
    {
        $chain    = $this->chain->tenants ?? $this->relations->chainOf($other);
        $position = static function (Reference $sought) use ($chain): int {
            foreach ($chain as $depth => $link) {
                if ($link->type === $sought->type && $link->id === $sought->id) {
                    return $depth;
                }
            }

            return -1;
        };

        return $position($tenant) > $position($other);
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
}
