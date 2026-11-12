<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Support\GrantRoots;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;

/**
 * Whether a role's grant and a policy attachment to the role hold in some
 * tenant together, as one run of an access review outside a scope a check is
 * decided in reads it: either is platform-wide, both name one tenant, or one
 * reaches below a tenant the other names or is below (see `canHoldTogether()`).
 *
 * The tree is asked in a fixed number of queries, never once for each holder,
 * grant or tenant of a grant: the chain of each attachment's tenant is read
 * once, so whether an attachment's tenant lies below a grant's is known from
 * it, and, for each attachment reaching below its tenant, the tenants of the
 * grants read are found within its subtree together (see `settle()`). The
 * queries grow with the attachments' tenants alone, which the reviewed target
 * or the holder's roles fix. Pairs of a tenant and an ancestor, as the conflict
 * report of exclusive roles weighs them, are settled with the subtrees of all
 * their ancestors read in one query, a chunk of the pairs at a time (see
 * `settleWithin()`). A pair nothing settled is asked of the tree, once.
 *
 * A grant query can also be limited to the rows that meet an attachment in SQL
 * (see `constrain()`), the attachment's chain bound and its subtree nested, so
 * a page of grants holds no grant that meets no attachment.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TenantRelations
{
    /** @var int The most grant tenants one query of a subtree is asked about. */
    public const int CHUNK = 500;

    /** @var int The most pairs of a tenant and an ancestor one query asks about: SQLite allows 500 terms in a compound select. */
    public const int PAIRS = 250;

    /** @var string The column of a grant row naming its tenant's type. */
    private const string TENANT_TYPE = '.tenant_type';

    /** @var string The column of a grant row naming its tenant's key. */
    private const string TENANT_ID = '.tenant_id';

    /** @var string The name a subtree query is read under. */
    private const string SUBTREE = 'authorization_review_subtree';

    /** @var string The column naming which ancestor's subtree a row was read from. */
    private const string ANCESTOR = 'authorization_ancestor';

    /** @var array<string, list<\SineMacula\Laravel\Authorization\Support\Reference>> The chain of each tenant read, the tenant first, then its ancestors nearest first, by the tenant's key. */
    private array $chains = [];

    /** @var array<string, bool> Whether one tenant is within another, by the pair's key. */
    private array $within = [];

    /**
     * Determine whether the two scopes hold in some tenant together: either is
     * platform-wide, both name one tenant, or one reaches below a tenant the
     * other names or is below.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $one
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $other
     * @return bool
     */
    public function canHoldTogether(GrantScope $one, GrantScope $other): bool
    {
        $first  = $one->tenant;
        $second = $other->tenant;

        if ($first === null || $second === null || self::isSame($first, $second)) {
            return true;
        }

        return ($one->includeSubtree && $this->isWithin($second, $first)) || ($other->includeSubtree && $this->isWithin($first, $second));
    }

    /**
     * Learn whether each of the grants meets each of the attachments, in a
     * fixed number of queries: the chain of each attachment's tenant, and, for
     * each attachment reaching below its tenant, which of the grants' tenants
     * are within it, a chunk of them at a time.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Support\GrantScope>  $grants
     * @param  list<\SineMacula\Laravel\Authorization\Support\GrantScope>  $attachments
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    public function settle(array $grants, array $attachments): void
    {
        $tenants = self::tenantsOf($grants);

        if ($tenants === []) {
            return;
        }

        foreach ($attachments as $attachment) {
            $tenant = $attachment->tenant;

            if ($tenant === null) {
                continue;
            }

            $this->chainOf($tenant);

            if (!$attachment->includeSubtree) {
                continue;
            }

            $this->settleBelow($tenant, $tenants);
        }
    }

    /**
     * Learn whether each tenant is within its ancestor, for pairs of a tenant
     * and an ancestor, in one query for each chunk of the pairs not known yet,
     * the subtrees of their ancestors read together; a tenant is within itself
     * without a query, and, for a flat tree, within nothing else.
     *
     * @param  list<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: \SineMacula\Laravel\Authorization\Support\Reference}>  $pairs
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    public function settleWithin(array $pairs): void
    {
        $pending = [];

        foreach ($pairs as [$tenant, $ancestor]) {
            $key = self::pair($tenant, $ancestor);

            if (self::isSame($tenant, $ancestor)) {
                $this->within[$key] = true;
            }

            if (isset($this->within[$key])) {
                continue;
            }

            $pending[$key] = [$tenant, $ancestor];
        }

        $tree = TenantChain::tree();

        foreach (\array_chunk($pending, self::PAIRS, true) as $chunk) {
            $found = $tree instanceof FlatTenantTree ? [] : self::foundIn($tree, self::byAncestor($chunk));

            foreach (\array_keys($chunk) as $key) {
                $this->within[$key] = isset($found[$key]);
            }
        }
    }

    /**
     * Determine whether the tenant is the ancestor or below it: from the
     * tenant's chain when it was read, else from what was settled, else asking
     * the tree, once for each pair.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
     * @return bool
     */
    public function isWithin(Reference $tenant, Reference $ancestor): bool
    {
        $chain = $this->chains[self::key($tenant)] ?? null;

        if ($chain !== null) {
            return \array_filter($chain, static fn (Reference $link): bool => self::isSame($link, $ancestor)) !== [];
        }

        return $this->within[self::pair($tenant, $ancestor)] ??= TenantChain::isWithin($tenant, $ancestor);
    }

    /**
     * Limit a grant query to the rows of the table that meet the attachment's
     * scope in some tenant: a platform-wide grant, never one naming half a
     * tenant, which meets no attachment naming a tenant; a grant in the
     * attachment's tenant; one reaching below a tenant of the attachment's
     * chain; and, for an attachment reaching below its tenant, one in its
     * subtree, nested whole, or, for a tree whose subtree cannot be nested, any
     * grant, which `canHoldTogether()` then weighs.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $table
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $attachment
     * @return \Illuminate\Database\Query\Builder
     */
    public function constrain(Builder $query, string $table, GrantScope $attachment): Builder
    {
        $tenant = $attachment->tenant;

        if ($tenant === null) {
            return $query;
        }

        $above = \array_slice($this->chainOf($tenant), 1);
        $below = $attachment->includeSubtree ? self::subtreeCondition($tenant) : static function (Builder $row): void {
            $row->whereRaw('1 = 0');
        };

        $reaching = static fn (Builder $any): Builder => self::among($any, $table, $above);

        return $query->where(static function (Builder $meet) use ($table, $tenant, $reaching, $below): void {
            TenantChain::whereNullTenant($meet, $table . self::TENANT_TYPE, $table . self::TENANT_ID)
                ->orWhere(static fn (Builder $same): Builder => $same->where($table . self::TENANT_TYPE, $tenant->type)->where($table . self::TENANT_ID, $tenant->id))
                ->orWhere(static fn (Builder $above): Builder => $above->where($table . '.include_subtree', true)->where($reaching))
                ->orWhere(static function (Builder $row) use ($table, $below): void {
                    $below($row, $table);
                });
        });
    }

    /**
     * Return the chain of the tenant, the tenant first, then its ancestors
     * nearest first, reading it from the tree the first time it is asked for.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    public function chainOf(Reference $tenant): array
    {
        return $this->chains[self::key($tenant)] ??= TenantChain::of($tenant, TenantChain::tree())->tenants;
    }

    /**
     * Return the tenants the scopes hold in, each once, the platform left out.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Support\GrantScope>  $scopes
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    private static function tenantsOf(array $scopes): array
    {
        $tenants = [];

        foreach ($scopes as $scope) {
            $tenant = $scope->tenant;

            if ($tenant === null) {
                continue;
            }

            $tenants[self::key($tenant)] = $tenant;
        }

        return \array_values($tenants);
    }

    /**
     * Learn which of the tenants are within the ancestor, asking its subtree
     * about a chunk of those not yet known at a time; for a flat tree, none but
     * the ancestor is, without a query.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $tenants
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    private function settleBelow(Reference $ancestor, array $tenants): void
    {
        $pending = \array_values(\array_filter($tenants, fn (Reference $tenant): bool => !isset($this->within[self::pair($tenant, $ancestor)])));
        $tree    = TenantChain::tree();

        foreach (\array_chunk($pending, self::CHUNK) as $chunk) {
            $found = $tree instanceof FlatTenantTree ? [] : self::foundIn($tree, [[$ancestor, $chunk]]);

            foreach ($chunk as $tenant) {
                $key = self::pair($tenant, $ancestor);

                $this->within[$key] = self::isSame($tenant, $ancestor) || isset($found[$key]);
            }
        }
    }

    /**
     * Return the pairs of a tenant and an ancestor whose tenant the ancestor's
     * subtree selects, for each ancestor and the tenants asked about it, in one
     * query, keyed by the pair. Each subtree is nested in that query, which
     * selects both its columns, so the database reports one the subtree lacks;
     * a row read without both still throws, naming the tree, rather than guess
     * the type or read a key as some other tenant's. Nothing in the review
     * catches either, so the review stops with it, and `authorization:review`
     * reports the exception's class.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\TenantTree  $tree
     * @param  list<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: list<\SineMacula\Laravel\Authorization\Support\Reference>}>  $groups
     * @return array<string, true>
     *
     * @throws \UnexpectedValueException
     */
    private static function foundIn(TenantTree $tree, array $groups): array
    {
        $arms  = \array_map(static fn (array $group, int $index): Builder => self::arm($tree, $group[0], $group[1], $index), $groups, \array_keys($groups));
        $union = $arms[0];

        foreach (\array_slice($arms, 1) as $arm) {
            $union->unionAll($arm);
        }

        $found = [];

        foreach ($union->get() as $row) {
            /** @var array{authorization_ancestor: int|string, tenant_type?: mixed, tenant_id?: mixed} $columns */
            $columns = (array) $row;
            $type    = $columns['tenant_type'] ?? null;
            $id      = $columns['tenant_id']   ?? null;

            if ((!\is_string($type) && !\is_int($type)) || (!\is_string($id) && !\is_int($id))) {
                $message = 'The subtree of the tenant tree ' . $tree::class . ' returned a row without both a tenant_type and a tenant_id: '
                    . 'a subtree must select both columns, typed, for every tenant.';

                throw new \UnexpectedValueException($message);
            }

            $found[self::pair(new Reference((string) $type, (string) $id), $groups[(int) $columns[self::ANCESTOR]][0])] = true;
        }

        return $found;
    }

    /**
     * Return the query of those of the tenants the ancestor's subtree selects,
     * each row naming the ancestor by its index among those asked about.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\TenantTree  $tree
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $tenants
     * @param  int  $index
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \UnexpectedValueException
     */
    private static function arm(TenantTree $tree, Reference $ancestor, array $tenants, int $index): Builder
    {
        $subtree = $tree->subtree($ancestor);
        $query   = $subtree instanceof EloquentBuilder ? $subtree->toBase() : $subtree;

        if (!$query instanceof Builder) {
            throw new \UnexpectedValueException('The tenant tree\'s subtree is not a query.');
        }

        return self::among($query->newQuery()->fromSub($query, self::SUBTREE), self::SUBTREE, $tenants)
            ->selectRaw('? as ' . self::ANCESTOR, [$index])
            ->addSelect([self::SUBTREE . self::TENANT_TYPE, self::SUBTREE . self::TENANT_ID]);
    }

    /**
     * Group the pairs of a tenant and an ancestor by the ancestor, each with
     * the tenants asked about it.
     *
     * @param  array<string, array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: \SineMacula\Laravel\Authorization\Support\Reference}>  $pairs
     * @return list<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: list<\SineMacula\Laravel\Authorization\Support\Reference>}>
     */
    private static function byAncestor(array $pairs): array
    {
        $groups = [];

        foreach ($pairs as [$tenant, $ancestor]) {
            $groups[self::key($ancestor)][0]   = $ancestor;
            $groups[self::key($ancestor)][1][] = $tenant;
        }

        return \array_values($groups);
    }

    /**
     * Return the condition a row of a table whose tenant is within the tenant's
     * subtree meets, the subtree nested whole; for a tree whose subtree cannot
     * be nested in a query of the package's tables, one every row meets.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \Closure(\Illuminate\Database\Query\Builder, string): void
     */
    private static function subtreeCondition(Reference $tenant): \Closure
    {
        try {
            return GrantRoots::within($tenant, TenantChain::tree());
        } catch (\UnexpectedValueException) {
            // A subtree on another connection cannot be nested; the grants it
            // would leave out are weighed one by one instead.
            return static function (Builder $row): void {
                $row->whereRaw('1 = 1');
            };
        }
    }

    /**
     * Limit the query to the rows of the table whose tenant is one of the
     * tenants, grouped by type, or to none for no tenants.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $table
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $tenants
     * @return \Illuminate\Database\Query\Builder
     */
    private static function among(Builder $query, string $table, array $tenants): Builder
    {
        $types = [];

        foreach ($tenants as $tenant) {
            $types[ReviewOrder::key([$tenant->type])]['type']  = $tenant->type;
            $types[ReviewOrder::key([$tenant->type])]['ids'][] = $tenant->id;
        }

        return $query->where(static function (Builder $any) use ($table, $types): void {
            $any->whereRaw('1 = 0');

            foreach ($types as ['type' => $type, 'ids' => $ids]) {
                $any->orWhere(static fn (Builder $row): Builder => $row->where($table . self::TENANT_TYPE, $type)->whereIn($table . self::TENANT_ID, $ids));
            }
        });
    }

    /**
     * Determine whether two references name one tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $one
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $other
     * @return bool
     */
    private static function isSame(Reference $one, Reference $other): bool
    {
        return $one->type === $other->type && $one->id === $other->id;
    }

    /**
     * Return the key of a tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return string
     */
    private static function key(Reference $tenant): string
    {
        return ReviewOrder::key([$tenant->type, $tenant->id]);
    }

    /**
     * Return the key of a tenant and an ancestor it may be within.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
     * @return string
     */
    private static function pair(Reference $tenant, Reference $ancestor): string
    {
        return ReviewOrder::key([$tenant->type, $tenant->id, $ancestor->type, $ancestor->id]);
    }
}
