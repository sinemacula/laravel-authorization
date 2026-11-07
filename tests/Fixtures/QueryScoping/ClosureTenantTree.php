<?php

declare(strict_types = 1);

namespace Tests\Fixtures\QueryScoping;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * A tenant tree kept in a closure table, for query scoping tests: one row for
 * each tenant and each of its ancestors, itself included at depth 0. It keeps
 * the contract `whereAuthorized()` relies on: `subtree(T)` selects exactly the
 * tenants `isWithin(R, T)` holds for, on the default connection, whatever the
 * tenant scope.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ClosureTenantTree implements TenantTree
{
    /** @var string The closure table. */
    public const string TABLE = 'scoped_tenant_closure';

    /**
     * Add a tenant to the tree, under the parent given, or at the top.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $parent
     * @return void
     */
    public static function add(Reference $tenant, ?Reference $parent = null): void
    {
        $rows = [self::row($tenant, $tenant, 0)];

        if ($parent !== null) {
            foreach ([$parent, ...(new self)->ancestors($parent)] as $depth => $ancestor) {
                $rows[] = self::row($ancestor, $tenant, $depth + 1);
            }
        }

        DB::table(self::TABLE)->insert($rows);
    }

    /**
     * Return the tenant's ancestors, nearest first.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    #[\Override]
    public function ancestors(Reference $tenant): array
    {
        $rows = DB::table(self::TABLE)
            ->where('descendant_type', $tenant->type)
            ->where('descendant_id', $tenant->id)
            ->where('depth', '>', 0)
            ->orderBy('depth')
            ->get(['ancestor_type', 'ancestor_id']);

        $ancestors = [];

        foreach ($rows as $row) {
            ['ancestor_type' => $type, 'ancestor_id' => $id] = (array) $row;

            // Exact bytes only, as PHP compares tenants.
            $ancestors[] = new Reference((string) $type, (string) $id); // @phpstan-ignore cast.string, cast.string
        }

        return $ancestors;
    }

    /**
     * Determine whether the tenant is the ancestor or below it.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
     * @return bool
     */
    #[\Override]
    public function isWithin(Reference $tenant, Reference $ancestor): bool
    {
        foreach ([$tenant, ...$this->ancestors($tenant)] as $candidate) {
            if ($candidate->type === $ancestor->type && $candidate->id === $ancestor->id) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return the tenant and every tenant below it, as a query of the closure
     * table.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \Illuminate\Contracts\Database\Query\Builder
     */
    #[\Override]
    public function subtree(Reference $tenant): Builder
    {
        return DB::table(self::TABLE)
            ->select(['descendant_type as tenant_type', 'descendant_id as tenant_id'])
            ->where('ancestor_type', $tenant->type)
            ->where('ancestor_id', $tenant->id);
    }

    /**
     * Return a row of the closure table.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $descendant
     * @param  int  $depth
     * @return array<string, int|string>
     */
    private static function row(Reference $ancestor, Reference $descendant, int $depth): array
    {
        return [
            'ancestor_type'   => $ancestor->type,
            'ancestor_id'     => $ancestor->id,
            'descendant_type' => $descendant->type,
            'descendant_id'   => $descendant->id,
            'depth'           => $depth,
        ];
    }
}
