<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\BenchmarkCase;
use Illuminate\Support\Str;
use PhpBench\Attributes as Bench;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * PHPBench micro-benchmark for `Role::ancestors()` and `Role::descendants()`.
 *
 * Role hierarchy traversal runs on every `getPermissions()` call when hierarchy
 * is enabled — which is the default. The walk lazy-loads each level, so depth
 * and breadth both compound with query count. The bench carves the call surface
 * into the three shapes production traffic actually hits:
 *
 * - Ancestors on a 5-deep chain — realistic engineering-tier / platform-tier /
 *   tenant-tier hierarchy.
 * - Ancestors on a 10-deep chain — budget reference shape.
 * - Descendants on a 20-wide subtree — bulk RBAC rollout patterns (break a
 *   tenant's role into per-team children).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[Bench\OutputTimeUnit('microseconds')]
final class RoleHierarchyBench extends BenchmarkCase
{
    /** @var \SineMacula\Laravel\Authorization\Models\Role Leaf role at the tip of the 5-deep ancestor chain. */
    private Role $fiveDeepLeaf; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Authorization\Models\Role Leaf role at the tip of the 10-deep ancestor chain. */
    private Role $tenDeepLeaf; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Authorization\Models\Role Root of the 20-wide descendant subtree. */
    private Role $wideRoot; // @phpstan-ignore property.uninitialized

    /**
     * Bench setUp — seed two ancestor chains and one wide subtree so each
     * subject has a dedicated fixture shape.
     *
     * @return void
     */
    public function setUp(): void
    {
        $this->boot();

        Role::query()->delete();

        $this->fiveDeepLeaf = self::buildChain(5, 'five-deep');
        $this->tenDeepLeaf  = self::buildChain(10, 'ten-deep');
        $this->wideRoot     = self::buildWideSubtree(20, 'wide-root');
    }

    /**
     * Benchmark: ancestors walk on a 5-deep chain.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(100)]
    public function benchAncestorsFiveDeep(): void
    {
        // Reload the leaf so the parent relation is cold and the walk exercises
        // the lazy-load chain every rep.
        $leaf = Role::query()->whereKey($this->fiveDeepLeaf->getKey())->firstOrFail();
        $leaf->ancestors();
    }

    /**
     * Benchmark: ancestors walk on a 10-deep chain — budget reference shape.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(100)]
    public function benchAncestorsTenDeep(): void
    {
        $leaf = Role::query()->whereKey($this->tenDeepLeaf->getKey())->firstOrFail();
        $leaf->ancestors();
    }

    /**
     * Benchmark: descendants walk on a 20-wide subtree.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(50)]
    public function benchDescendantsTwentyWide(): void
    {
        $root = Role::query()->whereKey($this->wideRoot->getKey())->firstOrFail();
        $root->descendants();
    }

    /**
     * Build a parent chain `depth` roles deep, returning the leaf.
     *
     * @param  int  $depth
     * @param  string  $namePrefix
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private static function buildChain(int $depth, string $namePrefix): Role
    {
        $parent = null;

        for ($i = 0; $i < $depth; $i++) {

            $role = Role::create([
                'id'        => (string) Str::uuid(),
                'name'      => "{$namePrefix}-level-{$i}",
                'guard'     => 'web',
                'parent_id' => $parent?->getKey(),
            ]);

            $parent = $role;
        }

        assert($parent !== null);

        return $parent;
    }

    /**
     * Build a root role with `width` direct children.
     *
     * @param  int  $width
     * @param  string  $namePrefix
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private static function buildWideSubtree(int $width, string $namePrefix): Role
    {
        $root = Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => "{$namePrefix}-root",
            'guard' => 'web',
        ]);

        for ($i = 0; $i < $width; $i++) {
            Role::create([
                'id'        => (string) Str::uuid(),
                'name'      => "{$namePrefix}-child-{$i}",
                'guard'     => 'web',
                'parent_id' => $root->getKey(),
            ]);
        }

        return $root;
    }
}
