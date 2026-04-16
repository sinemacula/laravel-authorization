<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\TestCase;

/**
 * Performance budget for `Role::ancestors()` walks.
 *
 * Role hierarchy traversal runs on every `getPermissions()` call
 * when hierarchy is enabled (the default). A 10-deep chain is the
 * deepest production hierarchy the package expects to see (org →
 * division → team → squad → role → seat plus extension levels);
 * the budget catches a regression that turns the walk into a
 * database-bound loop rather than a lazy-load chain.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Role::class)]
final class RoleHierarchyBudgetTest extends TestCase
{
    /**
     * A single ancestors walk on a 10-deep chain must complete in
     * under 50ms on the reference machine. Observed ~2.2ms on the
     * reference machine; budget is ~20× to tolerate CI variance
     * and the inherent cost of SQLite lazy loads.
     *
     * @return void
     */
    public function testAncestorsWalkOnTenDeepChainStaysBounded(): void
    {
        $leaf = self::buildChain(10);

        $start = \microtime(true);

        $leaf->ancestors();

        $elapsed = \microtime(true) - $start;

        self::assertLessThan(
            0.05,
            $elapsed,
            "Role::ancestors() 10-deep budget exceeded ({$elapsed}s).",
        );
    }

    /**
     * The `ancestors()` walk must return a full chain of 9
     * parents for a 10-deep leaf — guards against a regression
     * where the walk terminates early (missing permissions in
     * inherited rollup) or double-counts (cycle-detection bug).
     *
     * @return void
     */
    public function testAncestorsWalkReturnsFullChain(): void
    {
        $leaf = self::buildChain(10);

        self::assertCount(
            9,
            $leaf->ancestors(),
            'Expected a 10-deep leaf to have exactly 9 ancestors.',
        );
    }

    /**
     * Build an ancestor chain `depth` roles deep, returning the
     * leaf — same shape as the matching bench fixture.
     *
     * @param  int  $depth
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private static function buildChain(int $depth): Role
    {
        $parent = null;

        for ($i = 0; $i < $depth; $i++) {
            $role = Role::create([
                'id'         => (string) Str::uuid(),
                'name'       => "budget-chain-{$i}",
                'guard_name' => 'web',
                'parent_id'  => $parent?->getKey(),
            ]);

            $parent = $role;
        }

        \assert($parent !== null);

        return $parent;
    }
}
