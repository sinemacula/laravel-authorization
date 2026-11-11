<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\RoleReach;

/**
 * Unit tests for `RoleReach`, a role listed in a sync with a reach of its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RoleReach::class)]
final class RoleReachTest extends TestCase
{
    /**
     * A role reach names the role, a model or a name, and the reach given.
     *
     * @return void
     */
    public function testNamesTheRoleAndItsReach(): void
    {
        $role = new Role;

        self::assertSame(['editor', false], [RoleReach::of('editor', false)->role, RoleReach::of('editor', false)->includeSubtree]);
        self::assertSame([$role, true], [RoleReach::of($role, true)->role, RoleReach::of($role, true)->includeSubtree]);
    }

    /**
     * A sync's entries split into its targets, in the order listed and keyed
     * from zero whatever the entries' keys, and the reach of each entry listed
     * with one, keyed by its target's position; an entry listed alone names no
     * reach.
     *
     * @return void
     */
    public function testSplitsASyncsEntriesIntoTargetsAndReaches(): void
    {
        $role = new Role;

        self::assertSame(
            [['viewer', 'editor', $role, 'author'], [1 => false, 2 => true]],
            RoleReach::split([5 => 'viewer', 'a' => RoleReach::of('editor', false), 9 => RoleReach::of($role, true), 'author']),
        );
        self::assertSame([[], []], RoleReach::split([]));
        self::assertSame([['viewer'], []], RoleReach::split(['viewer']));
    }
}
