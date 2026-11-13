<?php

declare(strict_types = 1);

namespace Tests\Unit\Exclusions\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exclusions\ExclusionConflict;
use SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute;
use SineMacula\Laravel\Authorization\Exclusions\Support\ExclusionWrite;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for `ExclusionWrite`: which conflicts a write creates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExclusionWrite::class)]
final class ExclusionWriteTest extends TestCase
{
    /**
     * A conflict is a grant's when either route is the grantee's grant of the
     * role in the scope's tenant and application, whatever its reach; a route
     * of another grantee, role, tenant or application is not.
     *
     * @return void
     */
    public function testAConflictIsAGrantsWhenARouteIsItsGrant(): void
    {
        $user   = new Reference('user', '1');
        $tenant = new Reference('tenant', 'a');
        $write  = ExclusionWrite::granted($user, [['b', new GrantScope($tenant, 'admin', false)]]);

        self::assertSame([], $write->proposed);
        self::assertSame([], $write->parents);
        self::assertTrue($write->makes(self::conflict(self::route($user, ['a']), self::route($user, ['b'], $tenant, 'admin'))));
        self::assertTrue($write->makes(self::conflict(self::route($user, ['b'], $tenant, 'admin'), self::route($user, ['a']))));
        self::assertFalse($write->makes(self::conflict(self::route($user, ['a']), self::route(new Reference('user', '2'), ['b'], $tenant, 'admin'))));
        self::assertFalse($write->makes(self::conflict(self::route($user, ['a']), self::route(new Reference('admin', '1'), ['b'], $tenant, 'admin'))));
        self::assertFalse($write->makes(self::conflict(self::route($user, ['a']), self::route($user, ['c', 'b'], $tenant, 'admin'))));
        self::assertFalse($write->makes(self::conflict(self::route($user, ['a']), self::route($user, ['b'], new Reference('tenant', 'b'), 'admin'))));
        self::assertFalse($write->makes(self::conflict(self::route($user, ['a']), self::route($user, ['b'], new Reference('team', 'a'), 'admin'))));
        self::assertFalse($write->makes(self::conflict(self::route($user, ['a']), self::route($user, ['b'], $tenant))));
        self::assertFalse($write->makes(self::conflict(self::route($user, ['a']), self::route($user, ['b']))));
    }

    /**
     * A proposed grant is read as a live grant of the role in the scope, and
     * its route is the write's.
     *
     * @return void
     */
    public function testAProposedGrantIsReadAsALiveGrant(): void
    {
        $user  = new Reference('user', '1');
        $scope = new GrantScope(new Reference('tenant', 'a'));
        $write = ExclusionWrite::proposed($user, 'b', $scope);
        $row   = $write->proposed[0];

        self::assertCount(1, $write->proposed);
        self::assertSame('role', $row->source);
        self::assertSame('b', $row->targetId);
        self::assertSame($user, $row->grantee);
        self::assertSame($scope, $row->scope);
        self::assertNull($row->expiresAt());
        self::assertNull($row->grantedBy);
        self::assertTrue($write->makes(self::conflict(self::route($user, ['a']), self::route($user, ['b'], $scope->tenant))));
    }

    /**
     * A conflict is a re-parenting's when a route steps from the role to the
     * parent it is given, anywhere along its path, and not otherwise.
     *
     * @return void
     */
    public function testAConflictIsAReparentingsWhenARouteStepsToTheNewParent(): void
    {
        $user  = new Reference('user', '1');
        $write = ExclusionWrite::reparented('c', 'b');

        self::assertSame(['c' => 'b'], $write->parents);
        self::assertTrue($write->makes(self::conflict(self::route($user, ['a']), self::route($user, ['c', 'b']))));
        self::assertTrue($write->makes(self::conflict(self::route($user, ['d', 'c', 'b']), self::route($user, ['a']))));
        self::assertFalse($write->makes(self::conflict(self::route($user, ['a']), self::route($user, ['c']))));
        self::assertFalse($write->makes(self::conflict(self::route($user, ['a']), self::route($user, ['b', 'c']))));
        self::assertFalse($write->makes(self::conflict(self::route($user, ['a']), self::route($user, ['d', 'b']))));
    }

    /**
     * Return a conflict of the user's two routes.
     *
     * @param  \SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute  $first
     * @param  \SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute  $second
     * @return \SineMacula\Laravel\Authorization\Exclusions\ExclusionConflict
     */
    private static function conflict(ExclusionRoute $first, ExclusionRoute $second): ExclusionConflict
    {
        return new ExclusionConflict($first->grantee, null, $first, $second);
    }

    /**
     * Return a route of the grantee along the path of role keys, in the tenant
     * and application given.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  non-empty-list<string>  $path
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string|null  $application
     * @return \SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute
     */
    private static function route(Reference $grantee, array $path, ?Reference $tenant = null, ?string $application = null): ExclusionRoute
    {
        $roles = \array_map(static fn (string $key): Reference => new Reference('role', $key), $path);
        $scope = new GrantScope($tenant, $application);

        return new ExclusionRoute($grantee, $roles[\count($roles) - 1], $roles, $scope, $scope);
    }
}
