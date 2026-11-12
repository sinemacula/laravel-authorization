<?php

declare(strict_types = 1);

namespace Tests\Unit\Exclusions;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for `ExclusionRoute`: one way a holder holds a role of a pair.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExclusionRoute::class)]
final class ExclusionRouteTest extends TestCase
{
    /**
     * The route holds its grantee, its role, its path, its scope, where it is
     * held and its expiry, the role granted first on the path, direct only when
     * the path is the role alone.
     *
     * @return void
     */
    public function testHoldsWhereTheRoleComesFrom(): void
    {
        $grantee   = new Reference('user', '1');
        $clerk     = new Reference('role', 'clerk');
        $deputy    = new Reference('role', 'deputy');
        $scope     = new GrantScope(new Reference('tenant', 'a'), 'admin', false);
        $expiresAt = CarbonImmutable::parse('2026-07-01 12:00:00', 'UTC');
        $reach     = new GrantScope(new Reference('tenant', 'b'), 'admin');
        $inherited = new ExclusionRoute($grantee, $clerk, [$deputy, $clerk], $scope, $reach, $expiresAt);
        $direct    = new ExclusionRoute($grantee, $clerk, [$clerk], GrantScope::platform(), GrantScope::platform());

        $held = [$inherited->grantee, $inherited->role, $inherited->path, $inherited->scope, $inherited->reach, $inherited->expiresAt];

        self::assertSame([$grantee, $clerk, [$deputy, $clerk], $scope, $reach, $expiresAt], $held);
        self::assertSame($deputy, $inherited->granted());
        self::assertFalse($inherited->isDirect());
        self::assertSame($clerk, $direct->granted());
        self::assertTrue($direct->isDirect());
        self::assertNull($direct->expiresAt);
    }

    /**
     * The route is ordered by its grantee, its path, then its scope.
     *
     * @return void
     */
    public function testIsOrderedByItsGranteePathAndScope(): void
    {
        $route = new ExclusionRoute(
            new Reference('user', '1'),
            new Reference('role', 'clerk'),
            [new Reference('role', 'deputy'), new Reference('role', 'clerk')],
            new GrantScope(new Reference('tenant', 'a'), 'admin', false),
            new GrantScope(new Reference('tenant', 'b')),
        );

        self::assertSame(['user', '1', 'deputy', 'clerk', 'tenant', 'a', 'admin', false], $route->orderKey());
        $direct = new ExclusionRoute(new Reference('user', '1'), new Reference('role', 'clerk'), [new Reference('role', 'clerk')], GrantScope::platform(), GrantScope::platform());

        self::assertSame(['user', '1', 'clerk', null, null, null, true], $direct->orderKey());
    }
}
