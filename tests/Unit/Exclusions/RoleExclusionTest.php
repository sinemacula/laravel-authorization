<?php

declare(strict_types = 1);

namespace Tests\Unit\Exclusions;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exclusions\RoleExclusion;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for `RoleExclusion`: a pair of mutually exclusive roles as stored.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RoleExclusion::class)]
final class RoleExclusionTest extends TestCase
{
    /**
     * The pair holds its two roles, its owner, who declared it and when, the
     * last three null unless given.
     *
     * @return void
     */
    public function testHoldsThePairAsStored(): void
    {
        $role     = new Reference('role', 'a');
        $excluded = new Reference('role', 'b');
        $tenant   = new Reference('tenant', 't');
        $actor    = new Reference('user', '1');
        $at       = CarbonImmutable::parse('2026-07-01 12:00:00', 'UTC');
        $pair     = new RoleExclusion($role, $excluded, $tenant, $actor, $at);
        $bare     = new RoleExclusion($role, $excluded);

        self::assertSame([$role, $excluded, $tenant, $actor, $at], [$pair->role, $pair->excludedRole, $pair->tenant, $pair->grantedBy, $pair->createdAt]);
        self::assertSame([null, null, null], [$bare->tenant, $bare->grantedBy, $bare->createdAt]);
        self::assertTrue((new \ReflectionClass($pair))->isReadOnly());
    }
}
