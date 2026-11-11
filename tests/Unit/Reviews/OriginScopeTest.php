<?php

declare(strict_types = 1);

namespace Tests\Unit\Reviews;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Reviews\Enums\ReachKind;
use SineMacula\Laravel\Authorization\Reviews\OriginScope;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for where a stored row a review lists holds, as its columns store
 * it: a whole tenant, the platform, or half a tenant shown as stored.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OriginScope::class)]
final class OriginScopeTest extends TestCase
{
    /**
     * A grant scope's origin names its tenant whole, or none at the platform,
     * and neither is malformed.
     *
     * @return void
     */
    public function testAGrantScopesOriginNamesItsTenantWhole(): void
    {
        $tenant   = OriginScope::of(new GrantScope(new Reference('tenant', 't1'), 'web', false));
        $platform = OriginScope::of(GrantScope::platform());

        self::assertSame(['tenant', 't1', 'web', false], [$tenant->tenantType, $tenant->tenantId, $tenant->application, $tenant->includeSubtree]);
        self::assertEquals(new Reference('tenant', 't1'), $tenant->tenant());
        self::assertSame(['tenant' => ['type' => 'tenant', 'id' => 't1'], 'application' => 'web', 'include_subtree' => false], $tenant->toArray());
        self::assertFalse($tenant->isMalformed());

        self::assertNull($platform->tenant());
        self::assertSame(['tenant' => null, 'application' => null, 'include_subtree' => true], $platform->toArray());
        self::assertFalse($platform->isMalformed());
    }

    /**
     * Half a tenant, a type without a key or a key without a type, is
     * malformed, names no whole tenant, and shows the half it stores, never the
     * platform's empty tenant.
     *
     * @return void
     */
    public function testHalfATenantIsShownAsStored(): void
    {
        $noKey  = new OriginScope('tenant', null, null, true);
        $noType = new OriginScope(null, 't1', 'web', false);

        self::assertTrue($noKey->isMalformed());
        self::assertTrue($noType->isMalformed());
        self::assertNull($noKey->tenant());
        self::assertNull($noType->tenant());
        self::assertSame(['tenant' => ['type' => 'tenant', 'id' => null], 'application' => null, 'include_subtree' => true], $noKey->toArray());
        self::assertSame(['tenant' => ['type' => null, 'id' => 't1'], 'application' => 'web', 'include_subtree' => false], $noType->toArray());
    }

    /**
     * A row reaches the platform when it names no tenant column, whatever its
     * stored reach; else its tenant and those below when it reaches below, or
     * its tenant alone; half a tenant reads by the half it names.
     *
     * @return void
     */
    public function testItSaysHowFarItReaches(): void
    {
        self::assertSame(ReachKind::PLATFORM, (new OriginScope(null, null, 'web', false))->reach());
        self::assertSame(ReachKind::PLATFORM, OriginScope::of(GrantScope::platform())->reach());
        self::assertSame(ReachKind::SUBTREE, (new OriginScope('tenant', 't1', null, true))->reach());
        self::assertSame(ReachKind::NODE, (new OriginScope('tenant', 't1', null, false))->reach());
        self::assertSame(ReachKind::SUBTREE, (new OriginScope('tenant', null, null, true))->reach());
        self::assertSame(ReachKind::NODE, (new OriginScope(null, 't1', null, false))->reach());
    }
}
