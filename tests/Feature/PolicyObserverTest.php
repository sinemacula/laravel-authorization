<?php

declare(strict_types = 1);

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Observers\PolicyObserver;
use Tests\TestCase;

/**
 * Feature tests for the policy observer's tenant-columns invariant: a policy is
 * owned by the platform (both tenant columns null) or by one tenant (both set),
 * never half of each.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PolicyObserver::class)]
final class PolicyObserverTest extends TestCase
{
    /**
     * A platform-wide policy saves.
     *
     * @return void
     */
    public function testPlatformPolicySaves(): void
    {
        $policy = Policy::query()->create(['name' => 'readers', 'document' => self::document()]);

        self::assertNull($policy->tenant_type);
        self::assertNull($policy->tenant_id);
    }

    /**
     * A tenant-owned policy saves with both tenant columns.
     *
     * @return void
     */
    public function testTenantOwnedPolicySaves(): void
    {
        $policy = Policy::query()->create(['name' => 'readers', 'document' => self::document(), 'tenant_type' => 'tenant', 'tenant_id' => 'tenant-a']);

        $fresh = Policy::query()->findOrFail($policy->id);

        self::assertSame('tenant', $fresh->tenant_type);
        self::assertSame('tenant-a', $fresh->tenant_id);
    }

    /**
     * A tenant type without a tenant id is refused, naming the missing column.
     *
     * @return void
     */
    public function testTenantTypeWithoutIdIsRefused(): void
    {
        $this->expectException(InvalidTenantColumnsException::class);
        $this->expectExceptionMessage('Cannot save policy with inconsistent tenant columns — \'tenant_id\' is required');

        Policy::query()->create(['name' => 'readers', 'document' => self::document(), 'tenant_type' => 'tenant']);
    }

    /**
     * A tenant id without a tenant type is refused, naming the missing column.
     *
     * @return void
     */
    public function testTenantIdWithoutTypeIsRefused(): void
    {
        $this->expectException(InvalidTenantColumnsException::class);
        $this->expectExceptionMessage('Cannot save policy with inconsistent tenant columns — \'tenant_type\' is required');

        Policy::query()->create(['name' => 'readers', 'document' => self::document(), 'tenant_id' => 'tenant-a']);
    }

    /**
     * Clearing one tenant column of a stored policy is refused too.
     *
     * @return void
     */
    public function testClearingOneTenantColumnIsRefused(): void
    {
        $policy = Policy::query()->create(['name' => 'readers', 'document' => self::document(), 'tenant_type' => 'tenant', 'tenant_id' => 'tenant-a']);

        $this->expectException(InvalidTenantColumnsException::class);

        $policy->update(['tenant_id' => null]);
    }

    /**
     * Return a minimal valid policy document.
     *
     * @return array<string, mixed>
     */
    private static function document(): array
    {
        return ['version' => 1, 'statements' => []];
    }
}
