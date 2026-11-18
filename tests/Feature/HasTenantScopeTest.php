<?php

declare(strict_types = 1);

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Concerns\HasTenantScope;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\CustomPermission;
use Tests\Feature\Stubs\CustomRole;
use Tests\TestCase;

/**
 * Feature tests for the `HasTenantScope` trait.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(HasTenantScope::class)]
final class HasTenantScopeTest extends TestCase
{
    use ActsAsTenant;

    /**
     * A subclass hides the rows another tenant owns, as the shipped model does.
     *
     * @return void
     */
    public function testSubclassesKeepTenantScoping(): void
    {
        config(['authorization.models.role' => CustomRole::class, 'authorization.models.permission' => CustomPermission::class]);

        $tenantB = self::createTenant('tenant-b');

        CustomRole::query()->create(['name' => 'platform']);
        CustomRole::query()->create(['name' => 'b-only'] + self::ownedBy($tenantB));
        CustomPermission::query()->create(['name' => 'posts:read']);
        CustomPermission::query()->create(['name' => 'posts:b-only'] + self::ownedBy($tenantB));

        $this->actAsTenant(self::createTenant('tenant-a'));

        self::assertSame(['platform'], CustomRole::query()->pluck('name')->all());
        self::assertSame(['posts:read'], CustomPermission::query()->pluck('name')->all());

        $this->actAsTenant($tenantB);

        self::assertSame(['b-only', 'platform'], CustomRole::query()->orderBy('name')->pluck('name')->all());
        self::assertSame(['posts:b-only', 'posts:read'], CustomPermission::query()->orderBy('name')->pluck('name')->all());
    }
}
