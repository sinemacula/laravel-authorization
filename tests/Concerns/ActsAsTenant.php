<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use PHPUnit\Framework\Attributes\After;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\SwitchableSubjectResolver;

/**
 * Sets the tenant the package resolves for the current test, and creates the
 * stub tenants and the role or permission rows they own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait ActsAsTenant
{
    /**
     * Make the given tenant, or no tenant, the one the package resolves from
     * now on.
     *
     * @param  object|null  $tenant
     * @return void
     */
    protected function actAsTenant(?object $tenant): void
    {
        $this->app?->instance(SubjectResolver::class, new SwitchableSubjectResolver);
        $this->app?->forgetInstance(ResolvedTenant::class);

        SwitchableSubjectResolver::$tenant = $tenant;
    }

    /**
     * Create a stub tenant with the given id.
     *
     * @param  string  $id
     * @return \Tests\Feature\Stubs\StubTenant
     */
    protected static function createTenant(string $id): StubTenant
    {
        return StubTenant::query()->create(['id' => $id, 'name' => $id]);
    }

    /**
     * Return the owner columns of a row the given tenant owns, or of a
     * platform-wide row when there is no tenant.
     *
     * @param  \Tests\Feature\Stubs\StubTenant|null  $tenant
     * @return array{tenant_type: string|null, tenant_id: string|null}
     */
    protected static function ownedBy(?StubTenant $tenant): array
    {
        if ($tenant === null) {
            return ['tenant_type' => null, 'tenant_id' => null];
        }

        /** @var string $id */
        $id = $tenant->getKey();

        return ['tenant_type' => $tenant->getMorphClass(), 'tenant_id' => $id];
    }

    /**
     * Forget the tenant set by the test, so the next test starts without one.
     *
     * @return void
     */
    #[After]
    protected function forgetActingTenant(): void
    {
        SwitchableSubjectResolver::$tenant = null;
    }
}
