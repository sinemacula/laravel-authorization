<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\ApplicationAccess;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\TestCase;

/**
 * Feature tests for whether a principal may use an application (D23).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApplicationAccess::class)]
final class ApplicationAccessTest extends TestCase
{
    use ActsAsTenant;

    /**
     * Require a permission for the admin and mobile applications.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(ConfigRepository::class);
        $config->set('authorization.application_access', ['admin' => 'admin:access', 'mobile' => 'mobile:access']);
    }

    /**
     * An application the configuration does not name is open to every
     * principal, with no grants at all.
     *
     * @return void
     */
    public function testAnApplicationNotNamedIsOpen(): void
    {
        self::assertTrue(self::access()->mayUse('web', StubIdentity::create(['id' => 'user-1'])));
    }

    /**
     * A named application admits a principal holding its permission through a
     * role, and no other.
     *
     * @return void
     */
    public function testANamedApplicationRequiresItsPermission(): void
    {
        $staff    = StubIdentity::create(['id' => 'staff']);
        $customer = StubIdentity::create(['id' => 'customer']);

        Role::create(['name' => 'staff'])->givePermission(Permission::create(['name' => 'admin:access']));
        $staff->assignRole('staff');

        self::assertTrue(self::access()->mayUse('admin', $staff));
        self::assertFalse(self::access()->mayUse('admin', $customer));
        self::assertFalse(self::access()->mayUse('mobile', $staff));
    }

    /**
     * The check is decided on the application asked about, so a grant made for
     * it counts and one made for another does not, whatever the request's
     * application, which is restored afterwards.
     *
     * @return void
     */
    public function testTheCheckIsDecidedOnTheApplicationAskedAbout(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        Permission::create(['name' => 'admin:access']);
        Permission::create(['name' => 'mobile:access']);
        $user->givePermission('admin:access', application: 'admin');
        $user->givePermission('mobile:access', application: 'admin');

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($user, null, 'web'));
        $this->app?->forgetInstance(ResolvedTenant::class);

        self::assertTrue(self::access()->mayUse('admin', $user));
        self::assertFalse(self::access()->mayUse('mobile', $user));
        self::assertSame('web', TenantScope::currentApplication());
    }

    /**
     * The check is decided in the principal's tenant as the subject resolver
     * gives it, so a grant in that tenant counts and one in another does not.
     *
     * @return void
     */
    public function testTheCheckIsDecidedInThePrincipalsTenant(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $tenant = self::createTenant('tenant-a');

        Permission::create(['name' => 'admin:access']);
        $user->givePermission('admin:access', tenant: $tenant);

        $this->actAsTenant($tenant);

        self::assertTrue(self::access()->mayUse('admin', $user));

        $this->actAsTenant(self::createTenant('tenant-b'));

        self::assertFalse(self::access()->mayUse('admin', $user));
    }

    /**
     * Return the application access service the container builds.
     *
     * @return \SineMacula\Laravel\Authorization\Services\ApplicationAccess
     */
    private static function access(): ApplicationAccess
    {
        return app(ApplicationAccess::class);
    }
}
