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
use SineMacula\Laravel\Authorization\Subject;
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
        self::assertTrue(self::access()->mayUse('web', StubIdentity::create(['id' => 'user-1']), null));
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

        self::assertTrue(self::access()->mayUse('admin', $staff, null));
        self::assertFalse(self::access()->mayUse('admin', $customer, null));
        self::assertFalse(self::access()->mayUse('mobile', $staff, null));
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

        self::assertTrue(self::access()->mayUse('admin', $user, null));
        self::assertFalse(self::access()->mayUse('mobile', $user, null));
        self::assertSame('web', TenantScope::currentApplication());
    }

    /**
     * The check is decided in the tenant given, the principal's own, rather
     * than the request's, so a grant there counts and one in the request's
     * tenant does not.
     *
     * @return void
     */
    public function testTheCheckIsDecidedInTheTenantGiven(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $own     = self::createTenant('tenant-a');
        $request = self::createTenant('tenant-b');

        Permission::create(['name' => 'admin:access']);
        Permission::create(['name' => 'mobile:access']);
        $user->givePermission('admin:access', tenant: $own);
        $user->givePermission('mobile:access', tenant: $request);

        $this->actAsTenant($request);

        self::assertTrue(self::access()->mayUse('admin', $user, $own));
        self::assertFalse(self::access()->mayUse('mobile', $user, $own));
        self::assertFalse(self::access()->mayUse('admin', $user, null));
    }

    /**
     * Asked while the subject is being resolved, as a guard admitting a
     * principal at sign-in asks, the check still sees the application.
     *
     * @return void
     */
    public function testTheCheckHoldsWhileTheSubjectIsBeingResolved(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        Permission::create(['name' => 'admin:access']);
        $user->givePermission('admin:access', application: 'admin');

        $resolver = new class ($user) implements SubjectResolver {
            /** @var bool|null Whether the principal was admitted while resolving. */
            public ?bool $admitted = null;

            /**
             * Create a resolver that admits the principal as it resolves.
             *
             * @param  \Tests\Feature\Stubs\StubIdentity  $user
             */
            public function __construct(

                /** The principal admitted. */
                private readonly StubIdentity $user,
            ) {}

            /**
             * Admit the principal to the admin application, then resolve it.
             *
             * @return \SineMacula\Laravel\Authorization\Subject
             */
            #[\Override]
            public function resolve(): Subject
            {
                $this->admitted = app(ApplicationAccess::class)->mayUse('admin', $this->user, null);

                return $this->forUser($this->user);
            }

            /**
             * Return the user as the subject, on the web application.
             *
             * @param  object  $user
             * @return \SineMacula\Laravel\Authorization\Subject
             */
            #[\Override]
            public function forUser(object $user): Subject
            {
                return new Subject($user, $user, null, 'web');
            }
        };

        $this->app?->instance(SubjectResolver::class, $resolver);
        $this->app?->forgetInstance(ResolvedTenant::class);

        Role::query()->get();

        self::assertTrue($resolver->admitted);
        self::assertSame('web', TenantScope::currentApplication());
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
