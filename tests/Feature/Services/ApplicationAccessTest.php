<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\ApplicationAccess;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GuardrailService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubMachine;
use Tests\Feature\Stubs\StubSessionPolicySource;
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
     * A machine holding the application's permission is admitted, though it
     * holds no session and so no credential scopes yet, and one without it is
     * refused.
     *
     * @return void
     */
    public function testAMachineIsAdmittedOnItsPermissionAlone(): void
    {
        $holder  = StubMachine::create(['id' => 'svc-1']);
        $without = StubMachine::create(['id' => 'svc-2']);

        $holder->givePermission(Permission::create(['name' => 'admin:access']));

        self::assertTrue(self::access()->mayUse('admin', $holder, null));
        self::assertFalse(self::access()->mayUse('admin', $without, null));
    }

    /**
     * Once a machine's session exists, its ordinary checks are still capped: by
     * its credential's scopes, or, with none, by the empty cap that allows
     * nothing.
     *
     * @return void
     */
    public function testAMachinesOrdinaryChecksAreStillCapped(): void
    {
        $machine = StubMachine::create(['id' => 'svc-1']);

        $machine->givePermission(Permission::create(['name' => 'admin:access']));

        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for($machine)->check('admin:access')->reason);

        $this->withCredential(['posts:*']);

        self::assertTrue(self::access()->mayUse('admin', $machine, null));
        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for($machine)->check('admin:access')->reason);
        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::forUser($machine)->check('admin:access')->reason);
    }

    /**
     * A person is admitted whatever the request's session caps, which belong to
     * whoever made the request, and the source is never asked; an ordinary
     * check is still capped by them.
     *
     * @return void
     */
    public function testAPersonIsAdmittedWhateverTheRequestsSessionCaps(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'admin:access']));

        $source = $this->withCredential(['posts:read']);

        self::assertTrue(self::access()->mayUse('admin', $user, null));
        self::assertCount(0, $source->calls);
        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for($user)->check('admin:access')->reason);
        self::assertCount(1, $source->calls);

        $this->withCredential([]);

        self::assertTrue(self::access()->mayUse('admin', $user, null));
    }

    /**
     * A deny of the principal's own still refuses admission, for a person and a
     * machine alike.
     *
     * @return void
     */
    public function testADenyStillRefuses(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $machine = StubMachine::create(['id' => 'svc-1']);
        $deny    = Policy::create(['name' => 'no-admin', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['admin:access']]]]]);

        Permission::create(['name' => 'admin:access']);

        foreach ([$user, $machine] as $principal) {
            $principal->givePermission('admin:access');

            self::assertTrue(self::access()->mayUse('admin', $principal, null));

            $principal->attachPolicy($deny);

            self::assertFalse(self::access()->mayUse('admin', $principal, null));
        }
    }

    /**
     * A permission boundary that does not allow the application's permission
     * still refuses admission.
     *
     * @return void
     */
    public function testABoundaryStillRefuses(): void
    {
        $machine = StubMachine::create(['id' => 'svc-1']);

        $machine->givePermission(Permission::create(['name' => 'admin:access']));

        self::assertTrue(self::access()->mayUse('admin', $machine, null));

        self::boundaries()->set($machine, Policy::create(['name' => 'read-only', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]]));

        self::assertFalse(self::access()->mayUse('admin', $machine, null));
    }

    /**
     * A guardrail that does not allow the application's permission still
     * refuses admission.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testAGuardrailStillRefuses(): void
    {
        $user  = StubIdentity::create(['id' => 'user-1']);
        $actor = StubIdentity::create(['id' => 'guardrail-admin']);

        $user->givePermission(Permission::create(['name' => 'admin:access']));
        $actor->givePermission(Permission::create(['name' => PackagePermissions::GUARDRAIL_MANAGE]));

        self::assertTrue(self::access()->mayUse('admin', $user, null));

        $rail = Policy::create(['name' => 'read-only', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]]);

        self::guardrails()->set($rail, null, ActingContext::for($actor));

        self::assertFalse(self::access()->mayUse('admin', $user, null));
    }

    /**
     * A machine is admitted on the application and in the tenant asked about: a
     * grant made for another application, or in another tenant, does not count.
     *
     * @return void
     */
    public function testAMachineIsAdmittedInTheTenantAndApplicationAskedAbout(): void
    {
        $machine = StubMachine::create(['id' => 'svc-1']);
        $own     = self::createTenant('tenant-a');
        $other   = self::createTenant('tenant-b');

        Permission::create(['name' => 'admin:access']);
        Permission::create(['name' => 'mobile:access']);
        $machine->givePermission('admin:access', tenant: $own, application: 'admin');
        $machine->givePermission('mobile:access', tenant: $own, application: 'admin');

        self::assertTrue(self::access()->mayUse('admin', $machine, $own));
        self::assertFalse(self::access()->mayUse('admin', $machine, $other));
        self::assertFalse(self::access()->mayUse('admin', $machine, null));
        self::assertFalse(self::access()->mayUse('mobile', $machine, $own));
    }

    /**
     * Bind a session policy source answering the scopes given for every
     * credential, and drop the manager built with the previous one.
     *
     * @param  list<string>|null  $scopes
     * @return \Tests\Feature\Stubs\StubSessionPolicySource
     */
    private function withCredential(?array $scopes): StubSessionPolicySource
    {
        $source = new StubSessionPolicySource($scopes);

        $this->app?->instance(SessionPolicySource::class, $source);

        foreach (['authorization', AuthorizationManager::class] as $abstract) {
            $this->app?->forgetInstance($abstract);
        }

        Authorization::clearResolvedInstance('authorization');

        return $source;
    }

    /**
     * Return the permission boundary service the container builds.
     *
     * @return \SineMacula\Laravel\Authorization\Services\BoundaryService
     */
    private static function boundaries(): BoundaryService
    {
        $service = BoundaryService::instance();

        self::assertInstanceOf(BoundaryService::class, $service);

        return $service;
    }

    /**
     * Return the guardrail service the container builds.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GuardrailService
     */
    private static function guardrails(): GuardrailService
    {
        $service = GuardrailService::instance();

        self::assertInstanceOf(GuardrailService::class, $service);

        return $service;
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
