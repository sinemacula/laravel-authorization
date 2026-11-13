<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Database\BreakGlassActivations;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Evaluation\Enums\GrantSource;
use SineMacula\Laravel\Authorization\Evaluation\GrantProvenance;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Resolvers\DeclaredResourceTenant;
use SineMacula\Laravel\Authorization\Resolvers\NoResourceTenant;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Concerns\ActivatesBreakGlass;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\FixedSubjectResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubMachine;
use Tests\Feature\Stubs\StubTenant;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\Fixtures\QueryScoping\TenantScopedPost;
use Tests\TestCase;

/**
 * Feature tests for break-glass activations read as role grants (AUTHZ-11.7,
 * N133): a live activation grants its role, the role's permissions and its
 * policies, in its scope alone (the platform, a tenant and its subtree, a
 * tenant alone, an application), through a check, a bulk check,
 * `permissionsFor()` and `whereAuthorized()` alike, cold and warm; an expired
 * or ended one, one naming half a tenant, a machine's and an identity's grant
 * nothing; a normal grant of the same role is untouched; denies, boundaries and
 * guardrails still apply; the cache entry lapses at the activation's expiry and
 * a change made through the model is seen on the next check; switching
 * break-glass off stops every activation at once; and an explanation names the
 * route as break-glass with the activation's key, never its note.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(BreakGlassActivations::class)]
final class BreakGlassActivationsTest extends TestCase
{
    use ActivatesBreakGlass;

    /** @var string The action the emergency role carries. */
    private const string ACTION = 'posts:create';

    /** @var string The action nothing grants. */
    private const string OTHER = 'posts:delete';

    /** @var list<string> The scopes a check is decided in: the platform, the organisation, the account below it and another organisation. */
    private const array SCOPES = ['platform', 'o1', 'a1', 'o2'];

    /**
     * Start the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow('2026-07-01 12:00:00');
    }

    /**
     * Reset the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * Return each scope an activation names, with the scopes, and the
     * application, its role is held in.
     *
     * @return iterable<string, array{string|null, bool, string|null, string|null, list<string>}>
     */
    public static function scopes(): iterable
    {
        yield 'the platform' => [null, true, null, null, self::SCOPES];
        yield 'the organisation and its subtree' => ['o1', true, null, null, ['o1', 'a1']];
        yield 'the organisation alone' => ['o1', false, null, null, ['o1']];
        yield 'the account' => ['a1', true, null, null, ['a1']];
        yield 'another application' => [null, true, 'console', 'web', []];
        yield 'its application' => [null, true, 'console', 'console', self::SCOPES];
    }

    /**
     * A live activation grants its role's permission in its scope and nowhere
     * else, through a check, a bulk check, `permissionsFor()` and
     * `whereAuthorized()` alike, cold and from the persistent cache.
     *
     * @param  string|null  $tenant
     * @param  bool  $includeSubtree
     * @param  string|null  $application
     * @param  string|null  $requested
     * @param  list<string>  $allowed
     * @return void
     */
    #[DataProvider('scopes')]
    public function testALiveActivationGrantsItsRoleInItsScopeAlone(?string $tenant, bool $includeSubtree, ?string $application, ?string $requested, array $allowed): void
    {
        $tenants = $this->tree();
        $posts   = self::posts($tenants);
        $user    = StubIdentity::create(['id' => 'user-1']);

        $type = $tenant === null ? null : (new StubTenant)->getMorphClass();

        self::activate($user, self::emergencyRole(), ['tenant_type' => $type, 'tenant_id' => $tenant, 'include_subtree' => $includeSubtree, 'application' => $application]);

        foreach ([1, 2] as $round) {
            foreach (self::SCOPES as $scope) {
                $manager = $this->manager(new Subject($user, $user, $tenants[$scope], $requested));

                $this->assertDecided($manager, $posts[$scope], \in_array($scope, $allowed, true), "{$scope}, round {$round}");
            }
        }
    }

    /**
     * An activation that has expired, or that has ended, grants nothing, and
     * one about to expire grants until the instant it does.
     *
     * @return void
     */
    public function testAnExpiredOrEndedActivationGrantsNothing(): void
    {
        $user  = StubIdentity::create(['id' => 'user-1']);
        $role  = self::emergencyRole();
        $ended = self::activate($user, $role, ['ended_at' => Carbon::now()->subMinute(), 'end_reason' => 'surrendered']);

        self::activate($user, $role, ['activated_at' => Carbon::now()->subHour(), 'expires_at' => Carbon::now()]);

        self::assertFalse($this->manager(new Subject($user, $user))->can(self::ACTION));
        self::assertSame([], $user->getRoles());

        $ended->update(['ended_at' => null, 'end_reason' => null]);

        self::assertTrue($this->manager(new Subject($user, $user))->can(self::ACTION));
        self::assertSame(['responder'], StubIdentity::query()->findOrFail('user-1')->getRoles());

        Carbon::setTestNow(Carbon::now()->addMinutes(30));

        self::assertFalse($this->manager(new Subject($user, $user))->can(self::ACTION));
    }

    /**
     * A normal grant of the role and an activation of it are each their own
     * row: the role is read once for each, and ending the activation leaves the
     * normal grant's access, as revoking the grant leaves the activation's.
     *
     * @return void
     */
    public function testANormalGrantAndAnActivationOfTheSameRoleCoexist(): void
    {
        $user       = StubIdentity::create(['id' => 'user-1']);
        $role       = self::emergencyRole();
        $activation = self::activate($user, $role);

        $user->assignRole($role);

        self::assertSame(['responder', 'responder'], $user->roles()->pluck('name')->all());
        self::assertSame(1, DB::table('authorizable_roles')->count());

        $activation->update(['ended_at' => Carbon::now(), 'end_reason' => 'revoked']);

        self::assertTrue($this->manager(new Subject($user, $user))->can(self::ACTION));
        self::assertSame(1, DB::table('authorizable_roles')->count());

        $activation->update(['ended_at' => null, 'end_reason' => null]);
        $user->revokeRole($role);

        self::assertTrue($this->manager(new Subject($user, $user))->can(self::ACTION));
        self::assertSame(0, DB::table('authorizable_roles')->count());
    }

    /**
     * A deny attached to the grantee, a boundary and a guardrail each still
     * refuse what the activation's role grants.
     *
     * @return void
     */
    public function testDeniesBoundariesAndGuardrailsStillApply(): void
    {
        $limits = [
            'deny'      => fn (StubIdentity $user) => $user->attachPolicy(self::policy('deny', self::ACTION)),
            'boundary'  => fn (StubIdentity $user) => BoundaryService::instance()?->set($user, self::policy('allow', 'other:*')),
            'guardrail' => fn () => DB::table('guardrails')->insert(['policy_id' => self::policy('allow', 'other:*')->getKey()]),
        ];

        foreach ($limits as $kind => $limit) {
            DB::table('guardrails')->delete();

            $user = StubIdentity::create(['id' => 'user-' . $kind]);

            self::activate($user, self::emergencyRole());

            self::assertTrue($this->manager(new Subject($user, $user))->can(self::ACTION), $kind);

            $limit($user);

            // A row written straight to its table bumps no version, so the
            // persistent cache is emptied for the next check to read it.
            Cache::store('array')->clear();

            self::assertFalse($this->manager(new Subject($user, $user))->can(self::ACTION), $kind);
        }
    }

    /**
     * The persistent cache entry of a grantee holding a role only through an
     * activation lapses at the activation's expiry, with no write.
     *
     * @return void
     */
    public function testTheCacheEntryLapsesAtTheActivationsExpiry(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        self::activate($user, self::emergencyRole(), ['expires_at' => Carbon::now()->addMinutes(5)]);

        self::assertTrue($this->manager(new Subject($user, $user))->can(self::ACTION));

        DB::table('break_glass_activations')->update(['expires_at' => Carbon::now()->addHour()]);

        Carbon::setTestNow(Carbon::now()->addMinutes(4));

        // The stored entry still holds, so the row changed without a bump is
        // not read yet.
        self::assertTrue($this->manager(new Subject($user, $user))->can(self::ACTION));

        DB::table('break_glass_activations')->update(['expires_at' => Carbon::now()->addSeconds(30)]);

        Carbon::setTestNow(Carbon::now()->addMinute());

        self::assertFalse($this->manager(new Subject($user, $user))->can(self::ACTION));
    }

    /**
     * A change made through the model bumps the grantee's versions, so the next
     * check sees it, whatever the persistent cache stored: a new activation,
     * one ended, and one deleted.
     *
     * @return void
     */
    public function testAChangeThroughTheModelIsSeenOnTheNextCheck(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $role = self::emergencyRole();

        self::assertFalse($this->manager(new Subject($user, $user))->can(self::ACTION));

        $activation = self::activate($user, $role);

        self::assertTrue($this->manager(new Subject($user, $user))->can(self::ACTION));

        $activation->update(['ended_at' => Carbon::now(), 'ended_by_type' => $user->getMorphClass(), 'ended_by_id' => 'user-1', 'end_reason' => 'surrendered']);

        self::assertFalse($this->manager(new Subject($user, $user))->can(self::ACTION));

        $activation->update(['ended_at' => null]);

        self::assertTrue($this->manager(new Subject($user, $user))->can(self::ACTION));

        $activation->delete();

        self::assertFalse($this->manager(new Subject($user, $user))->can(self::ACTION));
    }

    /**
     * Switching break-glass off stops every live activation at once in the next
     * request, and in a fresh container, whatever the memo or the store kept,
     * while the rows stay; switching it back on counts them again.
     *
     * @return void
     */
    public function testSwitchingBreakGlassOffStopsEveryActivation(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $subject = new Subject($user, $user);

        self::activate($user, self::emergencyRole());

        $warm = $this->manager($subject);

        self::assertTrue($warm->can(self::ACTION));
        self::assertTrue($warm->can(self::ACTION));

        self::switchBreakGlass(false);

        self::assertFalse($this->manager($subject)->can(self::ACTION));
        self::assertFalse(StubIdentity::query()->findOrFail('user-1')->hasRole('responder'));
        self::assertSame(1, DB::table('break_glass_activations')->count());

        self::switchBreakGlass(true);

        self::assertTrue($this->manager($subject)->can(self::ACTION));

        config()->set('authorization.break_glass.enabled', false);

        $this->app?->forgetScopedInstances();

        self::assertFalse($this->manager($subject)->can(self::ACTION));
    }

    /**
     * The unexpired activations are those not ended and not expired, whether
     * break-glass is switched on or off.
     *
     * @return void
     */
    public function testTheUnexpiredActivationsIgnoreTheSwitch(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $role = self::emergencyRole();
        $kept = self::activate($user, $role)->getKey();

        self::activate($user, $role, ['ended_at' => Carbon::now()->subMinute()]);
        self::activate($user, $role, ['expires_at' => Carbon::now()->subMinute()]);

        $unexpired = static fn (): array => BreakGlassActivations::unexpired(DB::table('break_glass_activations'), 'break_glass_activations')->pluck('id')->all();

        self::assertSame([$kept], $unexpired());

        self::switchBreakGlass(false);

        self::assertSame([$kept], $unexpired());
        self::assertSame(0, BreakGlassActivations::live(DB::table('break_glass_activations'), 'break_glass_activations')->count());
    }

    /**
     * Whether break-glass is enabled is read once a request or job, when the
     * record is built: while it is off, no live activation is a role grant row,
     * none is live and no grantee's count; a change to the setting is read by
     * the next request.
     *
     * @return void
     */
    public function testTheSwitchIsReadOnceARequest(): void
    {
        $user  = StubIdentity::create(['id' => 'user-1']);
        $table = 'break_glass_activations';

        self::activate($user, self::emergencyRole());

        config()->set('authorization.break_glass.enabled', false);

        self::assertTrue(BreakGlassActivations::isEnabled());
        self::assertTrue(BreakGlassActivations::isCounted($user));
        self::assertCount(1, BreakGlassActivations::roleGrants()->get());
        self::assertSame(1, BreakGlassActivations::live(DB::table($table), $table)->count());

        self::switchBreakGlass(false);

        self::assertFalse(BreakGlassActivations::isEnabled());
        self::assertFalse(BreakGlassActivations::isCounted($user));
        self::assertCount(0, BreakGlassActivations::roleGrants()->get());
        self::assertSame(0, BreakGlassActivations::live(DB::table($table), $table)->count());
        self::assertSame(1, DB::table($table)->count());
    }

    /**
     * An activation naming a machine, or the identity behind a principal,
     * grants nothing, the principal's own activation and the identity's normal
     * grant reaching the principal still; one naming half a tenant applies
     * nowhere.
     *
     * @return void
     */
    public function testMachinesIdentitiesAndHalfTenantsFailClosed(): void
    {
        $role      = self::emergencyRole();
        $machine   = StubMachine::create(['id' => 'machine-1']);
        $identity  = StubIdentity::create(['id' => 'person-1']);
        $principal = StubIdentity::create(['id' => 'account-1']);
        $half      = StubIdentity::create(['id' => 'half-1']);
        $tenant    = StubTenant::query()->create(['id' => 'o1', 'name' => 'o1']);

        self::activate($machine, $role);
        self::activate($identity, $role);
        self::activate($half, $role, ['tenant_type' => null, 'tenant_id' => 'o1']);
        self::activate($half, $role, ['tenant_type' => $tenant->getMorphClass(), 'tenant_id' => null]);

        self::assertSame([], $machine->getRoles());
        self::assertFalse($machine->hasRole('responder'));
        self::assertFalse($this->manager(new Subject($principal, $identity))->can(self::ACTION));
        self::assertFalse($this->manager(new Subject($half, $half))->can(self::ACTION));
        self::assertFalse($this->manager(new Subject($half, $half, $tenant))->can(self::ACTION));

        // The identity, once read as one, holds nothing through its
        // activations, whether its loaded roles are read or its resolution.
        self::assertFalse($identity->hasRole('responder'));
        self::assertSame([], $identity->getRoles());

        $identity->assignRole($role);
        self::activate($principal, Role::create(['name' => 'auditor']));

        $manager = $this->manager(new Subject($principal, $identity));

        self::assertTrue($manager->can(self::ACTION));
        self::assertSame(['auditor'], $principal->getRoles());
    }

    /**
     * An explanation names the route through the activation as break-glass,
     * with the activation's key, beside the normal grant's route, and never the
     * note, in its evidence, its array and its text.
     *
     * @return void
     */
    public function testAnExplanationNamesTheBreakGlassRouteWithoutTheNote(): void
    {
        $user       = StubIdentity::create(['id' => 'user-1']);
        $role       = self::emergencyRole();
        $activation = self::activate($user, $role);

        $role->attachPolicy(self::policy('allow', self::OTHER));

        $explained = Authorization::for($user)->explain(self::ACTION);
        $policy    = Authorization::for($user)->explain(self::OTHER);
        $route     = new GrantProvenance(GrantSource::BREAK_GLASS_PERMISSION, self::ACTION, Reference::of($user), false, ['responder'], true, null, null, $activation->id);

        self::assertTrue($explained->isAllowed());
        $routes = $policy->evidence->grants ?? [];

        self::assertEquals([$route], $explained->evidence?->grants);
        self::assertSame([GrantSource::BREAK_GLASS_POLICY], \array_map(static fn (GrantProvenance $grant): GrantSource => $grant->source, $routes));
        self::assertSame([$activation->id], \array_map(static fn (GrantProvenance $grant): ?string => $grant->activation, $routes));
        self::assertStringNotContainsString(self::NOTE, (string) \json_encode($explained));
        self::assertStringNotContainsString(self::NOTE, $explained->toText());
        self::assertStringContainsString("through role \"responder\" by break-glass activation \"{$activation->id}\" in platform", $explained->toText());

        $user->assignRole($role);

        $both = Authorization::for(StubIdentity::query()->findOrFail('user-1'))->explain(self::ACTION);

        self::assertSame(
            [GrantSource::ROLE_PERMISSION, GrantSource::BREAK_GLASS_PERMISSION],
            \array_map(static fn (GrantProvenance $grant): GrantSource => $grant->source, $both->evidence->grants ?? []),
        );
    }

    /**
     * The rows read in place of the role grant table are every role grant, with
     * no activation, and every live activation with its key; an uncounted
     * grantee's activations are left out.
     *
     * @return void
     */
    public function testTheRoleGrantRowsHoldEveryGrantAndEveryLiveActivation(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $machine = StubMachine::create(['id' => 'machine-1']);
        $role    = self::emergencyRole();
        $live    = self::activate($user, $role);

        self::activate($user, $role, ['ended_at' => Carbon::now()]);
        self::activate($user, $role, ['expires_at' => Carbon::now()]);
        self::activate($machine, $role);
        $user->assignRole($role);

        $rows   = DB::query()->fromSub(BreakGlassActivations::roleGrants(), 'grants')->where('authorizable_id', 'user-1')->get();
        $second = (array) ($rows->get(1) ?? []);

        self::assertSame([null, $live->id], $rows->pluck(BreakGlassActivations::ACTIVATION)->all());
        self::assertSame(['created_at', 'updated_at'], \array_slice(\array_keys($second), 10, 2));
        self::assertEquals(Carbon::now(), Carbon::parse(\is_string($second['created_at'] ?? null) ? $second['created_at'] : ''));
        self::assertSame([null], BreakGlassActivations::roleGrants(BreakGlassActivations::isCounted($machine))->get()->pluck(BreakGlassActivations::ACTIVATION)->all());
        self::assertCount(3, BreakGlassActivations::roleGrants(now: Carbon::now()->subSecond())->get()->whereNotNull(BreakGlassActivations::ACTIVATION));
    }

    /**
     * Whether a grantee's activations count, the kind its resolutions are kept
     * under, and the activation a role was read through.
     *
     * @return void
     */
    public function testWhatCountsAndWhereItIsKept(): void
    {
        $user     = StubIdentity::create(['id' => 'user-1']);
        $identity = StubIdentity::create(['id' => 'person-1']);
        $machine  = new StubMachine;
        $live     = self::activate($user, self::emergencyRole());
        $marks    = BreakGlassActivations::instance();

        self::assertNotNull($marks);
        self::assertTrue(BreakGlassActivations::isCounted($user));
        self::assertFalse(BreakGlassActivations::isCounted($machine));
        self::assertFalse(BreakGlassActivations::isIdentity($identity));
        self::assertSame('permissions', $marks->kindOf('permissions', $identity));

        BreakGlassActivations::markIdentity($identity);
        BreakGlassActivations::markIdentity($identity);

        self::assertTrue(BreakGlassActivations::isIdentity($identity));
        self::assertFalse(BreakGlassActivations::isIdentity($user));
        self::assertFalse(BreakGlassActivations::isCounted($identity));
        self::assertSame('identity-permissions', $marks->kindOf('permissions', $identity));
        self::assertSame('permissions', $marks->kindOf('permissions', $user));

        $held = $user->roles()->first();

        self::assertInstanceOf(Role::class, $held);
        self::assertSame($live->id, BreakGlassActivations::activationOf($held));
        self::assertNull(BreakGlassActivations::activationOf(new Role));
        self::assertNull(BreakGlassActivations::activationOf((new Role)->setRelation('pivot', new Role)));
        self::assertNull(BreakGlassActivations::activationOf((new Role)->setRelation('pivot', (new Role)->forceFill([BreakGlassActivations::ACTIVATION => '']))));
        self::assertSame('7', BreakGlassActivations::activationOf((new Role)->setRelation('pivot', (new Role)->forceFill([BreakGlassActivations::ACTIVATION => 7]))));
        self::assertNull(BreakGlassActivations::activationOf((new Role)->setRelation('pivot', (new Role)->forceFill([BreakGlassActivations::ACTIVATION => ['7']]))));
    }

    /**
     * Without the record bound, as outside the package's request or job, no
     * instance is marked and no activation counts, as break-glass cannot be
     * read as enabled.
     *
     * @return void
     */
    public function testNothingIsMarkedOrCountedWithoutTheRecordBound(): void
    {
        $identity = StubIdentity::create(['id' => 'person-1']);

        $this->app?->offsetUnset(BreakGlassActivations::class);

        BreakGlassActivations::markIdentity($identity);

        self::assertNull(BreakGlassActivations::instance());
        self::assertFalse(BreakGlassActivations::isIdentity($identity));
        self::assertFalse(BreakGlassActivations::isEnabled());
        self::assertFalse(BreakGlassActivations::isCounted($identity));
    }

    /**
     * Read the tenants' tree, the posts and every grant row through the
     * persistent cache, and use the permissions of the enum.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('authorization.cache.store', 'array');
        $config->set('authorization.permission_enums', [PermissionEnum::class]);
    }

    /**
     * Assert the action is allowed on the post, or not, through a check, a bulk
     * check, the permissions listed and query scoping alike, and the other
     * action never.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $manager
     * @param  \Tests\Fixtures\QueryScoping\TenantScopedPost  $post
     * @param  bool  $expected
     * @param  string  $message
     * @return void
     */
    private function assertDecided(AuthorizationManager $manager, TenantScopedPost $post, bool $expected, string $message): void
    {
        $bulk   = $manager->checkMany(['post' => new CheckInput(self::ACTION, $post), 'none' => new CheckInput(self::ACTION), 'other' => new CheckInput(self::OTHER)]);
        $kept   = TenantScopedPost::query()->whereAuthorized(self::ACTION, [], $manager)->pluck('id')->all(); // @phpstan-ignore method.notFound
        $listed = $manager->permissionsFor(null, AuthorizationScope::current());

        self::assertSame($expected, $manager->can(self::ACTION, $post), $message);
        self::assertSame($expected, $manager->can(self::ACTION), $message);
        self::assertSame($expected, $bulk['post']->isAllowed(), $message);
        self::assertSame($expected, $bulk['none']->isAllowed(), $message);
        self::assertFalse($bulk['other']->isAllowed(), $message);
        self::assertSame($expected, \in_array(self::ACTION, $listed, true), $message);
        self::assertSame($expected, \in_array($post->getKey(), $kept, true), $message);
    }

    /**
     * Resolve the subject as the request's, and return the manager built afresh
     * for it, as a later request would.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return \SineMacula\Laravel\Authorization\AuthorizationManager
     */
    private function manager(Subject $subject): AuthorizationManager
    {
        $this->app?->instance(SubjectResolver::class, new FixedSubjectResolver($subject));
        $this->app?->instance(ResourceTenantResolver::class, new DeclaredResourceTenant(new NoResourceTenant));

        foreach (['authorization', AuthorizationManager::class, ResolvedTenant::class] as $abstract) {
            $this->app?->forgetInstance($abstract);
        }

        Authorization::clearResolvedInstance('authorization');

        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager */
        return $this->app?->make(AuthorizationManager::class);
    }

    /**
     * Build the tree: an organisation with an account below it, and another
     * organisation, each by its name, beside the platform.
     *
     * @return array<string, \Tests\Feature\Stubs\StubTenant|null>
     */
    private function tree(): array
    {
        $this->app?->instance(TenantTree::class, new ClosureTenantTree);

        $tenants = ['platform' => null];

        foreach (['o1', 'a1', 'o2'] as $id) {
            $tenants[$id] = StubTenant::query()->create(['id' => $id, 'name' => $id]);
        }

        ClosureTenantTree::add(Reference::of($tenants['o1']));
        ClosureTenantTree::add(Reference::of($tenants['a1']), Reference::of($tenants['o1']));
        ClosureTenantTree::add(Reference::of($tenants['o2']));

        return $tenants;
    }

    /**
     * Create a post in each scope, the platform's naming no tenant.
     *
     * @param  array<string, \Tests\Feature\Stubs\StubTenant|null>  $tenants
     * @return array<string, \Tests\Fixtures\QueryScoping\TenantScopedPost>
     */
    private static function posts(array $tenants): array
    {
        $posts = [];

        foreach ($tenants as $scope => $tenant) {
            $posts[$scope] = TenantScopedPost::query()->create(['title' => $scope, 'tenant_type' => $tenant?->getMorphClass(), 'tenant_id' => $tenant?->getKey()]);
        }

        return $posts;
    }

    /**
     * Return the policy of one statement of the effect on the action, creating
     * it the first time.
     *
     * @param  string  $effect
     * @param  string  $action
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function policy(string $effect, string $action): Policy
    {
        return Policy::query()->firstOrCreate(['name' => $effect . ' ' . $action], ['document' => ['statements' => [['effect' => $effect, 'actions' => [$action]]]]]);
    }
}
