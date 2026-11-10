<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Concerns\BuildsScopedManagers;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Concerns\RefusesThePackage;
use Tests\Concerns\ScopesQueries;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\RequestSubjectResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubMachine;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for the scoped clones of the authorization manager: each
 * returns a new manager, leaving the one it is called on unchanged.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(BuildsScopedManagers::class)]
final class BuildsScopedManagersTest extends TestCase
{
    use RefusesThePackage, ScopesQueries;

    /**
     * `for()` names the subject, keeping the request's tenant and application,
     * and `forUser()` names the subject the resolver makes of the user, or no
     * subject for a guest; the manager they are called on still decides about
     * the request's subject.
     *
     * @return void
     */
    public function testForAndForUserNameTheSubject(): void
    {
        $user  = StubIdentity::create(['id' => 'scoped-1']);
        $other = StubIdentity::create(['id' => 'scoped-2']);

        $user->givePermission(Permission::create(['name' => 'posts:read']));
        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($other, null, 'admin'));

        $manager = Authorization::getFacadeRoot();
        $named   = Authorization::for($user);

        self::assertNotSame($manager, $named);
        self::assertSame($user, $named->currentSubject()?->subject);
        self::assertSame('admin', $named->currentSubject()->application);
        self::assertTrue($named->can('posts:read'));
        self::assertSame($user, Authorization::forUser($user)->currentSubject()?->subject);
        self::assertNull(Authorization::forUser(null)->currentSubject());
        self::assertSame(DecisionReason::SUBJECT_UNRESOLVED, Authorization::forUser(null)->check('posts:read')->reason);
        self::assertSame($other, Authorization::currentSubject()?->subject);
        self::assertFalse(Authorization::can('posts:read'));

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver);

        self::assertSame($user, Authorization::for($user)->currentSubject()?->identity);

        $subject = new Subject($user, $other, null, 'admin', 'web', 'session-1');

        self::assertSame($subject, Authorization::for($subject)->currentSubject());
        self::assertTrue(Authorization::for($subject)->can('posts:read'));
    }

    /**
     * `withPolicies()` decides through the policies given, and `capped()` caps
     * every check, each in a new manager, the one they are called on unchanged.
     *
     * @return void
     */
    public function testWithPoliciesAndCappedChangeOnlyTheClone(): void
    {
        $user = StubIdentity::create(['id' => 'scoped-3']);

        $user->givePermission(Permission::create(['name' => 'posts:read']));

        $manager  = Authorization::for($user);
        $override = $manager->withPolicies([EvaluationPolicy::fromArray(['name' => 'edit', 'statements' => [['effect' => 'allow', 'actions' => ['posts:edit']]]])]);
        $capped   = $manager->capped(['posts:edit']);

        self::assertTrue($override->can('posts:edit'));
        self::assertFalse($manager->can('posts:edit'));
        self::assertSame(DecisionReason::SESSION_POLICY, $capped->check('posts:read')->reason);
        self::assertTrue($manager->can('posts:read'));
        self::assertSame(DecisionReason::SESSION_POLICY, $capped->capped(['posts:read'])->check('posts:edit')->reason);
    }

    /**
     * `withoutSessionCaps()` decides every check of a new manager without the
     * credential's scopes, the one it is called on still capped by them, and
     * keeps the explicit caps.
     *
     * @return void
     */
    public function testWithoutSessionCapsChangesOnlyTheClone(): void
    {
        $machine = StubMachine::create(['id' => 'scoped-4']);

        $machine->givePermission(Permission::create(['name' => 'posts:read']));

        $manager = Authorization::for($machine);
        $without = $manager->withoutSessionCaps();

        self::assertNotSame($manager, $without);
        self::assertTrue($without->can('posts:read'));
        self::assertSame(DecisionReason::SESSION_POLICY, $manager->check('posts:read')->reason);
        self::assertSame(DecisionReason::SESSION_POLICY, $without->capped(['posts:edit'])->check('posts:read')->reason);
        self::assertSame(DecisionReason::SESSION_POLICY, $manager->capped(['posts:read'])->check('posts:read')->reason);
    }

    /**
     * `for()` of a `Subject` naming a tenant decides there, and so do the
     * managers made from it by `capped()` and `withPolicies()`, while
     * `forUser()`, `for()` of a model and `forActor()` made from it decide in
     * the request's scope, and `forActor()` of the subject decides in the scope
     * in place, wherever the subject is.
     *
     * @return void
     */
    public function testOnlyForOfASubjectDecidesInItsOwnScope(): void
    {
        [$user, $first, $second] = self::heldInFirstTenant('scoped-5');

        $this->resolveRequest(StubIdentity::create(['id' => 'scoped-6']), $second);

        $inFirst = new Subject($user, $user, $first);
        $named   = Authorization::for($inFirst);

        self::assertTrue($named->can('posts:read'));
        self::assertTrue($named->capped(['posts:read'])->can('posts:read'));
        self::assertTrue($named->withPolicies([])->can('posts:read'));
        self::assertFalse($named->forUser($user)->can('posts:read'));
        self::assertFalse($named->for($user)->can('posts:read'));
        self::assertFalse($named->forActor($inFirst)->can('posts:read'));
        self::assertFalse(self::manager()->forActor($inFirst)->can('posts:read'));
        self::assertTrue(AuthorizationScope::tenant($first)->within(static fn (): bool => self::manager()->forActor($inFirst)->can('posts:read')));
        self::assertFalse(AuthorizationScope::tenant($second)->within(static fn (): bool => $named->forActor($inFirst)->can('posts:read')));
        self::assertSame($inFirst, self::manager()->forActor($inFirst)->currentSubject());
        self::assertSame([$second->getMorphClass(), 'tenant-b'], TenantScope::currentTenant());
    }

    /**
     * `for()` of a `Subject` on the platform decides there while the request is
     * in a tenant, so a grant held in that tenant does not allow it and one
     * held on the platform does, while the same subject without the marker
     * decides in the request's tenant; the request's tenant stays in place.
     *
     * @return void
     */
    public function testForOfASubjectOnThePlatformDecidesThere(): void
    {
        [$user, $first] = self::heldInFirstTenant('scoped-12');

        $this->resolveRequest(StubIdentity::create(['id' => 'scoped-13']), $first);
        $user->givePermission(Permission::create(['name' => 'posts:update']));

        $onPlatform = Authorization::for(new Subject($user, $user, platform: true));

        self::assertFalse($onPlatform->can('posts:read'));
        self::assertTrue($onPlatform->can('posts:update'));
        self::assertTrue(Authorization::for(new Subject($user, $user))->can('posts:read'));
        self::assertSame([$first->getMorphClass(), 'tenant-a'], TenantScope::currentTenant());
    }

    /**
     * A request whose subject is on the platform is decided there outside any
     * scope, about itself, a model named through `for()` and the user
     * `forUser()` translates alike, and inside an explicit tenant scope every
     * one of them, the Gate included, is decided in that tenant.
     *
     * @return void
     */
    public function testAnExplicitTenantScopeWinsForARequestOnThePlatform(): void
    {
        [$user, $first] = self::heldInFirstTenant('scoped-14');

        self::declareAbilities();
        $user->givePermission(Permission::create(['name' => 'posts:create']), null, Reference::of($first));

        $inFirst = AuthorizationScope::tenant($first);

        $this->actAs(new Subject($user, $user, platform: true));

        self::assertFalse(Authorization::can('posts:create'));
        self::assertFalse(Authorization::for($user)->can('posts:create'));
        self::assertFalse(Authorization::forUser($user)->can('posts:create'));
        self::assertFalse(Gate::forUser($user)->allows('posts:create'));
        self::assertTrue($inFirst->within(static fn (): bool => Authorization::can('posts:create')));
        self::assertTrue($inFirst->within(static fn (): bool => Authorization::for($user)->can('posts:create')));
        self::assertTrue($inFirst->within(static fn (): bool => Authorization::forUser($user)->can('posts:create')));
        self::assertTrue($inFirst->within(static fn (): bool => Gate::forUser($user)->allows('posts:create')));
    }

    /**
     * Inside an explicit tenant scope, a `Subject` passed to `for()` carrying
     * the platform marker is still decided on the platform, so a grant held in
     * that tenant does not allow it and one held on the platform does, and the
     * tenant scope is back in place afterwards.
     *
     * @return void
     */
    public function testASubjectPassedOnThePlatformIsDecidedThereInsideATenantScope(): void
    {
        [$user, $first] = self::heldInFirstTenant('scoped-15');

        $user->givePermission(Permission::create(['name' => 'posts:update']));

        $this->actAs(new Subject($user, $user, platform: true));

        $decided = AuthorizationScope::tenant($first)->within(static function () use ($user): array {
            $onPlatform = Authorization::for(new Subject($user, $user, platform: true));

            return [$onPlatform->can('posts:read'), $onPlatform->can('posts:update'), TenantScope::currentTenant()];
        });

        self::assertSame([false, true, [$first->getMorphClass(), 'tenant-a']], $decided);
        self::assertNull(TenantScope::currentTenant());
    }

    /**
     * A preview of a `Subject` on the platform, given no scope, is made on the
     * platform, on the subject's application, whatever tenant the request is
     * in, and one of a subject without the marker in the request's tenant.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testAPreviewOfASubjectOnThePlatformIsMadeThere(): void
    {
        [$user, $first] = self::heldInFirstTenant('scoped-16');

        $previewer = StubIdentity::create(['id' => 'scoped-17']);

        $previewer->givePermission(Permission::create(['name' => PackagePermissions::SUBJECT_PREVIEW]));

        $this->resolveRequest($previewer, $first);

        $onPlatform = Authorization::previewFor(new Subject($user, $user, platform: true))->can('posts:read');
        $platform   = Authorization::lastDecisionProvenance();
        $inTenant   = Authorization::previewFor(new Subject($user, $user))->can('posts:read');
        $tenant     = Authorization::lastDecisionProvenance();

        self::assertFalse($onPlatform);
        self::assertNotNull($platform);
        self::assertNull($platform->tenant);
        self::assertTrue($inTenant);
        self::assertSame('tenant-a', $tenant?->tenant?->id);
    }

    /**
     * A `Subject` whose tenant names no record is taken by `for()`, its tenant
     * read only when a check is decided, which refuses it before anything is
     * decided, as each form adapting it does; and `forActor()` is refused on a
     * preview, as `for()` is.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testAnUnreadableTenantAndAForActorOnAPreviewAreRefused(): void
    {
        $user    = StubIdentity::create(['id' => 'scoped-7']);
        $manager = self::manager()->for(new Subject($user, $user, new \stdClass));
        $calls   = [
            static fn (): mixed => $manager->check('posts:read'),
            static fn (): mixed => $manager->can('posts:read'),
            static fn (): mixed => $manager->any(['posts:read'], ['posts', 'p1']),
            static fn (): mixed => $manager->checkMany([new CheckInput('posts:read')]),
            static fn (): mixed => $manager->explain('posts:read'),
        ];

        foreach ($calls as $call) {
            try {
                $call();

                self::fail('The subject is refused.');
            } catch (InvalidTenantException) {
                self::assertNull(Authorization::lastDecision());
            }
        }

        $previewer = StubIdentity::create(['id' => 'scoped-8']);

        $previewer->givePermission(Permission::create(['name' => PackagePermissions::SUBJECT_PREVIEW]));

        $preview = Authorization::for($previewer)->previewFor($user);

        $this->expectException(InvalidPreviewException::class);

        $preview->forActor(new Subject($user, $user));
    }

    /**
     * A preview from a manager whose `Subject` names a tenant keeps its own
     * behaviour: the previewer is admitted in the preview's scope, not in the
     * tenant the previewer names, and the target is decided there.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testAPreviewIsAdmittedInItsOwnScope(): void
    {
        [$user, $first, $second] = self::heldInFirstTenant('scoped-9');

        $previewer = StubIdentity::create(['id' => 'scoped-10']);

        $previewer->givePermission(Permission::create(['name' => PackagePermissions::SUBJECT_PREVIEW]), null, $first);

        $this->resolveRequest(StubIdentity::create(['id' => 'scoped-11']), $second);

        $preview = Authorization::for(new Subject($previewer, $previewer, $second))->previewFor($user, AuthorizationScope::tenant($first));

        self::assertTrue($preview->can('posts:read'));
        self::assertSame('tenant-a', Authorization::lastDecisionProvenance()?->tenant?->id);
        self::assertSame([$second->getMorphClass(), 'tenant-b'], TenantScope::currentTenant());
    }

    /**
     * Once the package refuses, building every scoped manager refuses by the
     * builder's own guard, before the subject is resolved or a resource
     * translated, on a manager obtained while the package was healthy.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryScopedManagerRefusesOnceThePackageRefuses(): void
    {
        $user     = StubIdentity::create(['id' => 'user-1']);
        $manager  = $this->container()->make(AuthorizationManager::class);
        $subject  = new Subject($user, $user);
        $resolved = [];

        $this->refuseThePackage();
        $this->container()->beforeResolving(SubjectResolver::class, static function (string $abstract) use (&$resolved): void {
            $resolved[] = $abstract;
        });

        $this->assertEachRefused([
            'for'                => static fn () => $manager->for($user),
            'forActor'           => static fn () => $manager->forActor($subject),
            'forUser'            => static fn () => $manager->forUser($user),
            'withPolicies'       => static fn () => $manager->withPolicies([]),
            'previewFor'         => static fn () => $manager->previewFor($user),
            'capped'             => static fn () => $manager->capped(['posts:read']),
            'withoutSessionCaps' => static fn () => $manager->withoutSessionCaps(),
        ]);

        self::assertSame([], $resolved);
    }

    /**
     * Resolve the subject given as the request's, translating a user the Gate
     * hands over into the same request, and build the manager afresh for it.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return void
     */
    private function actAs(Subject $subject): void
    {
        $this->app?->instance(SubjectResolver::class, new RequestSubjectResolver($subject));

        foreach (['authorization', AuthorizationManager::class, ResolvedTenant::class] as $abstract) {
            $this->app?->forgetInstance($abstract);
        }

        Authorization::clearResolvedInstance('authorization');
    }

    /**
     * Declare the stub permission enum's abilities, so the Gate hook answers
     * them.
     *
     * @return void
     */
    private static function declareAbilities(): void
    {
        config(['authorization.permission_enums' => [PermissionEnum::class]]);

        (new AuthorizationServiceProvider(app()))->boot();
    }

    /**
     * Return the authorization manager the facade resolves.
     *
     * @return \SineMacula\Laravel\Authorization\AuthorizationManager
     */
    private static function manager(): AuthorizationManager
    {
        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager */
        return Authorization::getFacadeRoot();
    }

    /**
     * Return a user holding `posts:read` in a first tenant alone, with that
     * tenant and a second.
     *
     * @param  string  $id
     * @return array{0: \Tests\Feature\Stubs\StubIdentity, 1: \Tests\Feature\Stubs\StubTenant, 2: \Tests\Feature\Stubs\StubTenant}
     */
    private static function heldInFirstTenant(string $id): array
    {
        $first  = StubTenant::query()->create(['id' => 'tenant-a', 'name' => 'A']);
        $second = StubTenant::query()->create(['id' => 'tenant-b', 'name' => 'B']);
        $user   = StubIdentity::create(['id' => $id]);

        $user->givePermission(Permission::create(['name' => 'posts:read']), null, Reference::of($first));

        return [$user, $first, $second];
    }
}
