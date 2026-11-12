<?php

declare(strict_types = 1);

namespace Tests\Feature\PermissionsFor;

use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Concerns\ListsPermissions;
use SineMacula\Laravel\Authorization\Diagnostics\PackageState;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\HeldPermission;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\PermissionCatalogue;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Concerns\CatchesRefusals;
use Tests\Concerns\PreviewsSubjects;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Concerns\RefusesThePackage;
use Tests\Concerns\ReportsEveryDecision;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubRequirementChecker;
use Tests\Feature\Stubs\StubTenant;
use Tests\Fixtures\PermissionsFor\DeclaredPermissions;
use Tests\TestCase;

/**
 * Feature tests for the listings of the authorization manager:
 * `heldPermissionsFor()`, the actions a subject may take in a scope, each with
 * every authentication requirement its decision read, and `permissionsFor()`,
 * the same actions by name, both listed through the one path.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversTrait(ListsPermissions::class)]
final class ListsPermissionsTest extends TestCase
{
    use CatchesRefusals, PreviewsSubjects, ReadsDispatchedEvents, RefusesThePackage, ReportsEveryDecision;

    /** @var string The first action the enum declares. */
    private const string CREATE = 'posts:create';

    /** @var string The second action the enum declares. */
    private const string DELETE = 'posts:delete';

    /** @var array<string, mixed> A requirement of multifactor authentication. */
    private const array MULTIFACTOR = ['multifactor' => []];

    /** @var array<string, mixed> A requirement of a phishing-resistant authenticator. */
    private const array PHISHING_RESISTANT = ['phishing_resistant' => []];

    /**
     * Register the permission enum before each test.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->reportEveryDecision();

        $this->app?->make('config')->set('authorization.permission_enums', [PermissionEnum::class]);
    }

    /**
     * An action allowed with no authentication requirement read is listed,
     * unconditional.
     *
     * @return void
     */
    public function testAnActionAllowedWithNoRequirementIsUnconditional(): void
    {
        $user    = self::target('user-1', [self::CREATE]);
        $manager = $this->signIn($user, checker: self::meeting());
        $held    = $manager->heldPermissionsFor(null, AuthorizationScope::current());

        self::assertListed([[self::CREATE, []]], $manager, null, AuthorizationScope::current());
        self::assertTrue($held[0]->isUnconditional());
    }

    /**
     * An action allowed by a statement, of a policy attached to the subject or
     * to a role it holds, whose requirement is met is listed, conditional,
     * naming the requirement.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAllowWhoseRequirementIsMetIsConditional(): void
    {
        $user = self::target('user-1', []);
        $role = Role::create(['name' => 'editor']);

        self::attachStatements($user, 'step-up', [self::requiring(self::CREATE)]);
        $role->attachPolicy(Policy::create(['name' => 'strong', 'document' => ['statements' => [self::allowing(self::DELETE, self::PHISHING_RESISTANT)]]]));
        $user->assignRole($role);

        $manager = $this->signIn($user, checker: self::meeting());
        $held    = $manager->heldPermissionsFor(null, AuthorizationScope::current());

        self::assertListed([[self::CREATE, ['multifactor']], [self::DELETE, ['phishing_resistant']]], $manager, null, AuthorizationScope::current());
        self::assertFalse($held[0]->isUnconditional());
    }

    /**
     * An action whose only allow needs a requirement that is not met is not
     * listed, its check being `insufficient_authentication`, as
     * `permissionsFor()` leaves it out.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAllowNeedingAnUnmetRequirementIsNotListed(): void
    {
        $user = self::target('user-1', [self::DELETE]);

        self::attachStatements($user, 'step-up', [self::requiring(self::CREATE)]);

        $manager = $this->signIn($user, checker: new StubRequirementChecker(RequirementResult::unmet(['multifactor'])));

        self::assertListed([[self::DELETE, []]], $manager, null, AuthorizationScope::current());
        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $manager->check(self::CREATE)->reason);
    }

    /**
     * A deny guarded by a requirement applies only while it is met, so the
     * action another allow lets through is listed only while it is unmet, and
     * conditional, naming the deny's requirement; a boundary whose allow needs
     * a requirement refuses only while it is unmet, so what it lets through is
     * listed only while it is met, conditional on it too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequirementGuardingADenyOrACapMakesTheEntryConditional(): void
    {
        $user   = self::target('user-1', [self::CREATE, self::DELETE]);
        $scope  = AuthorizationScope::current();
        $phish  = ['phishing_resistant' => RequirementResult::unmet(['phishing_resistant'])];
        $unmet  = new StubRequirementChecker(RequirementResult::unmet(['multifactor', 'phishing_resistant']));
        $strong = new StubRequirementChecker(RequirementResult::met(), $phish);

        self::attachStatements($user, 'guarded', [self::denying(self::DELETE, self::PHISHING_RESISTANT)]);

        self::assertListed([[self::CREATE, []], [self::DELETE, ['phishing_resistant']]], $this->signIn($user, checker: $strong), null, $scope);
        self::assertListed([[self::CREATE, []]], $this->signIn($user, checker: self::meeting()), null, $scope);

        $boundary = Policy::create(['name' => 'boundary', 'document' => ['statements' => [self::allowing('posts:*', self::MULTIFACTOR)]]]);

        $this->app?->make(BoundaryService::class)->set($user, $boundary);

        self::assertListed([[self::CREATE, ['multifactor']], [self::DELETE, ['multifactor', 'phishing_resistant']]], $this->signIn($user, checker: $strong), null, $scope);
        self::assertListed([[self::CREATE, ['multifactor']]], $this->signIn($user, checker: self::meeting()), null, $scope);
        self::assertListed([], $this->signIn($user, checker: $unmet), null, $scope);
    }

    /**
     * A requirement read inside a statement's conditions, beside a test of the
     * caller's input, is named when the statement allows the action.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequirementInsideAConditionIsTracked(): void
    {
        $user = self::target('user-1', []);

        self::attachStatements($user, 'flagged', [
            ['effect' => 'allow', 'actions' => [self::CREATE], 'conditions' => [
                'eq'                         => ['input.flag' => 'on'],
                'authentication_requirement' => ['authentication' => self::MULTIFACTOR],
            ]],
        ]);

        $manager = $this->signIn($user, checker: self::meeting());

        self::assertListed([[self::CREATE, ['multifactor']]], $manager, null, AuthorizationScope::current(), ['flag' => 'on']);
        self::assertListed([], $manager, null, AuthorizationScope::current(), ['flag' => 'off']);
    }

    /**
     * Several requirements read for one action, on allows and on a deny, are
     * named once each, sorted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSeveralRequirementsAreNamedOnceSorted(): void
    {
        $user = self::target('user-1', []);

        self::attachStatements($user, 'several', [
            self::denying(self::CREATE, ['assurance_level' => ['min' => 'high']]),
            self::allowing(self::CREATE, [...self::PHISHING_RESISTANT, ...self::MULTIFACTOR]),
            self::allowing(self::CREATE, self::MULTIFACTOR),
        ]);

        $checker = new StubRequirementChecker(RequirementResult::met(), ['assurance_level' => RequirementResult::unmet(['assurance_level'])]);

        $expected = [[self::CREATE, ['assurance_level', 'multifactor', 'phishing_resistant']]];

        self::assertListed($expected, $this->signIn($user, checker: $checker), null, AuthorizationScope::current());
    }

    /**
     * The subject is taken as `permissionsFor()` takes it: null as the
     * manager's own, the request's with its session, the one `for()` names, or
     * a guest; a resolved `Subject` as it is, its session kept; and any other
     * object as `for()` names it, with no session, so a requirement made of it
     * is not met.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSubjectIsTakenAsTheChecksTakeIt(): void
    {
        $user  = self::target('user-1', [self::DELETE]);
        $other = self::target('user-2', [self::CREATE]);
        $scope = AuthorizationScope::current();

        self::attachStatements($user, 'step-up', [self::requiring(self::CREATE)]);

        $manager = $this->signIn($user, checker: self::meeting());
        $both    = [[self::CREATE, ['multifactor']], [self::DELETE, []]];

        self::assertListed($both, $manager, null, $scope);
        self::assertListed($both, $manager, new Subject($user, $user, null, null, 'web', 'session-2'), $scope);
        self::assertListed([[self::DELETE, []]], $manager, $user, $scope);
        self::assertListed([[self::CREATE, []]], $manager, $other, $scope);
        self::assertListed([[self::CREATE, []]], $manager->for($other), null, $scope);
        self::assertListed([], $manager->forUser(null), null, $scope);
    }

    /**
     * The scope's tenant is put in place, as the subject's and as the scope of
     * the grants that count, a subject on the platform included, and the
     * request's tenant is back in place afterwards.
     *
     * @return void
     */
    public function testTheScopeGivenIsTheOneListedIn(): void
    {
        $first  = StubTenant::query()->create(['id' => 't1', 'name' => 't1']);
        $second = StubTenant::query()->create(['id' => 't2', 'name' => 't2']);
        $user   = StubIdentity::query()->create(['id' => 'user-1']);

        $user->givePermission(self::permission(self::CREATE), null, $first);
        $user->givePermission(self::permission(self::DELETE), null, $second);

        $manager    = $this->signIn($user, tenant: $first);
        $onPlatform = new Subject($user, $user, platform: true);

        self::assertListed([[self::CREATE, []]], $manager, null, AuthorizationScope::current());
        self::assertListed([[self::DELETE, []]], $manager, null, AuthorizationScope::tenant($second));
        self::assertListed([[self::DELETE, []]], $manager, $onPlatform, AuthorizationScope::tenant(Reference::of($second)));
        self::assertListed([], $manager, $onPlatform, AuthorizationScope::platform());
        self::assertSame([$first->getMorphClass(), 't1'], TenantScope::currentTenant());
    }

    /**
     * Every action is decided on the scope's resource, so a statement allowing
     * one record, with a requirement, lists its action for that record alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryActionIsDecidedOnTheScopesResource(): void
    {
        $user = self::target('user-1', []);

        self::attachStatements($user, 'one-post', [[...self::requiring(self::DELETE), 'resources' => ['posts:p1']]]);

        $manager = $this->signIn($user, checker: self::meeting());
        $scope   = AuthorizationScope::current();

        self::assertListed([], $manager, null, $scope);
        self::assertListed([[self::DELETE, ['multifactor']]], $manager, null, $scope->withResource(ResourceReference::record('posts', 'p1')));
        self::assertListed([], $manager, null, $scope->withResource(ResourceReference::record('posts', 'p2')));
    }

    /**
     * Each name of the catalogue is listed once, in its order, one declared for
     * two guards included.
     *
     * @return void
     */
    public function testEachNameIsListedOnceInTheCataloguesOrder(): void
    {
        $user = self::target('user-1', ['*']);

        $this->app?->make('config')->set('authorization.permission_providers', [DeclaredPermissions::class]);
        $this->app?->instance(DeclaredPermissions::class, new DeclaredPermissions([
            new PermissionDefinition('reports:view'),
            new PermissionDefinition('reports:view', null, null, 'api'),
        ]));

        $manager = $this->signIn($user);
        $package = \array_map(static fn (PermissionDefinition $definition): string => $definition->name, (new PackagePermissions)->permissions());
        $held    = \array_map(static fn (HeldPermission $held): string => $held->action, $manager->heldPermissionsFor(null, AuthorizationScope::current()));

        self::assertSame([...$package, self::CREATE, self::DELETE, 'reports:view'], $held);
        self::assertSame($held, $manager->permissionsFor(null, AuthorizationScope::current()));
    }

    /**
     * Listing is introspection: neither listing records a last decision or
     * dispatches a `DecisionEvaluated` or an `AuthorizationFailed`, allowed or
     * refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testListingRecordsNothing(): void
    {
        $user = self::target('user-1', [self::CREATE]);

        self::attachStatements($user, 'step-up', [self::requiring(self::DELETE)]);

        $manager = $this->signIn($user, checker: self::meeting());

        self::assertCount(2, $manager->heldPermissionsFor(null, AuthorizationScope::current()));
        self::assertNull($manager->lastDecision());

        $last = $manager->check('posts:read');

        Event::fake([DecisionEvaluated::class, AuthorizationFailed::class]);

        self::assertCount(2, $manager->heldPermissionsFor(null, AuthorizationScope::current()));
        self::assertCount(2, $manager->permissionsFor(null, AuthorizationScope::current()->withResource('posts:p1')));
        self::assertSame($last, $manager->lastDecision());
        self::assertSame([], self::dispatchedEvents(DecisionEvaluated::class));
        self::assertSame([], self::dispatchedEvents(AuthorizationFailed::class));
    }

    /**
     * On a preview, both listings list the target's actions in the preview's
     * scope, as through `for()`, the target having no session, so a deny
     * guarded by a requirement does not apply and the action it guards is
     * conditional; each action evaluated is reported, naming both parties, and
     * none is stored, the last decision being the admission.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPreviewListsTheTargetsActionsAndReportsEach(): void
    {
        Event::fake([DecisionEvaluated::class]);

        $caller = self::previewer();
        $target = self::target('target', [self::CREATE, self::DELETE]);

        self::attachStatements($target, 'guarded', [self::denying(self::DELETE, self::MULTIFACTOR)]);

        $manager = $this->signIn($caller, checker: self::meeting());
        $preview = $manager->previewFor($target);
        $scope   = AuthorizationScope::current();
        $built   = \count(self::dispatchedEvents(DecisionEvaluated::class));

        self::assertListed([[self::CREATE, []], [self::DELETE, ['multifactor']]], $preview, null, $scope);
        self::assertSame(self::described($manager->for($target)->heldPermissionsFor(null, $scope)), self::described($preview->heldPermissionsFor(null, $scope)));

        $events  = \array_slice(self::dispatchedEvents(DecisionEvaluated::class), $built);
        $actions = \array_values(\array_unique(\array_map(static fn (PermissionDefinition $definition): string => $definition->name, $this->catalogue()->definitions())));

        $reported = \array_map(static fn (DecisionEvaluated $event): string => $event->action, \array_slice($events, 0, \count($actions) + 1));

        self::assertSame([PackagePermissions::SUBJECT_PREVIEW, ...$actions], $reported);

        foreach (\array_slice($events, 1, \count($actions)) as $event) {
            self::assertEquals(Reference::of($caller), $event->previewer);
            self::assertEquals(Reference::of($target), $event->subject);
        }

        self::assertTrue($manager->lastDecision()?->isAllowed());
        self::assertNull($manager->lastDecisionProvenance()?->previewer);
        self::assertEquals(Reference::of($caller), $manager->lastDecisionProvenance()?->subject);
    }

    /**
     * On a preview, naming any subject is refused as a change of its target by
     * the listing asked, and a scope of another application by both.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPreviewRefusesASubjectOrAnotherScope(): void
    {
        $target  = self::target('target', [self::CREATE]);
        $preview = $this->signIn(self::previewer())->previewFor($target);

        foreach ([$target, new Subject($target, $target)] as $named) {
            $held   = self::refusalOf(static fn (): mixed => $preview->heldPermissionsFor($named, AuthorizationScope::current()));
            $listed = self::refusalOf(static fn (): mixed => $preview->permissionsFor($named, AuthorizationScope::current()));

            self::assertInstanceOf(InvalidPreviewException::class, $held);
            self::assertInstanceOf(InvalidPreviewException::class, $listed);
            self::assertStringContainsString('through heldPermissionsFor()', $held->getMessage());
            self::assertStringContainsString('through permissionsFor()', $listed->getMessage());
        }

        self::assertInstanceOf(InvalidPreviewException::class, self::refusalOf(static fn (): mixed => $preview->heldPermissionsFor(null, AuthorizationScope::platform('admin'))));
        self::assertInstanceOf(InvalidPreviewException::class, self::refusalOf(static fn (): mixed => $preview->permissionsFor(null, AuthorizationScope::platform('admin'))));
    }

    /**
     * Both listings refuse while the package refuses, each in the method
     * itself, before anything is read.
     *
     * @return void
     */
    public function testBothListingsRefuseWhileThePackageRefuses(): void
    {
        $manager = $this->signIn(self::target('user-1', [self::CREATE]));
        $scope   = AuthorizationScope::current();

        $this->refuseThePackage();

        $this->assertEachRefused([
            'permissionsFor'     => static fn (): mixed => $manager->permissionsFor(null, $scope),
            'heldPermissionsFor' => static fn (): mixed => $manager->heldPermissionsFor(null, $scope),
        ]);
    }

    /**
     * With no package state held, as on a manager built in a container the
     * package was never registered in, both listings list as ever.
     *
     * @return void
     */
    public function testWithNoPackageStateBothListingsList(): void
    {
        $user = self::target('user-1', [self::CREATE]);

        $this->app?->forgetInstance(PackageState::class);

        $manager = $this->signIn($user);

        self::assertNull(PackageState::of($this->container()));
        self::assertListed([[self::CREATE, []]], $manager, null, AuthorizationScope::current());
    }

    /**
     * Assert that `heldPermissionsFor()` lists the actions given, in order,
     * each with the requirements given, and that `permissionsFor()` lists the
     * same actions, for the same arguments on the same manager.
     *
     * @param  list<array{string, list<string>}>  $expected
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $manager
     * @param  object|null  $subject
     * @param  \SineMacula\Laravel\Authorization\Support\AuthorizationScope  $scope
     * @param  array<string, mixed>  $context
     * @return void
     */
    private static function assertListed(array $expected, AuthorizationManager $manager, ?object $subject, AuthorizationScope $scope, array $context = []): void
    {
        self::assertSame($expected, self::described($manager->heldPermissionsFor($subject, $scope, $context)));
        self::assertSame(\array_column($expected, 0), $manager->permissionsFor($subject, $scope, $context));
    }

    /**
     * Return each held permission as its action and its requirements.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\HeldPermission>  $held
     * @return list<array{string, list<string>}>
     */
    private static function described(array $held): array
    {
        return \array_map(static fn (HeldPermission $permission): array => [$permission->action, $permission->requirements], $held);
    }

    /**
     * Return a statement allowing the action once the requirement is met.
     *
     * @param  string  $action
     * @param  array<string, mixed>  $requirement
     * @return array<string, mixed>
     */
    private static function allowing(string $action, array $requirement): array
    {
        return ['effect' => 'allow', 'actions' => [$action], 'conditions' => ['authentication_requirement' => ['authentication' => $requirement]]];
    }

    /**
     * Return a statement denying the action while the requirement is met.
     *
     * @param  string  $action
     * @param  array<string, mixed>  $requirement
     * @return array<string, mixed>
     */
    private static function denying(string $action, array $requirement): array
    {
        return ['effect' => 'deny', 'actions' => [$action], 'conditions' => ['authentication_requirement' => ['authentication' => $requirement]]];
    }

    /**
     * Return a requirement checker that meets every requirement.
     *
     * @return \Tests\Feature\Stubs\StubRequirementChecker
     */
    private static function meeting(): StubRequirementChecker
    {
        return new StubRequirementChecker(RequirementResult::met());
    }

    /**
     * Return the permission catalogue of the request.
     *
     * @return \SineMacula\Laravel\Authorization\Support\PermissionCatalogue
     */
    private function catalogue(): PermissionCatalogue
    {
        $catalogue = $this->app?->make(PermissionCatalogue::class);

        self::assertInstanceOf(PermissionCatalogue::class, $catalogue);

        return $catalogue;
    }
}
