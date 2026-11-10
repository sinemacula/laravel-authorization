<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Enums\DependencyPhase;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Preview\Previewing;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\SessionScopes;
use Tests\Concerns\ActsAsTenant;
use Tests\Concerns\CatchesRefusals;
use Tests\Feature\Stubs\FixedSubjectResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubMachine;
use Tests\Feature\Stubs\StubSessionPolicySource;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for `ActingContext`, who makes a delegated administration call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ActingContext::class)]
final class ActingContextTest extends TestCase
{
    use ActsAsTenant, CatchesRefusals;

    /**
     * Turn rank off: these tests are about the acting context, and name
     * grantees by references alone, whose rank cannot be read (see
     * `OperationConstraintsTest` for rank).
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config(['authorization.rank.enabled' => false]);
    }

    /**
     * The current acting context is the request's subject as `check()` resolves
     * it, its identity, guard and session kept.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testTheCurrentContextKeepsTheRequestsSubjectAndSession(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $subject = new Subject($user, $user, null, 'admin', 'web', 'session-1');

        $this->resolving($subject);

        $actor = ActingContext::current();

        self::assertSame($subject, $actor->subject);
        self::assertSame('session-1', $actor->subject->session);
        self::assertEquals(Reference::of($user), $actor->principal());
        self::assertEquals(Reference::of($user), $actor->identity());
        self::assertFalse($actor->isImpersonating());
        self::assertSame([], $actor->caps);
    }

    /**
     * A model is named as `Authorization::for()` names it, with no session; a
     * resolved subject is kept as it is.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testAModelIsNamedWithoutASessionAndASubjectAsItIs(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $admin   = StubIdentity::create(['id' => 'admin-1']);
        $subject = new Subject($admin, $user, null, null, 'web', 'session-1');

        $this->resolving(new Subject($user, $user, null, 'admin', 'web', 'session-1'));

        $named = ActingContext::for($admin);

        self::assertSame($admin, $named->subject->subject);
        self::assertNull($named->subject->session);
        self::assertSame('admin', $named->subject->application);
        self::assertSame($subject, ActingContext::for($subject)->subject);
        self::assertEquals(Reference::of($user), ActingContext::for($subject)->identity());
    }

    /**
     * An acting subject that cannot be resolved refuses as
     * `subject_unresolved`, with the decision, and never falls back to a
     * trusted call: none for the request, an unsaved model, a model without a
     * key, and an identity that is not a saved model reads as none.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testAnActorThatCannotBeResolvedRefuses(): void
    {
        $this->resolving(null);

        $resolutions = [
            static fn (): ActingContext => ActingContext::current(),
            static fn (): ActingContext => ActingContext::for(new StubIdentity(['id' => 'ghost'])),
            static fn (): ActingContext => ActingContext::for(new Subject(new \stdClass)),
            static fn (): ActingContext => ActingContext::for(new Subject(self::keyless())),
        ];

        foreach ($resolutions as $resolve) {
            $refusal = self::refusalOf($resolve);

            self::assertInstanceOf(AuthorizationException::class, $refusal);
            self::assertSame(DecisionReason::SUBJECT_UNRESOLVED, $refusal->getReason());
            self::assertSame(DecisionStage::SUBJECT, $refusal->getDecision()?->stage);
            self::assertSame('This action is unauthorized.', $refusal->getMessage());
        }

        $user = StubIdentity::create(['id' => 'user-1']);

        self::assertNull(ActingContext::for(new Subject($user, new \stdClass))->identity());
        self::assertNull(ActingContext::for(new Subject($user, new StubIdentity(['id' => 'ghost'])))->identity());
    }

    /**
     * A preview confers no authority: an acting context built while a preview
     * is evaluated, for the request or for a model, and one built from a
     * preview's target, whenever, is refused as `administration.previewing`, at
     * the administration stage; the target's model, named by the application
     * outside a preview, is its own acting subject.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testAContextBuiltWhileOrFromAPreviewIsRefused(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $target = StubIdentity::create(['id' => 'user-2']);
        $named  = Previewing::current()->track(new Subject($target, $target));

        $this->resolving(new Subject($user, $user));

        $refusals = [
            static fn (): ActingContext => Previewing::current()->during(static fn (): ActingContext => ActingContext::current()),
            static fn (): ActingContext => Previewing::current()->during(static fn (): ActingContext => ActingContext::for($target)),
            static fn (): ActingContext => ActingContext::for($named),
        ];

        foreach ($refusals as $refused) {
            $refusal = self::refusalOf($refused);

            self::assertInstanceOf(AuthorizationException::class, $refusal);
            self::assertSame(DecisionReason::ADMINISTRATION_PREVIEWING, $refusal->getReason());
            self::assertSame(DecisionStage::ADMINISTRATION, $refusal->getDecision()?->stage);
        }

        self::assertSame($target, ActingContext::for($target)->subject->subject);
        self::assertSame($user, ActingContext::current()->subject->subject);
    }

    /**
     * With no authorization manager bound, a model cannot be named, and a
     * resolved subject is refused once it is decided about.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testWithoutAManagerNothingIsDecided(): void
    {
        $user      = StubIdentity::create(['id' => 'user-1']);
        $actor     = ActingContext::for(new Subject($user, $user));
        $container = Container::getInstance();

        Container::setInstance(new Container);

        try {
            self::assertSame(DecisionReason::SUBJECT_UNRESOLVED, self::reasonOf(static fn (): ActingContext => ActingContext::for($user)));
            self::assertSame(DecisionReason::SUBJECT_UNRESOLVED, self::reasonOf(static fn (): Decision => $actor->decide('posts:edit')));
        } finally {
            Container::setInstance($container);
        }
    }

    /**
     * The acting subject is decided about through `check()`, with every cap the
     * call adds: an action none of a cap covers is refused at the session
     * stage, and caps intersect.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCallsCapsCapEveryDecision(): void
    {
        $admin = StubIdentity::create(['id' => 'admin-1']);

        $admin->givePermission(Permission::create(['name' => 'posts:*']));

        $actor = ActingContext::for($admin);

        self::assertTrue($actor->decide('posts:edit')->isAllowed());
        self::assertTrue($actor->capped(['posts:*'])->decide('posts:edit')->isAllowed());
        self::assertSame(DecisionReason::SESSION_POLICY, $actor->capped(['posts:read'])->decide('posts:edit')->reason);
        self::assertSame(DecisionReason::SESSION_POLICY, $actor->capped(['posts:*'])->capped(['posts:read'])->decide('posts:edit')->reason);
        self::assertSame([['posts:*'], ['posts:read']], $actor->capped(['posts:*'])->capped(['posts:read'])->caps);
    }

    /**
     * The refusal of an operation as a whole is recorded and reported as the
     * acting subject's, on the operation resource and under the operation's
     * first action, the operation type standing for an operation with none, and
     * the `AuthorizationException` carrying it is returned.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRefusalOfAnOperationIsReportedAsTheActors(): void
    {
        Event::fake();

        $admin    = StubIdentity::create(['id' => 'admin-1']);
        $actor    = ActingContext::for($admin);
        $decision = Decision::deny(DecisionReason::ADMINISTRATION_CONFLICT, DecisionStage::ADMINISTRATION);
        $named    = Operation::begin($actor, [PackagePermissions::ROLE_GRANT, PackagePermissions::ROLE_REVOKE]);
        $bare     = Operation::begin($actor);

        self::assertSame($decision, $actor->reportRefusal($named, $decision)->getDecision());
        self::assertSame($decision, $actor->reportRefusal($bare, $decision)->getDecision());

        $principal = $actor->principal();
        $failed    = static function (Operation $operation, string $action) use ($principal): \Closure {
            $named = [$principal->type, $principal->id, $action, OperationResource::TYPE . ':' . $operation->id];

            return static fn (AuthorizationFailed $event): bool => [$event->subject?->type, $event->subject?->id, $event->action, $event->resource] === $named;
        };

        Event::assertDispatched(AuthorizationFailed::class, $failed($named, PackagePermissions::ROLE_GRANT));
        Event::assertDispatched(AuthorizationFailed::class, $failed($bare, OperationResource::TYPE));
        Event::assertDispatchedTimes(DecisionEvaluated::class, 2);
    }

    /**
     * A machine actor keeps the scopes of its credential, which cap what it may
     * administer as they cap its other checks: none allow nothing, and an
     * administration action they do not cover is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMachineActorKeepsItsCredentialsCaps(): void
    {
        $machine = StubMachine::create(['id' => 'svc-1']);

        $machine->givePermission(Permission::create(['name' => 'authorization:*']));

        $edit   = Permission::create(['name' => 'posts:edit']);
        $revoke = OperationResource::revoke(PackagePermissions::PERMISSION_REVOKE, new Reference('user', '1'), $edit, GrantScope::platform());

        self::assertSame(DecisionReason::SESSION_POLICY, ActingContext::for($machine)->check($revoke)->reason);

        $this->withCredential(['authorization:role.*']);

        self::assertSame(DecisionReason::SESSION_POLICY, ActingContext::for($machine)->check($revoke)->reason);

        $this->withCredential(['authorization:permission.revoke']);

        self::assertTrue(ActingContext::for($machine)->check($revoke)->isAllowed());
    }

    /**
     * An impersonated acting context names its impersonator, a model or a
     * reference, and keeps its subject and caps.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testAnImpersonatedContextNamesItsImpersonator(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $support = StubIdentity::create(['id' => 'support-1']);
        $actor   = ActingContext::for($user)->capped(['posts:*']);

        self::assertTrue($actor->impersonatedBy($support)->isImpersonating());
        self::assertEquals(Reference::of($support), $actor->impersonatedBy($support)->impersonator);
        self::assertEquals(new Reference('support', '9'), $actor->impersonatedBy(new Reference('support', '9'))->impersonator);
        self::assertSame($actor->subject, $actor->impersonatedBy($support)->subject);
        self::assertSame([['posts:*']], $actor->impersonatedBy($support)->caps);
        self::assertSame([['posts:*'], ['posts:read']], $actor->impersonatedBy($support)->capped(['posts:read'])->caps);
        self::assertEquals(Reference::of($support), $actor->impersonatedBy($support)->capped(['posts:read'])->impersonator);
    }

    /**
     * A screen checking an operation gets the decision a service's
     * authorization makes: allowed for a change that only narrows, and refused
     * with the decision, reported with `AuthorizationFailed`, for one that
     * widens in a way that cannot be proved, such as detaching a denying
     * policy.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCheckAndAuthorizeMakeTheSameDecision(): void
    {
        Event::fake([AuthorizationFailed::class]);

        $admin = StubIdentity::create(['id' => 'admin-1']);

        $admin->givePermission(Permission::create(['name' => 'authorization:*']));

        $actor  = ActingContext::for($admin);
        $role   = Role::create(['name' => 'editor']);
        $deny   = Policy::create(['name' => 'denying', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['posts:*']]]]]);
        $grant  = OperationResource::revoke(PackagePermissions::POLICY_DETACH, new Reference('user', '1'), $deny, GrantScope::platform());
        $revoke = OperationResource::revoke(PackagePermissions::ROLE_REVOKE, new Reference('user', '1'), $role, GrantScope::platform());

        self::assertTrue($actor->check($revoke)->isAllowed());

        $actor->authorize($revoke);

        $screen  = $actor->check($grant);
        $refusal = self::refusalOf(static fn () => $actor->authorize($grant));

        self::assertInstanceOf(AuthorizationException::class, $refusal);
        self::assertEquals($screen, $refusal->getDecision());
        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, $refusal->getReason());
        Event::assertDispatchedTimes(AuthorizationFailed::class, 1);
        Event::assertDispatched(
            AuthorizationFailed::class,
            static fn (AuthorizationFailed $event): bool => $event->subject?->id === $admin->getKey() && $event->action === PackagePermissions::POLICY_DETACH,
        );
    }

    /**
     * Every change an operation makes is decided in order, each correlated with
     * the operation by its id, until the first refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryChangeOfAnOperationIsDecidedWithItsId(): void
    {
        Event::fake([DecisionEvaluated::class]);

        $admin = StubIdentity::create(['id' => 'admin-1']);

        $admin->givePermission(Permission::create(['name' => PackagePermissions::ROLE_REVOKE]));

        $actor     = ActingContext::for($admin);
        $operation = Operation::begin($actor);
        $role      = Role::create(['name' => 'editor']);
        $revoke    = OperationResource::revoke(PackagePermissions::ROLE_REVOKE, new Reference('user', '1'), $role, GrantScope::platform());

        $actor->authorizeIn($operation, $revoke, $revoke);
        $actor->authorizeIn($operation);

        Event::assertDispatchedTimes(DecisionEvaluated::class, 2);
        Event::assertNotDispatched(DecisionEvaluated::class, static fn (DecisionEvaluated $event): bool => $event->resource !== OperationResource::TYPE . ':' . $operation->id);

        $refusal = self::refusalOf(static fn () => $actor->impersonatedBy(new Reference('support', '9'))->authorizeIn($operation, $revoke, $revoke));

        self::assertSame(DecisionReason::ADMINISTRATION_IMPERSONATING, $refusal instanceof AuthorizationException ? $refusal->getReason() : null);
        Event::assertDispatchedTimes(DecisionEvaluated::class, 3);
    }

    /**
     * Inside a delegated operation's work, the actor's authority and what the
     * changes change are locked before the first is decided, and validated once
     * every change is allowed, so a change landing in between is a conflict;
     * outside every operation, nothing is locked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheChangesOfADelegatedOperationAreLockedAndValidated(): void
    {
        $admin = StubIdentity::create(['id' => 'admin-1']);

        $admin->givePermission(Permission::create(['name' => PackagePermissions::ROLE_REVOKE]));

        $actor     = ActingContext::for($admin);
        $operation = Operation::begin($actor);
        $role      = Role::create(['name' => 'editor']);
        $revoke    = OperationResource::revoke(PackagePermissions::ROLE_REVOKE, new Reference('user', '1'), $role, GrantScope::platform());

        $actor->authorizeIn($operation, $revoke);

        $phases = OperationScope::run($operation, static function () use ($actor, $operation, $revoke): ?DependencyPhase {
            $actor->authorizeIn($operation, $revoke);

            return OperationScope::pins()?->phase();
        });

        self::assertSame(DependencyPhase::TARGET, $phases);

        Event::listen(DecisionEvaluated::class, static function () use ($role): void {
            Role::query()->whereKey($role->getKey())->update(['description' => 'changed']);
        });

        $conflict = null;

        try {
            OperationScope::run(new Operation($operation->id, $operation->actor, $operation->at, false), static fn () => $actor->authorizeIn($operation, $revoke));
        } catch (AuthorizationException $refusal) {
            $conflict = $refusal->getReason();
        }

        self::assertSame(DecisionReason::ADMINISTRATION_CONFLICT, $conflict);
    }

    /**
     * A batch is decided in a stable order, kind by kind as the kinds first
     * appear, and within a kind by where each change holds and what it acts on,
     * so its first refusal never depends on the order its changes were read in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABatchIsDecidedInAStableOrder(): void
    {
        $admin = StubIdentity::create(['id' => 'admin-1']);

        $statement = static fn (string $effect, string $key, string $value): array => [
            'effect'     => $effect,
            'actions'    => [PackagePermissions::PERMISSION_REVOKE],
            'resources'  => [OperationResource::TYPE . ':*'],
            'conditions' => ['eq' => [$key => $value]],
        ];

        $admin->attachPolicy(Policy::create(['name' => 'revoker', 'document' => ['statements' => [
            $statement('allow', 'resource.permission', 'posts:a'),
            $statement('deny', 'resource.permission', 'posts:b'),
            $statement('deny', 'resource.application', 'billing'),
        ]]]));

        $actor     = ActingContext::for($admin);
        $operation = Operation::begin($actor);
        $user      = new Reference('user', '1');
        $revoke    = static fn (string $name, ?string $application = null): OperationResource => OperationResource::revoke(
            PackagePermissions::PERMISSION_REVOKE,
            $user,
            Permission::query()->firstOrCreate(['name' => $name]),
            new GrantScope(null, $application),
        );
        $role         = OperationResource::revoke(PackagePermissions::ROLE_REVOKE, $user, Role::create(['name' => 'editor']), GrantScope::platform());
        $firstRefusal = static function (OperationResource ...$changes) use ($actor, $operation): ?DecisionReason {
            $refusal = self::refusalOf(static fn () => $actor->authorizeIn($operation, ...$changes));

            return $refusal instanceof AuthorizationException ? $refusal->getReason() : null;
        };

        foreach ([[$revoke('posts:b', 'admin'), $revoke('posts:c', 'admin')], [$revoke('posts:c', 'admin'), $revoke('posts:c', 'billing')]] as [$one, $other]) {
            self::assertNotSame($firstRefusal($one), $firstRefusal($other));
            self::assertSame($firstRefusal($one, $other), $firstRefusal($other, $one));
        }

        self::assertSame(DecisionReason::NO_MATCH, $firstRefusal($role, $revoke('posts:b', 'admin')));
        self::assertSame(DecisionReason::NO_MATCH, $firstRefusal($role, $revoke('posts:b', 'admin'), $role));
        self::assertSame(DecisionReason::EXPLICIT_DENY, $firstRefusal($revoke('posts:b', 'admin'), $role));
    }

    /**
     * Changes of one kind in different tenants are decided tenant by tenant,
     * and changes to definitions, which name no grant, are ordered as grants
     * are, so the first refusal of either never depends on the order the
     * changes were read in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABatchIsDecidedTenantByTenant(): void
    {
        $admin = StubIdentity::create(['id' => 'admin-1']);

        $admin->attachPolicy(Policy::create(['name' => 'denier', 'document' => ['statements' => [[
            'effect'    => 'deny',
            'actions'   => [PackagePermissions::PERMISSION_REVOKE, PackagePermissions::ROLE_UPDATE],
            'resources' => [OperationResource::TYPE . ':*'],
        ]]]]));

        [$first, $second] = \array_map(self::createTenant(...), ['a', 'b']);

        $this->actAsTenant($first);

        $actor      = ActingContext::for($admin);
        $operation  = Operation::begin($actor);
        $permission = Permission::create(['name' => 'posts:edit']);
        $revoke     = static fn (StubTenant $tenant): OperationResource => OperationResource::revoke(
            PackagePermissions::PERMISSION_REVOKE,
            new Reference('user', '1'),
            $permission,
            new GrantScope(Reference::of($tenant)),
        );
        $update = static fn (string $name): OperationResource => OperationResource::definition(
            PackagePermissions::ROLE_UPDATE,
            Role::create(['name' => $name]),
            ['description' => 'x'],
        );
        $reason = static fn (OperationResource ...$changes): ?DecisionReason => self::reasonOf(static fn () => $actor->authorizeIn($operation, ...$changes));

        self::assertSame(DecisionReason::EXPLICIT_DENY, $reason($revoke($first)));
        self::assertSame(DecisionReason::TENANT_SCOPE, $reason($revoke($second)));
        self::assertSame(DecisionReason::EXPLICIT_DENY, $reason($revoke($second), $revoke($first)));
        self::assertSame(DecisionReason::EXPLICIT_DENY, $reason($update('editor'), $update('author')));
    }

    /**
     * The changes of an operation are decided as `authorizeIn()` decides them,
     * and, when it makes none, the changes it was asked for that change
     * nothing, so an actor without the action is refused either way.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOperationThatChangesNothingDecidesWhatItWasAskedFor(): void
    {
        Event::fake([DecisionEvaluated::class]);

        $admin = StubIdentity::create(['id' => 'admin-1']);

        $admin->givePermission(Permission::create(['name' => PackagePermissions::ROLE_REVOKE]));

        $actor     = ActingContext::for($admin);
        $operation = Operation::begin($actor);
        $role      = Role::create(['name' => 'editor']);
        $revoke    = OperationResource::revoke(PackagePermissions::ROLE_REVOKE, new Reference('user', '1'), $role, GrantScope::platform());
        $kept      = OperationResource::unchanged(PackagePermissions::ROLE_REVOKE, new Reference('user', '1'), null, GrantScope::platform());
        $removal   = OperationResource::unchanged(PackagePermissions::BOUNDARY_REMOVE, new Reference('user', '1'), null, GrantScope::platform());

        $actor->authorizeChanges($operation, [$revoke], $removal);
        $actor->authorizeChanges($operation, [], $kept, $kept);

        Event::assertDispatchedTimes(DecisionEvaluated::class, 3);
        Event::assertNotDispatched(DecisionEvaluated::class, static fn (DecisionEvaluated $event): bool => $event->action !== PackagePermissions::ROLE_REVOKE);

        $refusal = self::refusalOf(static fn () => $actor->authorizeChanges($operation, [], $removal));

        self::assertSame(DecisionReason::NO_MATCH, $refusal instanceof AuthorizationException ? $refusal->getReason() : null);
    }

    /**
     * A refusal is the decision's `AuthorizationException`, its reason the
     * decision's, its message the translated `denied` line, and no reason a
     * refusal names reads as `no_match`.
     *
     * @return void
     */
    public function testARefusalCarriesTheDecision(): void
    {
        $this->app?->make('translator')->addLines(['authorization.denied' => 'Refusé.'], 'fr', 'authorization'); // @phpstan-ignore method.notFound
        $this->app?->setLocale('fr');

        $decision = Decision::deny(DecisionReason::ADMINISTRATION_SCOPE, DecisionStage::ADMINISTRATION);
        $refusal  = ActingContext::refusal($decision);

        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, $refusal->getReason());
        self::assertSame($decision, $refusal->getDecision());
        self::assertSame('Refusé.', $refusal->getMessage());
        self::assertSame(DecisionReason::NO_MATCH, ActingContext::refusal(Decision::allow(DecisionStage::ALLOW))->getReason());
    }

    /**
     * An acting subject naming a tenant is decided in the scope in place, the
     * reach a service puts in place included, never in the tenant it names, so
     * a delegated call decides the actor's rights where it changes things.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testAnActorNamingATenantIsDecidedInTheScopeInPlace(): void
    {
        $first  = self::createTenant('acting-a');
        $second = self::createTenant('acting-b');
        $admin  = StubIdentity::create(['id' => 'admin-1']);

        $admin->givePermission(Permission::create(['name' => 'posts:read']), null, $second);

        $this->resolving(new Subject(StubIdentity::create(['id' => 'user-1']), null, $first));

        $actor  = ActingContext::for(new Subject($admin, $admin, $first));
        $decide = static fn (): bool => $actor->decide('posts:read')->isAllowed();

        self::assertFalse($decide());
        self::assertTrue(TenantScope::within($second, null, $decide));
    }

    /**
     * Bind a subject resolver answering with the subject, for the next facade
     * call.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @return void
     */
    private function resolving(?Subject $subject): void
    {
        $this->app?->instance(SubjectResolver::class, new FixedSubjectResolver($subject));
        $this->forgetTheManager();
    }

    /**
     * Bind a session policy source answering every check with the scopes, for
     * the next facade call.
     *
     * @param  list<string>  $scopes
     * @return void
     */
    private function withCredential(array $scopes): void
    {
        $this->app?->instance(SessionPolicySource::class, new StubSessionPolicySource($scopes));
        $this->app?->make(ConfigRepository::class)->set('authorization.session.scopes', []); // @phpstan-ignore method.nonObject
        $this->app?->forgetInstance(SessionScopes::class);
        $this->forgetTheManager();
    }

    /**
     * Forget the resolved authorization manager, so the next call builds one
     * from the bindings in place.
     *
     * @return void
     */
    private function forgetTheManager(): void
    {
        foreach (['authorization', AuthorizationManager::class] as $abstract) {
            $this->app?->forgetInstance($abstract);
        }

        Authorization::clearResolvedInstance('authorization');
    }

    /**
     * Return the reason the call is refused with.
     *
     * @param  \Closure(): mixed  $call
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function reasonOf(\Closure $call): ?DecisionReason
    {
        $refusal = self::refusalOf($call);

        return $refusal instanceof AuthorizationException ? $refusal->getReason() : null;
    }

    /**
     * Return a saved identity whose key is empty.
     *
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private static function keyless(): StubIdentity
    {
        $identity = new StubIdentity(['id' => '']);

        $identity->exists = true;

        return $identity;
    }
}
