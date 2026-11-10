<?php

declare(strict_types = 1);

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Concerns\BuildsScopedManagers;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
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
use Tests\Concerns\ScopesQueries;
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
    use ScopesQueries;

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
     * A `Subject` whose tenant names no record is refused by `for()`, before
     * anything is decided, and `forActor()` is refused on a preview, as `for()`
     * is.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testAnUnreadableTenantAndAForActorOnAPreviewAreRefused(): void
    {
        $user = StubIdentity::create(['id' => 'scoped-7']);

        try {
            self::manager()->for(new Subject($user, $user, new \stdClass));

            self::fail('The subject is refused.');
        } catch (InvalidTenantException) {
            self::assertNull(Authorization::lastDecision());
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
