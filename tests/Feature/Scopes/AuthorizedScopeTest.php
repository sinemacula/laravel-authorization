<?php

declare(strict_types = 1);

namespace Tests\Feature\Scopes;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Query\Reentrancy;
use SineMacula\Laravel\Authorization\Scopes\AuthorizedScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Concerns\RefusesThePackage;
use Tests\Concerns\ScopesQueries;
use Tests\Feature\Stubs\FixedSubjectResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Fixtures\QueryScoping\GuardedPost;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\TestCase;

/**
 * Feature tests for the model-level scope that keeps every query of a model to
 * the rows the current subject may take an action on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AuthorizedScope::class)]
final class AuthorizedScopeTest extends TestCase
{
    use RefusesThePackage, ScopesQueries;

    /**
     * Every query of the model keeps the rows `check()` allows the current
     * subject, decided each time it runs, so a grant made, or revoked, after
     * the query was built is seen when it runs; a count and a page agree.
     *
     * @return void
     */
    public function testEveryQueryIsDecidedWhenItRuns(): void
    {
        $user = StubIdentity::create(['id' => 'u1']);

        $this->resolveRequest($user);

        foreach ([1, 2, 3] as $id) {
            GuardedPost::query()->create(['id' => $id, 'title' => 'post']);
        }

        $query = GuardedPost::query()->where('title', 'post')->orWhere('title', 'other');

        self::assertSame([], $query->pluck('id')->all());

        $user->givePermission($permission = Permission::create(['name' => GuardedPost::ACTION]));
        $user->attachPolicy(self::storedPolicy('not-two', [['effect' => 'deny', 'actions' => [GuardedPost::ACTION], 'resources' => [(new GuardedPost)->getMorphClass() . ':2']]]));

        self::assertSame([1, 3], $query->orderBy('id')->pluck('id')->all());
        self::assertSame(2, $query->count());
        self::assertSame([1], GuardedPost::query()->orderBy('id')->paginate(1)->pluck('id')->all());

        $user->revokePermission($permission);

        self::assertSame(0, $query->count());
    }

    /**
     * A refusal throws from the call that runs the query, never when the query
     * is built.
     *
     * @return void
     */
    public function testARefusalThrowsFromTheCallThatRuns(): void
    {
        $user = StubIdentity::create(['id' => 'u1']);

        $this->resolveRequest($user);
        $user->attachPolicy(self::storedPolicy('unknown', [['effect' => 'deny', 'actions' => [GuardedPost::ACTION], 'resources' => [(new GuardedPost)->getMorphClass() . ':?']]]));

        $query = GuardedPost::query()->where('title', 'post');

        self::assertSame([RefusalReason::RESOURCE_PATTERN], self::refusalOf(static fn (): mixed => $query->get())->reasons());
    }

    /**
     * Removing the model-level scope by its class is the application's choice,
     * so the query runs unscoped with no refusal; removing a
     * `whereAuthorized()` scope refuses.
     *
     * @return void
     */
    public function testRemovingTheModelLevelScopeIsAnOptOut(): void
    {
        $user = StubIdentity::create(['id' => 'u1']);

        $manager = $this->resolveRequest($user);

        foreach ([1, 2] as $id) {
            GuardedPost::query()->create(['id' => $id, 'title' => 'post']);
        }

        self::assertSame(0, GuardedPost::query()->count());
        self::assertSame(2, GuardedPost::query()->withoutGlobalScope(AuthorizedScope::class)->count());

        $scoped = ScopedPost::query()->whereAuthorized('posts:view', [], $manager)->withoutGlobalScopes(); // @phpstan-ignore method.notFound

        self::assertSame([RefusalReason::SCOPE_REMOVED], self::refusalOf(static fn (): mixed => $scoped->count())->reasons());
    }

    /**
     * The scope applied while a scope is being decided, or on the subject's own
     * model, refuses as reentrant.
     *
     * @return void
     */
    public function testTheScopeRefusesReentry(): void
    {
        $this->resolveRequest(StubIdentity::create(['id' => 'u1']));

        $refused = self::refusalOf(static fn (): mixed => Reentrancy::guarded(static fn (): mixed => GuardedPost::query()->get()));

        self::assertSame([RefusalReason::REENTRANT], $refused->reasons());
        self::assertSame(GuardedPost::class, $refused->refusals[0]->key);

        $post = GuardedPost::query()->create(['id' => 9, 'title' => 'post']);

        $this->resolveRequest($post);

        self::assertSame([RefusalReason::REENTRANT], self::refusalOf(static fn (): mixed => GuardedPost::query()->get())->reasons());
        self::assertFalse(Reentrancy::isDeciding());
    }

    /**
     * The scope on the model of the subject's identity alone, or of the subject
     * alone, refuses as reentrant, whichever of the two the model is.
     *
     * @return void
     */
    public function testTheScopeRefusesOnTheModelOfEitherHalfOfTheSubject(): void
    {
        $user = StubIdentity::create(['id' => 'u1']);
        $post = GuardedPost::query()->withoutGlobalScope(AuthorizedScope::class)->create(['id' => 9, 'title' => 'post']);

        foreach ([new Subject($user, $post), new Subject($post, $user)] as $subject) {
            $this->app?->instance(SubjectResolver::class, new FixedSubjectResolver($subject));

            foreach (['authorization', AuthorizationManager::class, ResolvedTenant::class] as $abstract) {
                $this->app?->forgetInstance($abstract);
            }

            Authorization::clearResolvedInstance('authorization');

            self::assertSame([RefusalReason::REENTRANT], self::refusalOf(static fn (): mixed => GuardedPost::query()->get())->reasons());
        }
    }

    /**
     * Without the authorization manager bound, the scope cannot choose a
     * subject.
     *
     * @return void
     */
    public function testTheManagerMustBeBound(): void
    {
        $query     = GuardedPost::query();
        $container = Container::getInstance();

        Container::setInstance(new Container);

        try {
            $this->expectException(\LogicException::class);
            $this->expectExceptionMessage('An AuthorizedScope needs the authorization manager, which is not bound.');

            (new AuthorizedScope(GuardedPost::ACTION))->apply($query, new GuardedPost);
        } finally {
            Container::setInstance($container);
        }
    }

    /**
     * Once the package refuses, applying the scope refuses by its own guard,
     * before the manager is asked.
     *
     * @return void
     */
    public function testApplyingTheScopeRefusesOnceThePackageRefuses(): void
    {
        $this->refuseThePackage();

        $this->assertEachRefused([
            'apply' => static fn () => (new AuthorizedScope('posts:read'))->apply(StubIdentity::query(), new StubIdentity),
        ]);
    }
}
