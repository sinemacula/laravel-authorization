<?php

declare(strict_types = 1);

namespace Tests\Feature\Preview;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReport;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException;
use SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\PermissionCatalogue;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\CatchesRefusals;
use Tests\Concerns\PreviewsSubjects;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubRequirementChecker;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\TestCase;

/**
 * Feature tests for the authorization manager's forms on a preview
 * (AUTHZ-11.4): each decides about the target exactly as the same form through
 * `for()` decides under the same scope and state, through the one decision path
 * (D22), and differs only in its admission and in what it records and reports.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AuthorizationManager::class)]
final class AuthorizationManagerTest extends TestCase
{
    use CatchesRefusals, PreviewsSubjects, ReadsDispatchedEvents;

    /** @var string A value a check is given, which no event may carry. */
    private const string SECRET = 'not-for-the-audit-trail';

    /**
     * Every form decides on a preview what it decides through `for()`, with the
     * grants, the denies and the conditions of the target weighed alike: single
     * checks, their adapters, bulk checks, listings and explanations.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryFormDecidesAsForDecidesUnderTheSameScope(): void
    {
        [$manager, $target] = $this->previewed();

        $preview = $manager->previewFor($target);
        $named   = $manager->for($target);
        $checks  = ['create' => new CheckInput('posts:create'), 'delete' => new CheckInput('posts:delete'), 'read' => new CheckInput('posts:read', 'post:1')];
        $scope   = AuthorizationScope::current();

        foreach (['posts:create', 'posts:delete', 'posts:read'] as $action) {
            self::assertSame($named->check($action)->explain()->toText(), $preview->check($action)->explain()->toText(), $action);
            $unasked = static fn (AuthorizationManager $manager): array => \array_diff_key($manager->explain($action)->toArray(), ['request' => true]);

            self::assertSame($unasked($named), $unasked($preview), $action);
            self::assertSame($named->can($action), $preview->can($action), $action);
            self::assertSame($named->cannot($action), $preview->cannot($action), $action);
        }

        self::assertSame($named->any(['posts:delete', 'posts:create']), $preview->any(['posts:delete', 'posts:create']));
        self::assertSame($named->all(['posts:delete', 'posts:create']), $preview->all(['posts:delete', 'posts:create']));
        self::assertSame(self::explained($named->checkMany($checks)), self::explained($preview->checkMany($checks)));
        self::assertSame($named->canEach('posts:create', ['a' => 'post:1', 'b' => 'post:2']), $preview->canEach('posts:create', ['a' => 'post:1', 'b' => 'post:2']));
        self::assertSame($named->filterAuthorized('posts:delete', ['post:1']), $preview->filterAuthorized('posts:delete', ['post:1']));
        self::assertSame(['posts:create'], $preview->permissionsFor(null, $scope));
        self::assertSame($named->permissionsFor(null, $scope), $preview->permissionsFor(null, $scope));
        self::assertSame(DecisionReason::EXPLICIT_DENY, $preview->check('posts:delete')->reason);
    }

    /**
     * Every decision about the target is reported as soon as it is made, in
     * order, as a preview, with the target as its subject and the caller as its
     * previewer, the last of a batch stored with both; the admission, an allow
     * about the caller alone, is not reported under the shipped settings.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPreviewDecisionsAreReportedInOrderWithBothParties(): void
    {
        Event::fake([DecisionEvaluated::class]);

        [$manager, $target, $caller] = $this->previewed();

        $preview = $manager->previewFor($target);
        $built   = \count(self::dispatchedEvents(DecisionEvaluated::class));

        $preview->checkMany([new CheckInput('posts:create'), new CheckInput('posts:delete')]);

        $events  = \array_slice(self::dispatchedEvents(DecisionEvaluated::class), $built);
        $actions = \array_map(static fn (DecisionEvaluated $event): string => $event->action, $events);

        self::assertSame(0, $built);
        self::assertSame(['posts:create', 'posts:delete'], $actions);

        foreach ($events as $event) {
            self::assertEquals(Reference::of($target), $event->subject);
            self::assertEquals(Reference::of($target), $event->identity);
            self::assertEquals(Reference::of($caller), $event->previewer);
            self::assertSame(DecisionReport::PREVIEW, $event->reportedBecause());
        }

        self::assertSame(DecisionReason::EXPLICIT_DENY, $manager->lastDecision()?->reason);
        self::assertEquals(Reference::of($caller), $manager->lastDecisionProvenance()?->previewer);
        self::assertEquals(Reference::of($target), $manager->lastDecisionProvenance()?->subject);
    }

    /**
     * A preview listing reports each action it evaluates, naming both parties,
     * as a preview, but stores none of them: the last decision is still its
     * admission, which the shipped settings do not report.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPreviewListingReportsEachActionAndStoresNone(): void
    {
        Event::fake([DecisionEvaluated::class]);

        [$manager, $target, $caller] = $this->previewed();

        $preview = $manager->previewFor($target);
        $built   = \count(self::dispatchedEvents(DecisionEvaluated::class));
        $listed  = $preview->permissionsFor(null, AuthorizationScope::current());
        $events  = \array_slice(self::dispatchedEvents(DecisionEvaluated::class), $built);
        $actions = \array_values(\array_unique(\array_map(static fn (PermissionDefinition $definition): string => $definition->name, $this->catalogue()->definitions())));

        self::assertSame(['posts:create'], $listed);
        self::assertSame(0, $built);
        self::assertSame($actions, \array_map(static fn (DecisionEvaluated $event): string => $event->action, $events));

        foreach ($events as $event) {
            self::assertEquals(Reference::of($caller), $event->previewer);
            self::assertEquals(Reference::of($target), $event->subject);
            self::assertSame(DecisionReport::PREVIEW, $event->reportedBecause());
        }

        self::assertTrue($manager->lastDecision()?->isAllowed());
        self::assertNull($manager->lastDecisionProvenance()?->previewer);
        self::assertEquals(Reference::of($caller), $manager->lastDecisionProvenance()?->subject);
    }

    /**
     * `authorize()` on a preview reports the target's refusal with both
     * parties, and no event carries a value the checks were given or the
     * caller's session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusalNamesBothPartiesAndNoEventCarriesAValue(): void
    {
        Event::fake([DecisionEvaluated::class, AuthorizationFailed::class]);

        [$manager, $target, $caller] = $this->previewed();

        $preview = $manager->previewFor($target);

        try {
            $preview->authorize('posts:delete', null, ['reason' => self::SECRET]);
            self::fail('The target was allowed.');
        } catch (AuthorizationException $exception) {
            self::assertSame(DecisionReason::EXPLICIT_DENY, $exception->getReason());
        }

        $failed = self::dispatchedEvents(AuthorizationFailed::class);

        self::assertCount(1, $failed);
        self::assertEquals(Reference::of($caller), $failed[0]->previewer);
        self::assertEquals(Reference::of($target), $failed[0]->subject);

        $payload = \serialize([...self::dispatchedEvents(DecisionEvaluated::class), ...$failed]);

        self::assertStringNotContainsString(self::SECRET, $payload);
        self::assertStringNotContainsString('session-1', $payload);
    }

    /**
     * A refusal on a preview is reported with both parties even when a listener
     * has meanwhile recorded another decision, in the preview's own scope.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusalNamesBothPartiesWhenAnotherDecisionWasRecordedMeanwhile(): void
    {
        Event::fake([AuthorizationFailed::class]);

        [$manager, $target, $caller] = $this->previewed();

        $preview = $manager->previewFor($target, AuthorizationScope::platform('admin'));

        Event::listen(DecisionEvaluated::class, static function (DecisionEvaluated $event) use ($manager): void {
            if ($event->previewer === null) {
                return;
            }

            $manager->check('posts:read');
        });

        try {
            $preview->authorize('posts:delete');
            self::fail('The target was allowed.');
        } catch (AuthorizationException $exception) {
            self::assertSame(DecisionReason::EXPLICIT_DENY, $exception->getReason());
        }

        $failed = self::dispatchedEvents(AuthorizationFailed::class);

        self::assertCount(1, $failed);
        self::assertEquals(Reference::of($caller), $failed[0]->previewer);
        self::assertEquals(Reference::of($target), $failed[0]->subject);
        self::assertSame('admin', $failed[0]->application);
        self::assertNull($failed[0]->tenant);
    }

    /**
     * A listener of a preview's `AuthorizationFailed` runs as part of the
     * preview's evaluation, so a management service it calls is refused as
     * `administration.previewing` and nothing is written; the refusal itself is
     * still thrown.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPreviewsRefusalListenersMayChangeNothing(): void
    {
        [$manager, $target] = $this->previewed();

        $grantee = StubIdentity::query()->create(['id' => 'grantee']);
        $preview = $manager->previewFor($target);
        /** @var \ArrayObject<int, mixed> $calls */
        $calls = new \ArrayObject;

        Event::listen(AuthorizationFailed::class, static function (AuthorizationFailed $event) use ($grantee, $calls): void {
            if ($event->previewer === null) {
                return;
            }

            $calls[] = self::refusalOf(static fn (): mixed => GrantService::instance()?->grantPermission($grantee, self::permission('posts:edit')));
        });

        $refusal = self::refusalOf(static function () use ($preview): void {
            $preview->authorize('posts:delete');
        });

        self::assertInstanceOf(AuthorizationException::class, $refusal);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $refusal->getReason());
        self::assertCount(1, $calls);
        self::assertInstanceOf(AuthorizationException::class, $calls[0]);
        self::assertSame(DecisionReason::ADMINISTRATION_PREVIEWING, $calls[0]->getReason());
        self::assertFalse($grantee->fresh()?->hasPermission('posts:edit'));
    }

    /**
     * A preview's denial for a requirement made of the target is refused with a
     * plain `AuthorizationException`, carrying the decision, never with the
     * step-up exception: the target has no session, so no step-up by the caller
     * could meet it. Its `AuthorizationFailed` still names both parties.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPreviewsUnmetRequirementAsksForNoStepUp(): void
    {
        Event::fake([AuthorizationFailed::class]);

        $caller = self::previewer();
        $target = self::target('target', []);

        self::attachStatements($target, 'stepped-up-export', [self::requiring('reports:export')]);

        $preview = $this->signIn($caller, 'session-1', null, null, new StubRequirementChecker(RequirementResult::met()))->previewFor($target);
        $refusal = self::refusalOf(static function () use ($preview): void {
            $preview->authorize('reports:export');
        });

        self::assertSame(AuthorizationException::class, $refusal::class);
        self::assertInstanceOf(AuthorizationException::class, $refusal);
        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $refusal->getReason());
        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $refusal->getDecision()?->reason);

        $failed = self::dispatchedEvents(AuthorizationFailed::class);

        self::assertCount(1, $failed);
        self::assertEquals(Reference::of($caller), $failed[0]->previewer);
        self::assertEquals(Reference::of($target), $failed[0]->subject);
    }

    /**
     * A listing naming any subject on a preview, a model or a resolved
     * `Subject`, is refused as a change of the preview's target by
     * `permissionsFor()` itself.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAListingNamingASubjectIsRefusedAsARetarget(): void
    {
        [$manager, $target] = $this->previewed();

        $preview = $manager->previewFor($target);

        foreach ([$target, new Subject($target, $target)] as $named) {
            $refusal = self::refusalOf(static fn (): mixed => $preview->permissionsFor($named, AuthorizationScope::current()));

            self::assertInstanceOf(InvalidPreviewException::class, $refusal);
            self::assertStringContainsString('permissionsFor()', $refusal->getMessage());
        }
    }

    /**
     * `whereAuthorized()` given a preview keeps the rows the target may take
     * the action on, as through `for()`, admitting the preview again at each
     * execution, so a right revoked between building the query and running it
     * refuses the run; and it refuses every write with the query.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPreviewQueryKeepsTheTargetsRowsAndIsReadOnly(): void
    {
        [$manager, $target, $caller] = $this->previewed(['posts:view']);

        ScopedPost::query()->create(['title' => 'one']);
        ScopedPost::query()->create(['title' => 'two']);

        $preview = $manager->previewFor($target);
        $query   = self::scoped($preview);

        self::assertSame(self::scoped($manager->for($target))->count(), $query->count());
        self::assertCount(2, $query->get());

        $writes = [
            static fn (): mixed => self::scoped($preview)->update(['title' => 'changed']),
            static fn (): mixed => self::scoped($preview)->delete(),
            static fn (): mixed => DB::table('scoped_posts')->insertUsing(['title'], self::scoped($preview)->select('title')),
        ];

        foreach ($writes as $write) {
            try {
                $write();
                self::fail('A preview query wrote.');
            } catch (QueryScopeRefusedException $exception) {
                self::assertSame(RefusalReason::PREVIEW_WRITE, $exception->refusals[0]->reason);
            }
        }

        self::assertSame(['one', 'two'], ScopedPost::query()->orderBy('title')->pluck('title')->all());

        GrantService::instance()?->revokePermission($caller, self::permission(PackagePermissions::SUBJECT_PREVIEW));

        $this->expectException(AuthorizationException::class);

        $query->get();
    }

    /**
     * Return the request's manager for a caller allowed to preview, and a
     * target holding the permissions given, `posts:create` and `posts:delete`
     * by default, with a policy denying `posts:delete`, the catalogue declaring
     * the posts' actions; and the caller.
     *
     * @param  list<string>  $permissions
     * @return array{\SineMacula\Laravel\Authorization\AuthorizationManager, \Tests\Feature\Stubs\StubIdentity, \Tests\Feature\Stubs\StubIdentity}
     *
     * @throws \Throwable
     */
    private function previewed(array $permissions = ['posts:create', 'posts:delete', 'posts:read']): array
    {
        $this->app?->make('config')->set('authorization.permission_enums', [PermissionEnum::class]);

        $caller = self::previewer();
        $target = self::target('target', $permissions);

        self::attachStatements($target, 'no-deleting', [['effect' => 'deny', 'actions' => ['posts:delete']]]);

        return [$this->signIn($caller), $target, $caller];
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

    /**
     * Return the explanation of each decision, keyed as the decisions are.
     *
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Evaluation\Decision>  $decisions
     * @return array<array-key, string>
     */
    private static function explained(array $decisions): array
    {
        return \array_map(static fn (Decision $decision): string => $decision->explain()->toText(), $decisions);
    }

    /**
     * Return the posts query scoped to `posts:view` through the manager.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $manager
     * @return \Illuminate\Database\Eloquent\Builder<\Tests\Fixtures\QueryScoping\ScopedPost>
     */
    private static function scoped(AuthorizationManager $manager): Builder
    {
        /** @var \Illuminate\Database\Eloquent\Builder<\Tests\Fixtures\QueryScoping\ScopedPost> */
        return ScopedPost::query()->whereAuthorized('posts:view', [], $manager); // @phpstan-ignore method.notFound
    }
}
