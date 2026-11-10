<?php

declare(strict_types = 1);

namespace Tests\Feature\Preview;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException;
use SineMacula\Laravel\Authorization\Preview\PreviewContext;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\PreviewsSubjects;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\FixedSubjectResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubRequirementChecker;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for `PreviewContext`, who previews whom and where (AUTHZ-11.4):
 * the caller stays who is asking, the target is evaluated with no session in
 * the preview's scope, and every use is admitted again, before anything about
 * the target is decided.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PreviewContext::class)]
final class PreviewContextTest extends TestCase
{
    use PreviewsSubjects, ReadsDispatchedEvents;

    /**
     * A preview decides about the target while the manager it was built from,
     * and the request, still decide about the caller; its two parties are
     * fixed, and two previews are independent of each other.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testThePreviewDecidesAboutTheTargetWhileTheCallerStaysWhoAsks(): void
    {
        $caller  = self::previewer();
        $target  = self::target();
        $other   = self::target('other', ['posts:edit']);
        $manager = $this->signIn($caller);

        $preview = $manager->previewFor($target);
        $second  = $manager->previewFor($other);

        self::assertNotSame($manager, $preview);
        self::assertSame($target, $preview->currentSubject()?->subject);
        self::assertSame($target, $preview->currentSubject()->identity);
        self::assertSame('web', $preview->currentSubject()->guard);
        self::assertNull($preview->currentSubject()->session);
        self::assertSame($caller, $manager->currentSubject()?->subject);
        self::assertSame('session-1', $manager->currentSubject()->session);
        self::assertTrue($preview->can('posts:read'));
        self::assertFalse($preview->can('posts:edit'));
        self::assertTrue($second->can('posts:edit'));
        self::assertFalse($second->can('posts:read'));
        self::assertFalse($manager->can('posts:read'));
    }

    /**
     * A resolved `Subject` previewed keeps its principal and identity, but not
     * its session or anything that would let it meet a requirement.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testAResolvedSubjectKeepsItsPrincipalAndIdentityButNotItsSession(): void
    {
        $caller   = self::previewer();
        $machine  = self::target('principal');
        $identity = StubIdentity::query()->create(['id' => 'identity']);

        $tenant = StubTenant::query()->create(['id' => 'theirs', 'name' => 'theirs']);

        $preview = $this->signIn($caller)->previewFor(new Subject($machine, $identity, $tenant, 'admin', 'api', 'their-session'));

        self::assertSame($machine, $preview->currentSubject()?->subject);
        self::assertSame($identity, $preview->currentSubject()->identity);
        self::assertSame($tenant, $preview->currentSubject()->tenant);
        self::assertSame('admin', $preview->currentSubject()->application);
        self::assertSame('api', $preview->currentSubject()->guard);
        self::assertNull($preview->currentSubject()->session);
    }

    /**
     * The caller's own step-up admits a preview whose right needs it, but never
     * meets a requirement made of the target: the target has no session, so the
     * checker is never asked about it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCallersStepUpAdmitsButNeverMeetsTheTargetsRequirement(): void
    {
        $caller  = self::previewer('previewer', false);
        $target  = self::target('target', []);
        $checker = new StubRequirementChecker(RequirementResult::met());

        self::attachStatements($caller, 'stepped-up-preview', [self::requiring(PackagePermissions::SUBJECT_PREVIEW)]);
        self::attachStatements($target, 'stepped-up-export', [self::requiring('reports:export')]);

        $preview  = $this->signIn($caller, 'session-1', null, null, $checker)->previewFor($target);
        $decision = $preview->check('reports:export');

        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $decision->reason);
        self::assertNotSame([], $checker->calls);

        foreach ($checker->calls as [, $subject]) {
            self::assertSame($caller, $subject->subject);
            self::assertSame('session-1', $subject->session);
        }
    }

    /**
     * A caller without the right is refused the preview with
     * `AuthorizationException` before anything about the target is decided: the
     * only decision made, recorded and reported is the caller's own.
     *
     * @return void
     */
    public function testARefusedPreviewIsRefusedBeforeAnythingAboutTheTarget(): void
    {
        $caller = self::previewer('previewer', false);
        $target = self::target();

        Event::fake([DecisionEvaluated::class, AuthorizationFailed::class]);

        $manager = $this->signIn($caller);

        try {
            $manager->previewFor($target);
            self::fail('The preview was not refused.');
        } catch (AuthorizationException $exception) {
            self::assertSame(DecisionReason::NO_MATCH, $exception->getReason());
            self::assertSame('This action is unauthorized.', $exception->getMessage());
        }

        $evaluated = self::dispatchedEvents(DecisionEvaluated::class);
        $failed    = self::dispatchedEvents(AuthorizationFailed::class);

        self::assertCount(1, $evaluated);
        self::assertCount(1, $failed);

        foreach ([$evaluated[0], $failed[0]] as $event) {
            self::assertSame(PackagePermissions::SUBJECT_PREVIEW, $event->action);
            self::assertEquals(Reference::of($caller), $event->subject);
            self::assertNull($event->previewer);
        }

        self::assertNull($manager->lastDecisionProvenance()?->previewer);
        self::assertEquals(Reference::of($caller), $manager->lastDecisionProvenance()?->subject);
        self::assertFalse($manager->lastDecision()?->isAllowed());
    }

    /**
     * Admission is never kept between uses: a right revoked after the preview
     * is built refuses its next use, before the target is decided.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARightRevokedAfterThePreviewIsBuiltIsSeenAtTheNextUse(): void
    {
        $caller  = self::previewer();
        $target  = self::target();
        $preview = $this->signIn($caller)->previewFor($target);

        self::assertTrue($preview->can('posts:read'));

        GrantService::instance()?->revokePermission($caller, self::permission(PackagePermissions::SUBJECT_PREVIEW));

        Event::fake([DecisionEvaluated::class]);

        $this->assertRefused(static fn (): mixed => $preview->check('posts:read'));
        $this->assertRefused(static fn (): mixed => $preview->checkMany([new CheckInput('posts:read')]));
        $this->assertRefused(static fn (): mixed => $preview->permissionsFor(null, AuthorizationScope::current()));

        foreach (self::dispatchedEvents(DecisionEvaluated::class) as $event) {
            self::assertSame(PackagePermissions::SUBJECT_PREVIEW, $event->action);
            self::assertNull($event->previewer);
        }
    }

    /**
     * The target is evaluated in the preview's scope, put in place for its
     * checks, and the request's is restored afterwards, even when a check
     * throws.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testTheScopeIsPutInPlaceAndRestoredEvenWhenAUseThrows(): void
    {
        $caller = self::previewer();
        $target = self::target();
        $tenant = StubTenant::query()->create(['id' => 'scoped', 'name' => 'scoped']);

        $preview = $this->signIn($caller)->previewFor($target, AuthorizationScope::platform('admin'));

        $unreadable = new class implements \Stringable {
            /**
             * Throw, as a resource whose identifier cannot be read does.
             *
             * @return string
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function __toString(): string
            {
                throw new \RuntimeException('The resource cannot be read.');
            }
        };

        try {
            $preview->checkMany([new CheckInput('posts:read', $unreadable)]);
            self::fail('The check did not throw.');
        } catch (\RuntimeException) {
            self::assertNull(TenantScope::currentTenant());
            self::assertNull(TenantScope::currentApplication());
        }

        self::assertTrue($preview->can('posts:read'));
        self::assertSame('admin', $preview->lastDecisionProvenance()?->application);
        self::assertNull(TenantScope::currentApplication());
        self::assertSame(StubTenant::class, $tenant->getMorphClass());
    }

    /**
     * The provenance a preview names for a decision whose own is no longer
     * recorded is made in the preview's scope, naming both parties, whatever
     * scope the request is in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFallbackProvenanceIsMadeInThePreviewsScope(): void
    {
        $caller  = self::previewer();
        $target  = self::target();
        $tenant  = StubTenant::query()->create(['id' => 'scoped', 'name' => 'scoped']);
        $context = PreviewContext::of($this->signIn($caller), $target, AuthorizationScope::tenant($tenant, 'admin'));

        $provenance = $context->provenance();

        self::assertEquals(Reference::of($target), $provenance->subject);
        self::assertEquals(Reference::of($caller), $provenance->previewer);
        self::assertEquals(Reference::of($tenant), $provenance->tenant);
        self::assertSame('admin', $provenance->application);
        self::assertNull(TenantScope::currentApplication());
    }

    /**
     * A use sets the request's resolution memo aside and restores it, so the
     * caller's own check, warm before the use, reads nothing again after it,
     * while the next use is admitted afresh.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAUseLeavesWhatTheCallerResolvedInPlace(): void
    {
        $caller  = self::previewer();
        $target  = self::target();
        $tenant  = StubTenant::query()->create(['id' => 'memo', 'name' => 'memo']);
        $manager = $this->signIn($caller, 'session-1', $tenant);
        $preview = $manager->previewFor($target);

        $caller->givePermission(self::permission('posts:edit'));

        self::assertTrue($manager->can('posts:edit'));
        self::assertTrue($preview->can('posts:read'));
        self::assertSame(0, self::queriesOf(static fn (): bool => $manager->can('posts:edit')));
        self::assertGreaterThan(0, self::queriesOf(static fn (): bool => $preview->can('posts:read')));
    }

    /**
     * The target is decided as a subject of the preview's scope: its tenant is
     * the scope's, as a policy reads it under `subject.tenant`, whatever tenant
     * it was named in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTargetIsASubjectOfThePreviewsScope(): void
    {
        $caller = self::previewer();
        $target = self::target('target', []);
        $tenant = StubTenant::query()->create(['id' => 'scoped', 'name' => 'scoped']);

        self::attachStatements($target, 'in-the-tenant', [['effect' => 'allow', 'actions' => ['reports:view'], 'conditions' => ['eq' => ['subject.tenant.id' => 'scoped']]]]);

        $manager = $this->signIn($caller);

        self::assertTrue($manager->previewFor($target, AuthorizationScope::tenant($tenant))->can('reports:view'));
        self::assertFalse($manager->previewFor($target)->can('reports:view'));
    }

    /**
     * A listing in a scope other than the preview's, or naming a subject, is
     * refused before anything is decided.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testAListingInAnotherScopeOrNamingASubjectIsRefused(): void
    {
        $this->app?->make('config')->set('authorization.permission_enums', [PermissionEnum::class]);

        $caller  = self::previewer();
        $target  = self::target('target', ['posts:create']);
        $tenant  = StubTenant::query()->create(['id' => 'elsewhere', 'name' => 'elsewhere']);
        $preview = $this->signIn($caller)->previewFor($target);

        $other    = StubTenant::query()->create(['id' => 'other', 'name' => 'other']);
        $inTenant = $this->signIn($caller)->previewFor($target, AuthorizationScope::tenant($tenant));

        $refusals = [
            static fn (): mixed => $preview->permissionsFor(null, AuthorizationScope::platform('admin')),
            static fn (): mixed => $preview->permissionsFor(null, AuthorizationScope::tenant($tenant)),
            static fn (): mixed => $inTenant->permissionsFor(null, AuthorizationScope::tenant($other)),
            static fn (): mixed => $preview->permissionsFor($target, AuthorizationScope::current()),
            static fn (): mixed => $preview->permissionsFor(new Subject($target, $target), AuthorizationScope::current()),
        ];

        foreach ($refusals as $refusal) {
            try {
                $refusal();
                self::fail('The listing was not refused.');
            } catch (InvalidPreviewException $exception) {
                self::assertNotSame('', $exception->getMessage());
            }
        }

        self::assertSame(['posts:create'], $preview->permissionsFor(null, AuthorizationScope::current()->withResource('post:1')));
    }

    /**
     * A previewer that names no record, a guest included, is refused as
     * `subject_unresolved`, and a target that names no record with
     * `InvalidPreviewException`, before anything is decided.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testUnidentifiedPartiesAreRefused(): void
    {
        $target = self::target();

        $this->app?->instance(SubjectResolver::class, new FixedSubjectResolver(null));
        $this->app?->forgetInstance('authorization');

        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager $guest */
        $guest = $this->app?->make('authorization');

        try {
            $guest->previewFor($target);
            self::fail('A guest previewed.');
        } catch (AuthorizationException $exception) {
            self::assertSame(DecisionReason::SUBJECT_UNRESOLVED, $exception->getReason());
        }

        $unsaved = new StubIdentity;

        try {
            $this->signIn($unsaved)->previewFor($target);
            self::fail('A previewer naming no record previewed.');
        } catch (AuthorizationException $exception) {
            self::assertSame(DecisionReason::SUBJECT_UNRESOLVED, $exception->getReason());
        }

        $this->expectException(InvalidPreviewException::class);

        $this->signIn(self::previewer())->previewFor(new \stdClass);
    }

    /**
     * Return how many queries the callback runs.
     *
     * @param  \Closure(): mixed  $callback
     * @return int
     */
    private static function queriesOf(\Closure $callback): int
    {
        DB::flushQueryLog();
        DB::enableQueryLog();

        try {
            $callback();
        } finally {
            DB::disableQueryLog();
        }

        return \count(DB::getQueryLog());
    }

    /**
     * Assert the callback is refused as an unadmitted preview.
     *
     * @param  \Closure(): mixed  $callback
     * @return void
     */
    private function assertRefused(\Closure $callback): void
    {
        try {
            $callback();
            self::fail('The preview was not refused.');
        } catch (AuthorizationException $exception) {
            self::assertSame(DecisionReason::NO_MATCH, $exception->getReason());
            self::assertFalse($exception->getDecision()?->isAllowed());
        }
    }
}
