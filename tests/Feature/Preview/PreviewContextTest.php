<?php

declare(strict_types = 1);

namespace Tests\Feature\Preview;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
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
use SineMacula\Laravel\Authorization\Support\CredentialScopes;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\PreviewsSubjects;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Feature\Stubs\AuthenticatableIdentity;
use Tests\Feature\Stubs\CredentialScopesSource;
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
     * A resolved `Subject` previewed keeps its credential's scopes and its
     * platform marker, losing only its session, so its credential still caps
     * what the preview allows; the source is not asked about scopes it says.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testAResolvedSubjectKeepsItsScopesAndItsMarker(): void
    {
        // The previewer's own session carries no cap; the target's credential
        // is said on its subject.
        $source = new CredentialScopesSource(['session:session-1' => null]);

        $this->app?->instance(SessionPolicySource::class, $source);

        $caller  = self::previewer();
        $target  = self::target('target', ['posts:read', 'posts:edit']);
        $preview = $this->signIn($caller)->previewFor(new Subject($target, $target, null, null, 'web', 'their-session', CredentialScopes::of(['posts:read']), true));

        self::assertSame([], self::askedAbout($source, $target));
        self::assertSame(['posts:read'], $preview->currentSubject()?->scopes?->scopes());
        self::assertTrue($preview->currentSubject()->platform);
        self::assertNull($preview->currentSubject()->session);
        self::assertTrue($preview->can('posts:read'));
        self::assertSame(DecisionReason::SESSION_POLICY, $preview->check('posts:edit')->reason);
    }

    /**
     * A target naming a session but saying nothing of its scopes is capped by
     * that session's credential, which the source is asked about before the
     * session goes: the scopes it carries cap the preview, a session the source
     * cannot resolve allows nothing, and one carrying no cap leaves the preview
     * uncapped.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testATargetInASessionIsPreviewedWithItsCredentialsScopes(): void
    {
        $source = new CredentialScopesSource(['session:session-1' => null, 'session:capped' => ['posts:read'], 'session:free' => null]);

        $this->app?->instance(SessionPolicySource::class, $source);

        $manager = $this->signIn(self::previewer());
        $target  = self::target('target', ['posts:read', 'posts:edit']);
        $capped  = $manager->previewFor(new Subject($target, $target, null, null, 'web', 'capped'));

        $asked = self::askedAbout($source, $target);

        self::assertCount(1, $asked);
        self::assertSame('capped', $asked[0]->session);
        self::assertSame(['posts:read'], $capped->currentSubject()?->scopes?->scopes());
        self::assertNull($capped->currentSubject()->session);
        self::assertTrue($capped->can('posts:read'));
        self::assertSame(DecisionReason::SESSION_POLICY, $capped->check('posts:edit')->reason);

        $unknown = $manager->previewFor(new Subject($target, $target, null, null, 'web', 'unknown'));

        self::assertSame([], $unknown->currentSubject()?->scopes?->scopes());
        self::assertSame(DecisionReason::SESSION_POLICY, $unknown->check('posts:read')->reason);

        $free = $manager->previewFor(new Subject($target, $target, null, null, 'web', 'free'));

        self::assertFalse($free->currentSubject()?->scopes?->isCapped() ?? true);
        self::assertTrue($free->can('posts:read'));
        self::assertTrue($free->can('posts:edit'));
    }

    /**
     * A target with no session whose guard's caller is its own record names
     * that caller's credential, so the preview is capped by it, while a target
     * naming no credential, a model, a guard whose caller is another model or a
     * guard not configured, is previewed saying nothing, without the source
     * being asked.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testATargetOnItsGuardIsPreviewedWithItsCredentialsScopes(): void
    {
        $source = new CredentialScopesSource(['session:session-1' => null, 'guard:web' => ['posts:read']]);

        $this->app?->instance(SessionPolicySource::class, $source);

        $manager = $this->signIn(self::previewer());
        $target  = self::target('target', ['posts:read', 'posts:edit']);
        $other   = self::target('other', ['posts:edit']);

        $this->actingAs(AuthenticatableIdentity::query()->findOrFail('target'), 'web');

        $guarded = $manager->previewFor(new Subject($target, $target, guard: 'web'));

        self::assertCount(1, self::askedAbout($source, $target));
        self::assertSame(['posts:read'], $guarded->currentSubject()?->scopes?->scopes());
        self::assertSame(DecisionReason::SESSION_POLICY, $guarded->check('posts:edit')->reason);

        $source->calls = [];

        self::assertNull($manager->previewFor(new Subject($other, $other, guard: 'web'))->currentSubject()?->scopes);
        self::assertNull($manager->previewFor(new Subject($target, $target, guard: 'unconfigured'))->currentSubject()?->scopes);
        self::assertNull($manager->previewFor($other)->currentSubject()?->scopes);
        self::assertSame([], self::askedAbout($source, $target));
        self::assertSame([], self::askedAbout($source, $other));
    }

    /**
     * A target on the platform, given no scope, is previewed on the platform,
     * on its application, whatever tenant the request is in, and any other
     * target in the request's scope; a scope given is the preview's, and places
     * a target on the platform in its tenant.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testATargetOnThePlatformIsPreviewedThereByDefault(): void
    {
        $caller = self::previewer();
        $target = self::target();
        $tenant = StubTenant::query()->create(['id' => 'theirs', 'name' => 'theirs']);

        $target->givePermission(self::permission('posts:edit'), null, $tenant);

        $manager    = $this->signIn($caller, 'session-1', $tenant);
        $onPlatform = new Subject($target, $target, null, 'admin', platform: true);
        $context    = PreviewContext::of($manager, $onPlatform);

        self::assertNull($context->scope->tenant);
        self::assertSame('admin', $context->scope->application);
        self::assertSame('theirs', PreviewContext::of($manager, new Subject($target, $target))->scope->tenant?->id);
        self::assertFalse($manager->previewFor($onPlatform)->can('posts:edit'));
        self::assertTrue($manager->previewFor($onPlatform)->can('posts:read'));
        self::assertTrue($manager->previewFor(new Subject($target, $target))->can('posts:edit'));
        self::assertTrue($manager->previewFor($onPlatform, AuthorizationScope::tenant($tenant))->can('posts:edit'));
        self::assertSame([$tenant->getMorphClass(), 'theirs'], TenantScope::currentTenant());
    }

    /**
     * A model target, given no scope, is previewed in the scope in place even
     * when the previewer is on the platform and so names the model with the
     * marker, while a `Subject` given carrying the marker is previewed on the
     * platform there.
     *
     * @return void
     */
    public function testAModelTargetIsPreviewedInTheScopeInPlace(): void
    {
        $caller   = self::previewer();
        $target   = self::target();
        $tenant   = StubTenant::query()->create(['id' => 'theirs', 'name' => 'theirs']);
        $admitter = $this->signIn($caller)->for(new Subject($caller, $caller, null, null, 'web', 'session-1', platform: true));

        $scopes = AuthorizationScope::tenant($tenant)->within(static fn (): array => [
            PreviewContext::of($admitter, $target)->scope->tenant?->id,
            PreviewContext::of($admitter, new Subject($target, $target, platform: true))->scope->tenant,
        ]);

        self::assertSame(['theirs', null], $scopes);
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

    /**
     * Return the subjects about the model the source was asked about, leaving
     * out those about the previewer, whose admission asks it too.
     *
     * @param  \Tests\Feature\Stubs\CredentialScopesSource  $source
     * @param  object  $model
     * @return list<\SineMacula\Laravel\Authorization\Subject>
     */
    private static function askedAbout(CredentialScopesSource $source, object $model): array
    {
        return \array_values(\array_filter($source->calls, static fn (Subject $subject): bool => $subject->subject === $model));
    }
}
