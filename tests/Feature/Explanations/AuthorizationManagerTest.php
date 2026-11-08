<?php

declare(strict_types = 1);

namespace Tests\Feature\Explanations;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\Enums\ConditionOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\GrantSource;
use SineMacula\Laravel\Authorization\Evaluation\Explanation;
use SineMacula\Laravel\Authorization\Evaluation\GrantProvenance;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\CatchesRefusals;
use Tests\Concerns\PreviewsSubjects;
use Tests\Feature\Stubs\CustomGrantsIdentity;
use Tests\Feature\Stubs\FixedSubjectResolver;
use Tests\Feature\Stubs\RecordingResourceAttributes;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubMachine;
use Tests\Feature\Stubs\StubRequirementChecker;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for the manager's `explain()` (AUTHZ-11.5, N88, N89): the one
 * check `check()` makes, decided in explain mode, with the same verdict,
 * recorded and reported as any check is, and explained with where each grant
 * that allowed it came from, every condition test with its outcome, the keys
 * found missing, the stages it never reached and what it asked, never a value.
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
    use CatchesRefusals, PreviewsSubjects;

    /** @var string A value a check is given, which no explanation may carry. */
    private const string SECRET = 'sentinel-value-7f3a';

    /**
     * A permission granted directly is explained by its grant: the permission,
     * the principal it was granted to, no role, and the tenant and application
     * it was granted in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADirectGrantNamesItsGrantRow(): void
    {
        $tenant = StubTenant::query()->create(['id' => 'tenant-1', 'name' => 'tenant-1']);
        $user   = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:read']), null, $tenant, true, 'web');

        $explanation = TenantScope::within(Reference::of($tenant), 'web', static fn (): Explanation => Authorization::for($user)->explain('posts:read'));

        self::assertTrue($explanation->isAllowed());
        self::assertTrue($explanation->isDetailed());
        self::assertSame(['kind' => 'permission', 'names' => ['posts:read']], $explanation->cause);
        $grant = new GrantProvenance(GrantSource::PERMISSION, 'posts:read', Reference::of($user), false, [], true, Reference::of($tenant), 'web');

        self::assertEquals([$grant], $explanation->evidence?->grants);
        self::assertSame([], $explanation->notEvaluated);
        self::assertStringContainsString('grant permission "posts:read" to principal ' . self::escaped($user) . ' in tenant ', $explanation->toText());
    }

    /**
     * A permission a role carries names the role it came through, and one an
     * ancestor carries the whole path, from the role held up to the role that
     * carries it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARoleGrantNamesThePathToTheRoleThatCarriesIt(): void
    {
        $author = Role::create(['name' => 'author']);
        $editor = Role::create(['name' => 'editor', 'parent_id' => $author->id]);
        $user   = StubIdentity::create(['id' => 'user-1']);

        $author->givePermissionTo(Permission::create(['name' => 'posts:publish']));
        $editor->givePermissionTo(Permission::create(['name' => 'posts:edit']));
        $user->assignRole($editor);

        $edit    = Authorization::for($user)->explain('posts:edit');
        $publish = Authorization::for($user)->explain('posts:publish');

        self::assertEquals([new GrantProvenance(GrantSource::ROLE_PERMISSION, 'posts:edit', Reference::of($user), false, ['editor'], true)], $edit->evidence?->grants);
        $inherited = new GrantProvenance(GrantSource::ROLE_PERMISSION, 'posts:publish', Reference::of($user), false, ['editor', 'author'], true);

        self::assertEquals([$inherited], $publish->evidence?->grants);
        self::assertStringContainsString('through role "editor" < "author" in platform', $publish->toText());
    }

    /**
     * A permission the identity holds names the identity as its grantee.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityGrantNamesTheIdentity(): void
    {
        $principal = StubIdentity::create(['id' => 'principal-1']);
        $identity  = StubSecondIdentity::create(['id' => 'person-1']);

        $identity->givePermission(Permission::create(['name' => 'posts:read']));

        $explanation = Authorization::for(new Subject($principal, $identity))->explain('posts:read');

        self::assertTrue($explanation->isAllowed());
        self::assertEquals([new GrantProvenance(GrantSource::PERMISSION, 'posts:read', Reference::of($identity), true, [], true)], $explanation->evidence?->grants);
        self::assertStringContainsString('to identity ', $explanation->toText());
    }

    /**
     * A policy attached to the principal names the attachment, one attached to
     * a role names the role, and a resource policy names the resource it is
     * attached to.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyAllowNamesHowThePolicyReachedTheSubject(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $role   = Role::create(['name' => 'reviewer']);
        $own    = self::policy('own', [['effect' => 'allow', 'actions' => ['posts:read']]]);
        $shared = self::policy('shared', [['effect' => 'allow', 'actions' => ['posts:review']]]);
        $share  = self::policy('share', [['effect' => 'allow', 'actions' => ['posts:share'], 'principals' => [$user->getMorphClass() . ':user-1']]]);

        $user->attachPolicy($own);
        $role->attachPolicy($shared);
        $user->assignRole($role);
        self::resourcePolicies()->attach($share, 'posts');

        $read    = Authorization::for($user)->explain('posts:read');
        $review  = Authorization::for($user)->explain('posts:review');
        $sharing = Authorization::for($user)->explain('posts:share', ['posts', 7]);

        self::assertEquals([new GrantProvenance(GrantSource::POLICY, "own[{$own->id}]", Reference::of($user), false, [], true)], $read->evidence?->grants);
        self::assertEquals([new GrantProvenance(GrantSource::ROLE_POLICY, "shared[{$shared->id}]", Reference::of($user), false, ['reviewer'], true)], $review->evidence?->grants);
        self::assertEquals([new GrantProvenance(GrantSource::RESOURCE_POLICY, "share[{$share->id}] on posts:*")], $sharing->evidence?->grants);
        self::assertNull($read->cause);
    }

    /**
     * A policy the principal and an identity of the other kind both hold is
     * explained by the principal's attachment alone: the identity gives its
     * deny statements alone, which never allow a check.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityOfTheOtherKindNeverExplainsAnAllow(): void
    {
        $principal = StubIdentity::create(['id' => 'user-1']);
        $machine   = StubMachine::create(['id' => 'machine-1']);
        $editors   = self::policy('editors', [['effect' => 'allow', 'actions' => ['posts:edit']]]);

        $principal->attachPolicy($editors);
        $machine->attachPolicy($editors);

        $explanation = Authorization::for(new Subject($principal, $machine))->explain('posts:edit');

        self::assertTrue($explanation->isAllowed());
        self::assertEquals([new GrantProvenance(GrantSource::POLICY, "editors[{$editors->id}]", Reference::of($principal), false, [], true)], $explanation->evidence?->grants);
    }

    /**
     * An explained check decides from what an everyday check decides from, the
     * resolution cache included, so its verdict is the same even when the cache
     * is stale; a grant the cache holds that the grant rows read afresh no
     * longer give is explained as `unavailable`, never guessed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStaleCacheIsExplainedAsUnavailable(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $own  = self::policy('own', [['effect' => 'allow', 'actions' => ['posts:edit']]]);

        $user->givePermission(Permission::create(['name' => 'posts:read']));
        $user->attachPolicy($own);

        self::assertTrue(Authorization::for($user)->check('posts:read')->isAllowed());
        self::assertTrue(Authorization::for($user)->check('posts:edit')->isAllowed());

        DB::table('authorizable_permissions')->delete();
        DB::table('authorizable_policies')->delete();

        $read = Authorization::for($user)->explain('posts:read');
        $edit = Authorization::for($user)->explain('posts:edit');

        self::assertSame(Authorization::for($user)->check('posts:read')->isAllowed(), $read->isAllowed());
        self::assertTrue($read->isAllowed());
        self::assertEquals([GrantProvenance::unavailable('posts:read', Reference::of($user))], $read->evidence?->grants);
        self::assertTrue($edit->isAllowed());
        self::assertEquals([GrantProvenance::unavailable("own[{$own->id}]", Reference::of($user))], $edit->evidence?->grants);
    }

    /**
     * The last decision of an everyday check explains without the evidence it
     * never recorded, its request among it, its schema built without reading
     * anything that is not there.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEverydayDecisionExplainsWithoutItsRequest(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:read']));

        $array = Authorization::for($user)->check('posts:read')->explain()->toArray();

        self::assertSame(Explanation::NOT_RECORDED, $array['request']);
        self::assertSame(Explanation::NOT_RECORDED, $array['grants']);
    }

    /**
     * A grantee whose grants its own code gives cannot say where they came
     * from: its permission and its policy are explained as `unavailable`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACustomSourceIsUnavailable(): void
    {
        $user = CustomGrantsIdentity::create(['id' => 'custom-1']);

        $read   = Authorization::for($user)->explain('reports:read');
        $export = Authorization::for($user)->explain('reports:export');

        self::assertTrue($read->isAllowed());
        self::assertEquals([GrantProvenance::unavailable('reports:read', Reference::of($user))], $read->evidence?->grants);
        self::assertEquals([GrantProvenance::unavailable('coded', Reference::of($user))], $export->evidence?->grants);
        self::assertStringContainsString('grant unavailable "reports:read": provenance unavailable', $read->toText());
    }

    /**
     * A check refused before any grant is read is explained with an empty
     * trace, its reason as its cause, and every later stage not evaluated.
     *
     * @return void
     */
    public function testAnEarlyRefusalHasAnEmptyTrace(): void
    {
        $explanation = Authorization::forUser(null)->explain('posts:read');

        self::assertSame(DecisionReason::SUBJECT_UNRESOLVED, $explanation->reason);
        self::assertSame([], $explanation->steps);
        self::assertSame(['kind' => 'reason', 'names' => []], $explanation->cause);
        self::assertSame(\array_slice(DecisionStage::cases(), 1), $explanation->notEvaluated);
        self::assertSame([], $explanation->evidence?->grants);
    }

    /**
     * An explicit deny names every deny that applies, and marks every stage
     * after the deny as not evaluated, without weighing them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExplicitDenyNamesEveryDenyAndStopsThere(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:delete']));
        $user->attachPolicy(self::policy('first', [['effect' => 'deny', 'actions' => ['posts:delete']]]));
        $user->attachPolicy(self::policy('second', [['effect' => 'deny', 'actions' => ['posts:*']]]));

        $explanation = Authorization::for($user)->explain('posts:delete');

        self::assertSame(DecisionReason::EXPLICIT_DENY, $explanation->reason);
        self::assertSame(['first', 'second'], \array_map(static fn ($statement): string => $statement->policy, $explanation->statements));
        self::assertSame(\array_slice(DecisionStage::cases(), 4), $explanation->notEvaluated);
        self::assertSame(['deny'], \array_column($explanation->toArray()['stages'], 'stage'));
        self::assertStringContainsString('not evaluated: guardrail, boundary, session, allow, administration, implicit', $explanation->toText());
    }

    /**
     * A boundary that does not allow the check, or a session cap that does not
     * cover it, is named as the cause, with the later stages not evaluated.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACapIsNamedAsTheCause(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:edit']));

        $capped = Authorization::for($user)->capped(['posts:read'])->explain('posts:edit');

        self::boundaries()->set($user, self::policy('read-only', [['effect' => 'allow', 'actions' => ['posts:read']]]));

        $bounded = Authorization::for($user)->explain('posts:edit');

        self::assertSame(DecisionReason::SESSION_POLICY, $capped->reason);
        self::assertSame('session', $capped->cause['kind'] ?? null);
        self::assertSame([DecisionStage::ALLOW, DecisionStage::ADMINISTRATION, DecisionStage::IMPLICIT], $capped->notEvaluated);
        self::assertSame(DecisionReason::BOUNDARY, $bounded->reason);
        self::assertNotNull($bounded->cause);
        self::assertSame('boundary', $bounded->cause['kind']);
        self::assertCount(1, $bounded->cause['names']);
        self::assertStringStartsWith('read-only[', $bounded->cause['names'][0]);
    }

    /**
     * A policy that cannot be read is explained as an invalid policy, its stage
     * the deny stage, with no statement and every later stage not evaluated.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInvalidPolicyIsExplained(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $broken = Policy::create(['name' => 'broken', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]]);

        $user->attachPolicy($broken);
        DB::table('policies')->where('id', $broken->id)->update(['document' => '{"statements": "nonsense"}']);
        $this->app?->forgetInstance(ResolutionCache::class);

        $explanation = Authorization::for($user)->explain('posts:read');

        self::assertSame(DecisionReason::INVALID_POLICY, $explanation->reason);
        self::assertSame(DecisionStage::DENY, $explanation->stage);
        self::assertSame(['kind' => 'reason', 'names' => []], $explanation->cause);
        self::assertContains(DecisionStage::ALLOW, $explanation->notEvaluated);
    }

    /**
     * An insufficient authentication is explained by the allows it kept from
     * applying, each requirement by its part names and its unmet parts.
     *
     * @return void
     */
    public function testInsufficientAuthenticationNamesTheRequirements(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $this->app?->instance(SubjectResolver::class, new FixedSubjectResolver(new Subject($user, $user, session: 'session-1')));
        $this->app?->instance(AuthenticationRequirementChecker::class, new StubRequirementChecker(RequirementResult::unmet(['multifactor'])));

        foreach (['authorization', AuthorizationManager::class, CheckContextFactory::class] as $abstract) {
            $this->app?->forgetInstance($abstract);
        }

        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager $manager */
        $manager = $this->app?->make(AuthorizationManager::class);
        $policy  = EvaluationPolicy::fromArray(['name' => 'step-up', 'statements' => [[
            'effect'     => 'allow',
            'actions'    => ['reports:export'],
            'conditions' => ['authentication_requirement' => ['authentication' => ['multifactor' => ['max_age' => 900]]]],
        ]]]);

        $explanation = $manager->withPolicies([$policy])->explain('reports:export');
        $array       = $explanation->toArray();

        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $explanation->reason);
        self::assertSame([['names' => ['multifactor'], 'unmet' => ['multifactor']]], $array['requirements']);
        self::assertSame(ConditionOutcome::FAILED, $explanation->steps[3]->tests[0]->outcome ?? null);
        self::assertStringNotContainsString('session-1', \json_encode($array, \JSON_THROW_ON_ERROR));
        self::assertStringNotContainsString('900', $explanation->toText());
    }

    /**
     * Each condition test is explained on its own, by key, operator and typed
     * outcome: held, failed, missing, null, wrong type and unresolved, a
     * missing key passing under `_if_exists`; the keys found missing and the
     * unresolved references are named, and never a value.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachConditionTestIsExplainedWithItsOutcome(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $policy = EvaluationPolicy::fromArray(['name' => 'conditions', 'statements' => [[
            'effect'     => 'allow',
            'actions'    => ['posts:read'],
            'conditions' => [
                'eq'           => ['input.team' => self::SECRET, 'input.blank' => 'x', 'input.absent' => 'y', 'input.other' => '${input.nowhere}'],
                'gt'           => ['input.count' => 3, 'input.team' => 1],
                'eq_if_exists' => ['input.optional' => 'z'],
            ],
        ]]]);

        $context     = ['team' => self::SECRET, 'blank' => null, 'count' => 'many', 'other' => 'o'];
        $explanation = Authorization::for($user)->withPolicies([$policy])->explain('posts:read', null, $context);
        $tests       = $explanation->steps[3]->tests ?? [];
        $outcomes    = \array_map(static fn ($test): array => [$test->key, $test->operator, $test->outcome, $test->isMissing], $tests);

        self::assertSame(DecisionReason::CONDITION_FAILED, $explanation->reason);
        self::assertSame([
            ['input.team', 'eq', ConditionOutcome::HELD, false],
            ['input.blank', 'eq', ConditionOutcome::NULL, false],
            ['input.absent', 'eq', ConditionOutcome::MISSING, true],
            ['input.other', 'eq', ConditionOutcome::UNRESOLVED, false],
            ['input.count', 'gt', ConditionOutcome::WRONG_TYPE, false],
            ['input.team', 'gt', ConditionOutcome::WRONG_TYPE, false],
            ['input.optional', 'eq', ConditionOutcome::HELD, true],
        ], $outcomes);
        self::assertSame(['input.nowhere'], $tests[3]->unresolved);
        self::assertSame(['input.absent', 'input.nowhere'], $explanation->missingKeys());
        self::assertContains('input.nowhere', $explanation->keys);
        self::assertStringNotContainsString(self::SECRET, $explanation->toText());
        self::assertStringNotContainsString(self::SECRET, \json_encode($explanation, \JSON_THROW_ON_ERROR));
        self::assertStringNotContainsString('many', $explanation->toText());
    }

    /**
     * Explain mode decides as `check()` decides, records the explained check as
     * the last decision and reports it once, like any check, and rendering the
     * explanation records, reports and reads nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testExplainRecordsAsACheckAndRenderingHasNoSideEffects(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:read']));

        Event::fake([DecisionEvaluated::class]);

        $manager     = Authorization::for($user);
        $explanation = $manager->explain('posts:read');

        Event::assertDispatchedTimes(DecisionEvaluated::class, 1);
        self::assertTrue($manager->lastDecision()?->hasEvidence());

        $last = $manager->lastDecision();

        DB::enableQueryLog();
        DB::flushQueryLog();

        $text = $explanation->toText();
        $json = \json_encode($explanation, \JSON_THROW_ON_ERROR);

        self::assertSame([], DB::getQueryLog());
        Event::assertDispatchedTimes(DecisionEvaluated::class, 1);
        self::assertSame($last, $manager->lastDecision());
        self::assertNotSame('', $text);
        self::assertSame(1, \json_decode($json, true, 512, \JSON_THROW_ON_ERROR)['version']);
    }

    /**
     * Explain mode asks no attribute provider and reads no grant beyond what
     * the plain check does, from a cold cache.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testExplainModeReadsNothingMoreThanTheCheck(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $role   = Role::create(['name' => 'editor']);
        $type   = $user->getMorphClass();
        $posts  = new RecordingResourceAttributes;
        $policy = self::policy('drafts', [['effect' => 'allow', 'actions' => ['posts:edit'], 'conditions' => ['eq' => ['resource.status' => 'draft']]]]);

        $role->givePermissionTo(Permission::create(['name' => 'posts:read']));
        $role->attachPolicy($policy);
        $user->assignRole($role);

        $this->app?->instance(RecordingResourceAttributes::class, $posts);
        $this->app?->make(ConfigRepository::class)->set('authorization.attributes.resources', [$type => RecordingResourceAttributes::class]);
        $this->app?->forgetInstance(CheckContextFactory::class);
        $this->app?->forgetInstance('authorization');
        Authorization::clearResolvedInstance('authorization');

        foreach ([['posts:edit', [$type, 'post-1']], ['posts:read', null]] as [$action, $resource]) {
            [$checked, $checkQueries, $checkCalls]       = $this->measured($posts, static fn (): bool => Authorization::for($user)->check($action, $resource)->isAllowed());
            [$explained, $explainQueries, $explainCalls] = $this->measured($posts, static fn (): bool => Authorization::for($user)->explain($action, $resource)->isAllowed());

            self::assertTrue($checked, $action);
            self::assertSame($checked, $explained, $action);
            self::assertLessThanOrEqual($checkQueries, $explainQueries, $action);
            self::assertSame($checkCalls, $explainCalls, $action);
        }
    }

    /**
     * A preview's `explain()` keeps its admission and its recording: it
     * explains the target's check, naming the previewer beside the target, and
     * reports it naming both; a previewer without the right is refused before
     * anything about the target is explained or reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPreviewExplainsTheTargetOnceAdmitted(): void
    {
        $caller = self::previewer();
        $target = self::target();

        Event::fake([DecisionEvaluated::class]);

        $explanation = $this->signIn($caller)->previewFor($target)->explain('posts:read');
        $request     = $explanation->evidence?->request;
        $reported    = Event::dispatched(DecisionEvaluated::class, static fn (DecisionEvaluated $event): bool => $event->action === 'posts:read');

        self::assertTrue($explanation->isAllowed());
        self::assertEquals(Reference::of($caller), $request?->decided->previewer);
        self::assertEquals(Reference::of($target), $request?->decided->subject);
        self::assertEquals([new GrantProvenance(GrantSource::PERMISSION, 'posts:read', Reference::of($target), false, [], true)], $explanation->evidence?->grants);
        self::assertCount(1, $reported);
        $event = $reported->values()[0][0];

        self::assertInstanceOf(DecisionEvaluated::class, $event);
        self::assertEquals(Reference::of($caller), $event->previewer);

        $refused = self::refusalOf(fn (): Explanation => $this->signIn(self::previewer('stranger', false))->previewFor($target)->explain('posts:read'));

        self::assertInstanceOf(AuthorizationException::class, $refused);
        self::assertCount(1, Event::dispatched(DecisionEvaluated::class, static fn (DecisionEvaluated $event): bool => $event->action === 'posts:read'));
    }

    /**
     * Return what the callback returns, with how many queries it ran and how
     * many times the provider was asked, from a cold cache.
     *
     * @param  \Tests\Feature\Stubs\RecordingResourceAttributes  $posts
     * @param  \Closure(): bool  $callback
     * @return array{bool, int, int}
     */
    private function measured(RecordingResourceAttributes $posts, \Closure $callback): array
    {
        $this->app?->forgetInstance(ResolutionCache::class);
        $posts->calls = [];

        DB::enableQueryLog();
        DB::flushQueryLog();

        $result  = $callback();
        $queries = \count(DB::getQueryLog());

        DB::disableQueryLog();

        return [$result, $queries, \count($posts->calls)];
    }

    /**
     * Return the reference to the model as an explanation writes it, escaped.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return string
     */
    private static function escaped(Model $model): string
    {
        return \substr(\json_encode(Reference::of($model)->type . ':' . Reference::of($model)->id, \JSON_UNESCAPED_SLASHES | \JSON_THROW_ON_ERROR), 1, -1);
    }

    /**
     * Create a stored policy with the statements.
     *
     * @param  string  $name
     * @param  list<array<string, mixed>>  $statements
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function policy(string $name, array $statements): Policy
    {
        return Policy::create(['name' => $name, 'document' => ['statements' => $statements]]);
    }

    /**
     * Return the boundary service.
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
     * Return the resource policy service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\ResourcePolicyService
     */
    private static function resourcePolicies(): ResourcePolicyService
    {
        $service = ResourcePolicyService::instance();

        self::assertInstanceOf(ResourcePolicyService::class, $service);

        return $service;
    }
}
