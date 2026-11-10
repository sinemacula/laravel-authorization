<?php

declare(strict_types = 1);

namespace Tests\Feature\Evaluation;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\CheckBatch;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionPipeline;
use SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Resolvers\DeclaredResourceTenant;
use SineMacula\Laravel\Authorization\Resolvers\GuardrailResolver;
use SineMacula\Laravel\Authorization\Resolvers\NoResourceTenant;
use SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\ResourceReferences;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\Fixtures\BulkChecks\BulkStatusAttributes;
use Tests\Fixtures\BulkChecks\CountingBulkTenants;
use Tests\Fixtures\BulkChecks\FailingTenantTree;
use Tests\Fixtures\BulkChecks\GuardedPost;
use Tests\Fixtures\BulkChecks\GuardedStatusAttributes;
use Tests\Fixtures\BulkChecks\StatusAttributes;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\Fixtures\QueryScoping\TenantScopedDocument;
use Tests\Fixtures\QueryScoping\TenantScopedPost;
use Tests\TestCase;

/**
 * Feature tests for `CheckBatch`, the one path every check of the manager
 * takes: each check decided as `check()` decides it, recorded and reported as
 * it is decided, in order, with what the checks share read once and the
 * resources' data read in bulk.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(CheckBatch::class)]
final class CheckBatchTest extends TestCase
{
    use ReadsDispatchedEvents;

    /** @var string The action the checks decide. */
    private const string ACTION = 'posts:read';

    /** @var string The status the published posts have. */
    private const string PUBLISHED = 'published';

    /**
     * Each check is decided as `check()` decides it, whatever form its resource
     * takes, and the decisions are keyed and ordered as the checks are, a check
     * repeated included.
     *
     * @return void
     */
    public function testEachCheckIsDecidedAsCheckDecidesIt(): void
    {
        $user = $this->subject();
        $post = ScopedPost::query()->create(['title' => 'a', 'status' => self::PUBLISHED]);

        $user->givePermission(Permission::create(['name' => self::ACTION]));

        $resources = [
            'z'       => $post,
            3         => [ScopedPost::class, self::key($post)],
            'type'    => ScopedPost::class,
            'none'    => null,
            'opaque'  => 'reports:7',
            'again'   => $post,
            'unsaved' => new ScopedPost,
        ];
        $checks    = \array_map(static fn (mixed $resource): CheckInput => new CheckInput(self::ACTION, $resource), $resources);
        $expected  = \array_map(static fn (mixed $resource): Decision => Authorization::check(self::ACTION, $resource), $resources);
        $decisions = Authorization::checkMany($checks);

        self::assertSame(\array_keys($resources), \array_keys($decisions));
        self::assertEquals($expected, $decisions);
        self::assertSame(DecisionReason::RESOURCE_UNRESOLVED, $decisions['unsaved']->reason);
    }

    /**
     * Each check dispatches its own decision event, in the order of the checks,
     * a check repeated included, with the check's action, resource and effect
     * and a reference to the subject, but never the check's context, as
     * `check()` dispatches it.
     *
     * @return void
     */
    public function testEachCheckDispatchesItsOwnDecisionEventInOrder(): void
    {
        $user  = $this->subject();
        $posts = $this->posts(3);

        $user->givePermission(Permission::create(['name' => self::ACTION]));

        Event::fake([DecisionEvaluated::class]);

        Authorization::checkMany([
            'b' => new CheckInput(self::ACTION, $posts[1], ['flag' => 'on']),
            'a' => new CheckInput('posts:edit', $posts[0]),
            'c' => new CheckInput(self::ACTION, $posts[1]),
            'd' => new CheckInput(self::ACTION, $posts[2]),
        ]);

        $events = self::dispatchedEvents(DecisionEvaluated::class);

        self::assertCount(4, $events);
        self::assertSame([self::ACTION, 'posts:edit', self::ACTION, self::ACTION], \array_map(static fn (DecisionEvaluated $event): string => $event->action, $events));
        $named = \array_map(static fn (ScopedPost $post): string => $post->getMorphClass() . ':' . self::key($post), [$posts[1], $posts[0], $posts[1], $posts[2]]);

        self::assertSame($named, \array_map(static fn (DecisionEvaluated $event): ?string => $event->resource, $events));
        self::assertSame([], $events[0]->keys);
        self::assertStringNotContainsString('flag', \serialize($events[0]));
        self::assertFalse($events[1]->isAllowed());
        self::assertSame(DecisionReason::NO_MATCH, $events[1]->reason);
        self::assertEquals(Reference::of($user), $events[0]->subject);
    }

    /**
     * The last decision is the last check of the batch; an empty batch decides
     * nothing, dispatches nothing and leaves the last decision as it was.
     *
     * @return void
     */
    public function testTheLastDecisionIsTheLastCheckAndAnEmptyBatchLeavesIt(): void
    {
        $this->subject()->givePermission(Permission::create(['name' => self::ACTION]));

        $posts = $this->posts(2);
        $first = Authorization::check('posts:edit', $posts[0]);

        Event::fake([DecisionEvaluated::class]);

        self::assertSame([], Authorization::checkMany([]));
        self::assertSame($first, Authorization::lastDecision());
        Event::assertNotDispatched(DecisionEvaluated::class);

        $decisions = Authorization::checkMany([new CheckInput('posts:edit', $posts[0]), new CheckInput(self::ACTION, $posts[1])]);

        self::assertSame($decisions[1], Authorization::lastDecision());
        self::assertTrue($decisions[1]->isAllowed());
    }

    /**
     * A batch made neither to dispatch nor to store decides each check as a
     * recording one does, one check on its own or many, but leaves the last
     * decision as it was and dispatches no decision event.
     *
     * @return void
     */
    public function testABatchThatDoesNotRecordDecidesAlikeAndRecordsNothing(): void
    {
        $user = $this->subject();

        $user->givePermission(Permission::create(['name' => self::ACTION]));

        $posts  = $this->posts(3);
        $checks = ['a' => new CheckInput(self::ACTION, $posts[0]), 'b' => new CheckInput('posts:edit', $posts[1]), 'c' => new CheckInput(self::ACTION, $posts[2])];
        $first  = Authorization::check('posts:edit', $posts[0]);

        /** @var \Illuminate\Foundation\Application $app */
        $app      = $this->app;
        $contexts = $app->make(CheckContextFactory::class);
        $pipeline = new DecisionPipeline($app->make(PolicyEvaluator::class), $app->make(PolicyResolver::class), $contexts, new ResourcePolicyResolver, new GuardrailResolver);
        $batch    = new CheckBatch($pipeline, $app->make(LastDecisionStore::class), $app->make(SubjectResolver::class), $app->make(Dispatcher::class), false, false);

        Event::fake([DecisionEvaluated::class]);

        $subject = Authorization::currentSubject();
        $silent  = $batch->decide($subject, $checks);
        $one     = $batch->decideOne($subject, $checks['b']);

        self::assertSame($first, Authorization::lastDecision());
        Event::assertNotDispatched(DecisionEvaluated::class);

        self::assertEquals(Authorization::checkMany($checks), $silent);
        self::assertEquals(Authorization::check('posts:edit', $posts[1]), $one);
        self::assertSame([true, false, true], \array_values(\array_map(static fn (Decision $decision): bool => $decision->isAllowed(), $silent)));
    }

    /**
     * The four ways a batch may be made: dispatching and storing, each on or
     * off.
     *
     * @return iterable<string, array{bool, bool}>
     */
    public static function switches(): iterable
    {
        yield 'dispatching and storing' => [true, true];
        yield 'dispatching alone' => [true, false];
        yield 'storing alone' => [false, true];
        yield 'neither' => [false, false];
    }

    /**
     * Dispatching and storing are separate switches: a batch dispatches each
     * decision's event only when it dispatches, and stores each decision as the
     * last decision, with its provenance, only when it stores, for many checks,
     * one on its own and a decision made elsewhere alike, deciding every check
     * the same way whichever it does.
     *
     * @param  bool  $isDispatching
     * @param  bool  $isStoring
     * @return void
     */
    #[DataProvider('switches')]
    public function testDispatchingAndStoringAreSeparateSwitches(bool $isDispatching, bool $isStoring): void
    {
        $user = $this->subject();

        $user->givePermission(Permission::create(['name' => self::ACTION]));

        $posts    = $this->posts(2);
        $checks   = ['a' => new CheckInput(self::ACTION, $posts[0]), 'b' => new CheckInput('posts:edit', $posts[1])];
        $refusal  = Decision::deny(DecisionReason::ADMINISTRATION_CONFLICT, DecisionStage::ADMINISTRATION);
        $expected = Authorization::checkMany($checks);

        Authorization::forgetLastDecision();
        Event::fake([DecisionEvaluated::class]);

        /** @var \Illuminate\Foundation\Application $app */
        $app      = $this->app;
        $contexts = $app->make(CheckContextFactory::class);
        $pipeline = new DecisionPipeline($app->make(PolicyEvaluator::class), $app->make(PolicyResolver::class), $contexts, new ResourcePolicyResolver, new GuardrailResolver);
        $store    = $app->make(LastDecisionStore::class);
        $batch    = new CheckBatch($pipeline, $store, $app->make(SubjectResolver::class), $app->make(Dispatcher::class), $isDispatching, $isStoring);
        $subject  = Authorization::currentSubject();
        $many     = $batch->decide($subject, $checks);

        self::assertEquals($expected, $many);
        self::assertSame($isStoring ? $many['b'] : null, Authorization::lastDecision());

        $one = $batch->decideOne($subject, $checks['a']);

        self::assertSame($isStoring ? $one : null, Authorization::lastDecision());
        self::assertSame($refusal, $batch->recordOne($subject, $checks['b'], $refusal));
        self::assertSame($isStoring ? $refusal : null, Authorization::lastDecision());
        self::assertEquals($isStoring ? DecisionProvenance::of($subject) : null, Authorization::lastDecisionProvenance());

        $events = self::dispatchedEvents(DecisionEvaluated::class);

        self::assertCount($isDispatching ? 4 : 0, $events);
        $actions = \array_map(static fn (DecisionEvaluated $event): string => $event->action, $events);

        self::assertSame($isDispatching ? [self::ACTION, 'posts:edit', self::ACTION, 'posts:edit'] : [], $actions);
        self::assertSame($isDispatching ? [true, false, true, false] : [], \array_map(static fn (DecisionEvaluated $event): bool => $event->isAllowed(), $events));
    }

    /**
     * A preview's batch names its previewer in the provenance of every decision
     * it records and in every event it dispatches, many checks, one on its own
     * and a decision made elsewhere alike, beside the subject; any other batch
     * names none.
     *
     * @return void
     */
    public function testAPreviewsBatchNamesItsPreviewerBesideTheSubject(): void
    {
        $user = $this->subject();

        $user->givePermission(Permission::create(['name' => self::ACTION]));

        $posts     = $this->posts(2);
        $checks    = ['a' => new CheckInput(self::ACTION, $posts[0]), 'b' => new CheckInput('posts:edit', $posts[1])];
        $previewer = new Reference('previewer', 'p1');
        $refusal   = Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);

        Event::fake([DecisionEvaluated::class]);

        /** @var \Illuminate\Foundation\Application $app */
        $app      = $this->app;
        $contexts = $app->make(CheckContextFactory::class);
        $pipeline = new DecisionPipeline($app->make(PolicyEvaluator::class), $app->make(PolicyResolver::class), $contexts, new ResourcePolicyResolver, new GuardrailResolver);
        $store    = $app->make(LastDecisionStore::class);
        $batch    = new CheckBatch($pipeline, $store, $app->make(SubjectResolver::class), $app->make(Dispatcher::class), true, true, $previewer);
        $subject  = Authorization::currentSubject();

        $batch->decide($subject, $checks);

        self::assertSame($previewer, $store->provenance()?->previewer);

        $batch->decideOne($subject, $checks['a']);

        self::assertSame($previewer, $store->provenance()->previewer);

        $batch->recordOne($subject, $checks['b'], $refusal);

        self::assertEquals(DecisionProvenance::of($subject, $previewer), Authorization::lastDecisionProvenance());

        $events = self::dispatchedEvents(DecisionEvaluated::class);

        self::assertCount(4, $events);

        foreach ($events as $event) {
            self::assertSame($previewer, $event->previewer);
            self::assertEquals(Reference::of($user), $event->subject);
        }

        Authorization::check(self::ACTION, $posts[0]);

        self::assertNull($store->provenance()->previewer);
    }

    /**
     * A decision the pipeline did not make is recorded and reported for its
     * check as one the pipeline made is, as the last decision with its own
     * decision event naming the check's resource; a batch made neither to
     * dispatch nor to store records nothing of it either.
     *
     * @return void
     */
    public function testADecisionMadeElsewhereIsRecordedAsTheChecksDecision(): void
    {
        $user     = $this->subject();
        $decision = Decision::deny(DecisionReason::ADMINISTRATION_CONFLICT, DecisionStage::ADMINISTRATION);
        $check    = new CheckInput('posts:edit', ['posts', 7]);

        /** @var \Illuminate\Foundation\Application $app */
        $app      = $this->app;
        $contexts = $app->make(CheckContextFactory::class);
        $pipeline = new DecisionPipeline($app->make(PolicyEvaluator::class), $app->make(PolicyResolver::class), $contexts, new ResourcePolicyResolver, new GuardrailResolver);
        $store    = $app->make(LastDecisionStore::class);
        $resolver = $app->make(SubjectResolver::class);
        $batch    = static fn (bool $isRecording): CheckBatch => new CheckBatch($pipeline, $store, $resolver, $app->make(Dispatcher::class), $isRecording, $isRecording);

        Event::fake([DecisionEvaluated::class]);

        $subject = Authorization::currentSubject();

        self::assertSame($decision, $batch(false)->recordOne($subject, $check, $decision));
        self::assertNotSame($decision, Authorization::lastDecision());
        Event::assertNotDispatched(DecisionEvaluated::class);

        self::assertSame($decision, $batch(true)->recordOne($subject, $check, $decision));
        self::assertSame($decision, Authorization::lastDecision());
        $named     = [DecisionReason::ADMINISTRATION_CONFLICT, 'posts:7', $user->getKey()];
        $evaluated = static fn (DecisionEvaluated $event): bool => [$event->reason, $event->resource, $event->subject?->id] === $named;

        Event::assertDispatched(DecisionEvaluated::class, $evaluated);
    }

    /**
     * A batch decided in an `AuthorizationScope`, as `permissionsFor()` decides
     * its listing, records and reports each decision in that scope's tenant and
     * application, whatever tenant the subject names; `permissionsFor()` itself
     * still records nothing.
     *
     * @return void
     */
    public function testABatchInAnAuthorizationScopeNamesThatScope(): void
    {
        $tenant = StubTenant::query()->create(['id' => 't1', 'name' => 't1']);
        $other  = StubTenant::query()->create(['id' => 't2', 'name' => 't2']);

        $this->subject($tenant);

        Event::fake([DecisionEvaluated::class]);

        /** @var \Illuminate\Foundation\Application $app */
        $app      = $this->app;
        $pipeline = new DecisionPipeline($app->make(PolicyEvaluator::class), $app->make(PolicyResolver::class), $app->make(CheckContextFactory::class));
        $batch    = new CheckBatch($pipeline, $app->make(LastDecisionStore::class), $app->make(SubjectResolver::class), $app->make(Dispatcher::class), true, true);
        $subject  = Authorization::currentSubject();
        $scope    = AuthorizationScope::tenant($other, 'admin');

        $scope->within(static fn (): array => $batch->decide($subject, [new CheckInput(self::ACTION), new CheckInput('posts:edit')]));

        $events = self::dispatchedEvents(DecisionEvaluated::class);

        self::assertSame($tenant, $subject?->tenant);
        self::assertCount(2, $events);

        foreach ($events as $event) {
            self::assertEquals(Reference::of($other), $event->tenant);
            self::assertSame('admin', $event->application);
        }

        $recorded = Authorization::lastDecisionProvenance();

        self::assertEquals(Reference::of($other), $recorded?->tenant);

        Authorization::permissionsFor(null, $scope);

        self::assertSame($recorded, Authorization::lastDecisionProvenance());
        self::assertCount(2, self::dispatchedEvents(DecisionEvaluated::class));
    }

    /**
     * A check that throws stops the batch there: the checks before it are
     * recorded and reported, the last decision being the last of them, and none
     * after it is decided; the ambient tenant scope is the request's again,
     * though the check threw in its resource's tenant.
     *
     * @return void
     */
    public function testACheckThatThrowsStopsTheBatchAndRestoresTheScope(): void
    {
        $tenant = StubTenant::query()->create(['id' => 't1', 'name' => 't1']);
        $posts  = $this->posts(3, $tenant);

        $this->subject($tenant);

        $provider          = $this->attributes(new StatusAttributes);
        $provider->failing = [self::key($posts[1])];

        Event::fake([DecisionEvaluated::class]);

        $manager = Authorization::withPolicies([$this->statusPolicy()]);

        try {
            $manager->checkMany(\array_map(static fn (TenantScopedPost $post): CheckInput => new CheckInput(self::ACTION, $post), $posts));

            self::fail('The batch is stopped.');
        } catch (AttributeProviderFailed $exception) {
            self::assertSame(StatusAttributes::MESSAGE, $exception->getPrevious()?->getMessage());
        }

        $events = self::dispatchedEvents(DecisionEvaluated::class);

        self::assertCount(1, $events);
        self::assertSame($posts[0]->getMorphClass() . ':' . self::key($posts[0]), $events[0]->resource);
        self::assertSame(['resource.status'], $events[0]->keys);
        self::assertTrue($manager->lastDecision()?->isAllowed());
        self::assertSame([self::key($posts[0]), self::key($posts[1])], $provider->calls);
        self::assertTrue($events[0]->isAllowed());
        self::assertSame($tenant->getMorphClass() . ':t1:every', TenantScope::scopeKey());
        self::assertFalse($this->app?->bound('authorization.tenant_scope.within'));
    }

    /**
     * A bulk provider's failure for one record fails that record's check alone,
     * and only when it reads `resource`: the other checks are decided from the
     * values read with it, in one call for the records still to be decided.
     *
     * @return void
     */
    public function testAProvidersFailureIsIsolatedToItsOwnCheck(): void
    {
        $posts = $this->posts(3);

        $this->subject();

        $provider          = $this->attributes(new BulkStatusAttributes);
        $provider->failing = [self::key($posts[1])];

        $decisions = Authorization::withPolicies([$this->statusPolicy()])->checkMany([
            new CheckInput(self::ACTION, $posts[0]),
            new CheckInput('posts:list', $posts[1]),
            new CheckInput(self::ACTION, [ScopedPost::class, self::key($posts[2])]),
        ]);

        self::assertSame([true, false, true], \array_map(static fn (Decision $decision): bool => $decision->isAllowed(), $decisions));
        self::assertSame([\array_map(self::key(...), $posts)], $provider->bulkCalls);
        self::assertSame([], $provider->calls);

        $this->expectException(AttributeProviderFailed::class);

        Authorization::withPolicies([$this->statusPolicy()])->checkMany([new CheckInput(self::ACTION, $posts[0]), new CheckInput(self::ACTION, $posts[1])]);
    }

    /**
     * A bulk provider whose call throws, or whose answer leaves a record out,
     * is asked about each such record on its own, so its checks are decided as
     * they would be one at a time.
     *
     * @return void
     */
    public function testARecordTheBulkCallCannotAnswerIsAskedAboutOnItsOwn(): void
    {
        $posts = $this->posts(2);

        $this->subject();

        $provider           = $this->attributes(new BulkStatusAttributes);
        $provider->isBroken = true;

        $checks = \array_map(static fn (ScopedPost $post): CheckInput => new CheckInput(self::ACTION, $post), $posts);
        $policy = $this->statusPolicy();

        self::assertSame([true, false], \array_map(static fn (Decision $decision): bool => $decision->isAllowed(), Authorization::withPolicies([$policy])->checkMany($checks)));
        self::assertSame(\array_map(self::key(...), $posts), $provider->calls);

        $provider->isBroken = false;
        $provider->calls    = [];
        $provider->leftOut  = [self::key($posts[1])];

        self::assertSame([true, false], \array_map(static fn (Decision $decision): bool => $decision->isAllowed(), Authorization::withPolicies([$policy])->checkMany($checks)));
        self::assertSame([self::key($posts[1])], $provider->calls);
    }

    /**
     * A grant revoked by a listener reacting to a check's decision is seen by
     * every check after it, as it would be one check at a time.
     *
     * @return void
     */
    public function testAGrantRevokedByAListenerMidBatchIsSeenByTheChecksAfterIt(): void
    {
        $user       = $this->subject();
        $permission = Permission::create(['name' => self::ACTION]);
        $posts      = $this->posts(3);

        $user->givePermission($permission);

        Event::listen(DecisionEvaluated::class, static function () use ($user, $permission): void {
            $user->revokePermission($permission);
        });

        self::assertSame([true, false, false], Authorization::canEach(self::ACTION, $posts));
    }

    /**
     * The checks are decided a chunk of `authorization.bulk.chunk_size` at a
     * time, the decisions keyed and ordered as the checks are across chunks,
     * the size read as the environment writes it; a size that is not a whole
     * number of at least 1 is refused before any check is decided, never read
     * as the default.
     *
     * @return void
     */
    public function testTheChecksAreDecidedInChunks(): void
    {
        $posts = $this->posts(5);

        $this->subject();

        $provider  = $this->attributes(new BulkStatusAttributes);
        $resources = ['e' => $posts[4], 'a' => $posts[0], 'd' => $posts[3], 'b' => $posts[1], 'c' => $posts[2]];

        $this->config()->set('authorization.bulk.chunk_size', '2');

        $allowed = Authorization::withPolicies([$this->statusPolicy()])->canEach(self::ACTION, $resources);

        self::assertSame(['e' => false, 'a' => true, 'd' => false, 'b' => false, 'c' => true], $allowed);

        $this->config()->set('authorization.bulk', []);

        self::assertSame($allowed, Authorization::withPolicies([$this->statusPolicy()])->canEach(self::ACTION, $resources));
        self::assertSame([2, 2, 1, 5], \array_map(\count(...), $provider->bulkCalls));

        $this->config()->set('authorization.bulk.chunk_size', 0);

        try {
            Authorization::withPolicies([$this->statusPolicy()])->canEach(self::ACTION, $resources);

            self::fail('A chunk size of 0 was not refused.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame('authorization.bulk.chunk_size', $exception->getConfigKey());
        }

        self::assertCount(4, $provider->bulkCalls);
    }

    /**
     * A batch holding something other than a `CheckInput` is refused before any
     * check is decided.
     *
     * @return void
     */
    public function testABatchHoldingSomethingElseIsRefusedBeforeAnyCheck(): void
    {
        Event::fake([DecisionEvaluated::class]);

        $this->subject();

        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager $manager */
        $manager = $this->app?->make(AuthorizationManager::class);

        try {
            $manager->checkMany(['first' => new CheckInput(self::ACTION), 'second' => self::ACTION]); // @phpstan-ignore argument.type

            self::fail('The batch is refused.');
        } catch (InvalidCheckArgumentException $exception) {
            self::assertStringContainsString('\'second\'', $exception->getMessage());
        }

        Event::assertNotDispatched(DecisionEvaluated::class);
        self::assertNull(Authorization::lastDecision());
    }

    /**
     * A bulk resolver is asked once for the models and once for the records of
     * each type, each record once however often it is named; a record it leaves
     * out, or every resource when its bulk call throws, is asked about on its
     * own, and one whose tenant cannot be told fails its own check alone, when
     * it is reached.
     *
     * @return void
     */
    public function testTheResourcesTenantsAreReadInBulk(): void
    {
        $tenant   = new Reference('stub_tenant', 't1');
        $resolver = new CountingBulkTenants(['1' => $tenant, '2' => null, '3' => $tenant]);
        $user     = $this->subject();

        $this->app?->instance(ResourceTenantResolver::class, $resolver);

        $user->givePermission(Permission::create(['name' => self::ACTION]));

        $model = new StubIdentity(['id' => '1']);

        $model->exists = true;

        $checks    = \array_map(static fn (mixed $resource): CheckInput => new CheckInput(self::ACTION, $resource), [['posts', '2'], ['posts', '2'], ['posts', '4'], $model]);
        $decisions = Authorization::checkMany($checks);

        self::assertSame([['1'], ['2', '4']], $resolver->bulkCalls);
        self::assertSame([], $resolver->calls);
        self::assertSame([true, true, false, true], \array_map(static fn (Decision $decision): bool => $decision->isAllowed(), $decisions));
        self::assertSame(DecisionReason::RESOURCE_UNRESOLVED, $decisions[2]->reason);

        $resolver->isBroken  = true;
        $resolver->bulkCalls = [];

        Authorization::checkMany([new CheckInput(self::ACTION, ['posts', '2']), new CheckInput(self::ACTION, $model)]);

        self::assertSame(['2', '1'], $resolver->calls);

        $resolver->isBroken = false;
        $resolver->calls    = [];
        $resolver->failing  = ['3'];
        $decided            = 0;

        Event::listen(DecisionEvaluated::class, static function () use (&$decided): void {
            $decided++;
        });

        try {
            Authorization::checkMany([new CheckInput(self::ACTION, ['posts', '2']), new CheckInput(self::ACTION, ['posts', '3']), new CheckInput(self::ACTION, ['posts', '2'])]);

            self::fail('The check whose tenant cannot be told throws.');
        } catch (\RuntimeException $exception) {
            self::assertSame(CountingBulkTenants::MESSAGE, $exception->getMessage());
        }

        self::assertSame(['3'], $resolver->calls);
        self::assertSame(1, $decided);
    }

    /**
     * A check on its own reads the policies attached to its record as it would
     * read them, with no bulk read ahead; two checks read theirs together.
     *
     * @return void
     */
    public function testACheckOnItsOwnReadsNothingAhead(): void
    {
        $this->subject();

        $posts = $this->posts(2);
        $reads = [];

        DB::listen(static function (QueryExecuted $query) use (&$reads): void {
            if (!\str_contains($query->sql, 'as "attached_resource_id"') && !\str_contains($query->sql, 'as `attached_resource_id`')) {
                return;
            }

            $reads[] = \str_contains($query->sql, ' in (') ? 'bulk' : 'single';
        });

        Authorization::check(self::ACTION, $posts[0]);
        Authorization::checkMany([new CheckInput(self::ACTION, $posts[0]), new CheckInput(self::ACTION, $posts[1])]);

        self::assertSame(['single', 'bulk'], $reads);

        $tenants = [];

        DB::listen(static function (QueryExecuted $query) use (&$tenants): void {
            // A lookup of a document's tenant, not a read of the table's
            // schema.
            if (!\str_contains($query->sql, 'scoped_documents') || !\str_contains($query->sql, 'tenant_type')) {
                return;
            }

            $tenants[] = $query->sql;
        });

        $this->app?->instance(ResourceTenantResolver::class, new DeclaredResourceTenant(new NoResourceTenant));

        Authorization::check(self::ACTION, [TenantScopedDocument::class, 'missing-doc']);

        self::assertCount(1, $tenants, \implode("\n", $tenants));
        self::assertStringNotContainsString(' in (', $tenants[0]);

        $resolver = new CountingBulkTenants(['1' => null]);

        $this->app?->instance(ResourceTenantResolver::class, $resolver);

        Authorization::checkMany([new CheckInput(self::ACTION, ['posts', '1'])]);

        self::assertSame(['1'], $resolver->calls);
        self::assertSame([], $resolver->bulkCalls);
    }

    /**
     * A record decided without reading `resource` is forgotten once decided, so
     * the next record of its type to read it is read for without it.
     *
     * @return void
     */
    public function testARecordDecidedIsReadForNoMore(): void
    {
        $posts = $this->posts(2);

        $this->subject();

        $provider = $this->attributes(new BulkStatusAttributes);

        Authorization::withPolicies([$this->statusPolicy()])->checkMany([new CheckInput('posts:list', $posts[0]), new CheckInput(self::ACTION, $posts[1])]);

        self::assertSame([[self::key($posts[1])]], $provider->bulkCalls);
        self::assertSame(500, CheckBatch::CHUNK_SIZE);
    }

    /**
     * A reference several checks share is read for once, across chunks too,
     * whether its provider reads in bulk or one record at a time, and kept
     * until the last check on it is decided; a record its own check alone holds
     * is still read for on its own.
     *
     * @return void
     */
    public function testAReferenceSharedByChecksIsReadForOnce(): void
    {
        $posts  = $this->posts(2);
        $shared = ResourceReference::record((new ScopedPost)->getMorphClass(), self::key($posts[0]), null, $posts[0]);
        $checks = [
            'a' => new CheckInput('posts:list', $shared),
            'b' => new CheckInput(self::ACTION, $shared),
            'c' => new CheckInput(self::ACTION, $posts[1]),
            'd' => new CheckInput(self::ACTION, $shared),
            'e' => new CheckInput(self::ACTION, $shared),
        ];

        $this->subject();
        $this->config()->set('authorization.bulk.chunk_size', 2);

        $single  = $this->attributes(new StatusAttributes);
        $allowed = ['a' => false, 'b' => true, 'c' => false, 'd' => true, 'e' => true];

        self::assertSame($allowed, \array_map(self::isAllowed(...), Authorization::withPolicies([$this->statusPolicy()])->checkMany($checks)));
        self::assertSame([self::key($posts[0]), self::key($posts[1])], $single->calls);

        $bulk = $this->attributes(new BulkStatusAttributes);

        foreach ([CheckContextFactory::class, AuthorizationManager::class, 'authorization'] as $abstract) {
            $this->app?->forgetInstance($abstract);
        }

        Authorization::clearResolvedInstance('authorization');

        self::assertSame($allowed, \array_map(self::isAllowed(...), Authorization::withPolicies([$this->statusPolicy()])->checkMany($checks)));
        self::assertSame([[self::key($posts[0])], [self::key($posts[1])]], $bulk->bulkCalls);
        self::assertSame([], $bulk->calls);
    }

    /**
     * Each record's attributes are read in the scope its own check is decided
     * in, with the other records of that scope alone: those of each tenant
     * below the request's in that tenant, those of none where the request is,
     * and those admitted from outside at platform scope, so a provider reading
     * through the tenant scope finds what it finds for each one on its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachRecordsAttributesAreReadInTheScopeItIsDecidedIn(): void
    {
        $this->app?->instance(TenantTree::class, new ClosureTenantTree);

        [$org, $first, $second, $other] = \array_map(static fn (string $id): StubTenant => StubTenant::query()->create(['id' => $id, 'name' => $id]), ['o1', 'a1', 'a2', 'o2']);

        ClosureTenantTree::add(Reference::of($org));
        ClosureTenantTree::add(Reference::of($first), Reference::of($org));
        ClosureTenantTree::add(Reference::of($second), Reference::of($org));
        ClosureTenantTree::add(Reference::of($other));

        $user = $this->subject($org);

        $user->givePermission(Permission::create(['name' => 'posts:audit']));

        $statement = static fn (string $effect, string $action, string $status): array => [
            'effect'     => $effect,
            'actions'    => [$action],
            'conditions' => ['eq' => ['resource.status' => $status]],
        ];

        $user->attachPolicy(Policy::create(['name' => 'published', 'document' => ['statements' => [$statement('allow', 'posts:view', self::PUBLISHED)]]]), null, $org, true);
        $user->attachPolicy(Policy::create(['name' => 'drafts', 'document' => ['statements' => [$statement('deny', 'posts:audit', 'draft')]]]));

        $this->app?->instance(ResourceTenantResolver::class, new DeclaredResourceTenant(new NoResourceTenant));

        $provider = new GuardedStatusAttributes;

        $this->app?->instance(GuardedStatusAttributes::class, $provider);
        $this->config()->set('authorization.attributes.resources', [(new GuardedPost)->getMorphClass() => GuardedStatusAttributes::class]);

        $post   = static fn (?StubTenant $tenant): GuardedPost => GuardedPost::query()->create([...self::ownerOf($tenant), 'status' => self::PUBLISHED]);
        $posts  = ['a1' => $post($first), 'a2' => $post($second), 'none' => $post(null), 'o2' => $post($other), 'again' => $post($first)];
        $checks = \array_map(static fn (GuardedPost $post): CheckInput => new CheckInput('posts:view', [GuardedPost::class, self::key($post)]), $posts);

        $checks['o2'] = new CheckInput('posts:audit', [GuardedPost::class, self::key($posts['o2'])]);

        $single          = \array_map(static fn (CheckInput $check): Decision => Authorization::check($check->action, $check->resource), $checks);
        $provider->calls = [];
        $decisions       = Authorization::checkMany($checks);
        $scope           = static fn (?StubTenant $tenant): string => $tenant === null ? 'platform:every' : $tenant->getMorphClass() . ':' . self::key($tenant) . ':every';

        self::assertEquals($single, $decisions);
        // Read at platform scope, the post of another tenant is not found, so
        // the deny that reads its status cannot be decided, and denies.
        self::assertSame(['a1' => true, 'a2' => true, 'none' => true, 'o2' => false, 'again' => true], \array_map(self::isAllowed(...), $decisions));
        self::assertSame([
            'many ' . self::key($posts['a1']) . ',' . self::key($posts['again']) . ' in ' . $scope($first),
            'many ' . self::key($posts['a2']) . ' in ' . $scope($second),
            'many ' . self::key($posts['none']) . ' in ' . $scope($org),
            'many ' . self::key($posts['o2']) . ' in ' . $scope(null),
        ], $provider->calls);
    }

    /**
     * What cannot be read ahead never stops a check that would not fail on its
     * own: a tenant whose place in the tree cannot be read fails the check on
     * its resource alone, when it is reached, after the checks before it are
     * decided, recorded and reported.
     *
     * @return void
     */
    public function testWhatCannotBeReadAheadFailsOnlyItsOwnCheck(): void
    {
        $tenant = StubTenant::query()->create(['id' => 't1', 'name' => 't1']);
        $user   = $this->subject($tenant);

        $this->app?->instance(TenantTree::class, new FailingTenantTree([], ['boom']));
        $this->app?->instance(ResourceTenantResolver::class, new CountingBulkTenants(['1' => null, '2' => new Reference($tenant->getMorphClass(), 'boom')]));

        $user->givePermission(Permission::create(['name' => self::ACTION]));

        Event::fake([DecisionEvaluated::class]);

        try {
            Authorization::checkMany(['a' => new CheckInput(self::ACTION, ['posts', '1']), 'b' => new CheckInput(self::ACTION, ['posts', '2'])]);

            self::fail('The check whose tenant cannot be placed throws.');
        } catch (\RuntimeException $exception) {
            self::assertSame(FailingTenantTree::MESSAGE, $exception->getMessage());
        }

        $events = self::dispatchedEvents(DecisionEvaluated::class);

        self::assertCount(1, $events);
        self::assertTrue($events[0]->isAllowed());
        self::assertSame('posts:1', $events[0]->resource);
        self::assertTrue(Authorization::lastDecision()?->isAllowed());
    }

    /**
     * A request whose tenant cannot be read stops no check that would not stop
     * on its own: checks denied before the tenant is read are decided as they
     * would be one at a time.
     *
     * @return void
     */
    public function testATenantThatCannotBeReadStopsNoCheckThatReadsNone(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($user, new \stdClass));
        $this->app?->instance(ResourceTenantResolver::class, new CountingBulkTenants);

        Authorization::clearResolvedInstance('authorization');

        $decisions = Authorization::checkMany([new CheckInput(self::ACTION, ['posts', '1']), new CheckInput(self::ACTION, ['posts', '2'])]);

        $reasons = \array_map(static fn (Decision $decision): ?DecisionReason => $decision->reason, $decisions);

        self::assertSame([DecisionReason::RESOURCE_UNRESOLVED, DecisionReason::RESOURCE_UNRESOLVED], $reasons);
    }

    /**
     * A batch reads the tenant tree as one check does: each tenant's place in
     * the tree once, however many of its checks are decided there.
     *
     * @return void
     */
    public function testABatchReadsEachTenantsPlaceInTheTreeOnce(): void
    {
        $this->app?->instance(TenantTree::class, new ClosureTenantTree);

        [$org, $account] = \array_map(static fn (string $id): StubTenant => StubTenant::query()->create(['id' => $id, 'name' => $id]), ['o1', 'a1']);

        ClosureTenantTree::add(Reference::of($org));
        ClosureTenantTree::add(Reference::of($account), Reference::of($org));

        $this->subject($org)->givePermission(Permission::create(['name' => self::ACTION]), null, $org, true);

        $posts = $this->posts(2, $account);
        $count = function (\Closure $check): int {
            $this->app?->forgetInstance(ResolvedTenant::class);

            $reads = 0;

            DB::listen(static function (QueryExecuted $query) use (&$reads): void {
                $reads += (int) \str_contains($query->sql, ClosureTenantTree::TABLE);
            });

            self::assertTrue($check());

            $this->app?->make('events')->forget(QueryExecuted::class);

            return $reads;
        };

        $one = $count(static fn (): bool => Authorization::can(self::ACTION, $posts[0]));
        $two = $count(static fn (): bool => Authorization::canEach(self::ACTION, $posts) === [true, true]);

        self::assertSame($one, $two);
    }

    /**
     * A reference given as the resource is decided as given, its tenant
     * included, and never asked about again.
     *
     * @return void
     */
    public function testAReferenceIsDecidedAsGiven(): void
    {
        $resolver = new CountingBulkTenants;
        $user     = $this->subject();

        $this->app?->instance(ResourceTenantResolver::class, $resolver);

        $user->givePermission(Permission::create(['name' => self::ACTION]), null, StubTenant::query()->create(['id' => 't1', 'name' => 't1']));

        $references = [ResourceReference::record('posts', '9', new Reference('stub_tenant', 't9')), ResourceReference::record('posts', '9')];
        $decisions  = Authorization::checkMany(\array_map(static fn (ResourceReference $reference): CheckInput => new CheckInput(self::ACTION, $reference), $references));

        self::assertSame(DecisionReason::TENANT_SCOPE, $decisions[0]->reason);
        self::assertSame(DecisionReason::NO_MATCH, $decisions[1]->reason);
        self::assertSame([], $resolver->bulkCalls);
        self::assertSame([], $resolver->calls);
    }

    /**
     * A batch that explains decides each check in explain mode, with the
     * verdict any batch gives, and adds to its evidence what it asked: the
     * action, the resource, who it was about and the scope it was asked and
     * decided in; every other batch records none.
     *
     * @return void
     */
    public function testAnExplainingBatchRecordsTheRequest(): void
    {
        $user = $this->subject();

        $user->givePermission(Permission::create(['name' => self::ACTION]));

        $posts = $this->posts(1);
        $check = new CheckInput(self::ACTION, $posts[0]);

        /** @var \Illuminate\Foundation\Application $app */
        $app      = $this->app;
        $contexts = $app->make(CheckContextFactory::class);
        $pipeline = new DecisionPipeline($app->make(PolicyEvaluator::class), $app->make(PolicyResolver::class), $contexts, new ResourcePolicyResolver, new GuardrailResolver);
        $store    = $app->make(LastDecisionStore::class);
        $resolver = $app->make(SubjectResolver::class);
        $batch    = static fn (bool $isExplaining): CheckBatch => new CheckBatch($pipeline, $store, $resolver, $app->make(Dispatcher::class), true, true, null, $isExplaining);
        $subject  = Authorization::currentSubject();

        $plain     = $batch(false)->decideOne($subject, $check);
        $explained = $batch(true)->decideOne($subject, $check);
        $request   = $explained->evidence?->request;

        self::assertNotNull($request);

        self::assertNull($plain->evidence);
        self::assertSame($plain->isAllowed(), $explained->isAllowed());
        self::assertSame($explained, $store->get());
        self::assertSame(self::ACTION, $request->action);
        self::assertSame(ResourceReferences::identifierOf(ResourceReferences::of($posts[0])), $request->resource);
        self::assertEquals(Reference::of($user), $request->decided->subject);
        self::assertEquals($store->provenance(), $request->decided);
        self::assertEquals(DecisionProvenance::of($subject), $request->requested);
        self::assertCount(1, $explained->evidence->grants ?? []);
        self::assertNull($batch(false)->decide($subject, ['a' => $check, 'b' => $check])['a']->evidence);
    }

    /**
     * Resolve the request about a new user, in the tenant given, and return the
     * user.
     *
     * @param  \Tests\Feature\Stubs\StubTenant|null  $tenant
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private function subject(?StubTenant $tenant = null): StubIdentity
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($user, $tenant));
        $this->app?->forgetInstance(AuthorizationManager::class);
        $this->app?->forgetInstance('authorization');

        Authorization::clearResolvedInstance('authorization');

        return $user;
    }

    /**
     * Create posts, alternately published and drafts, every third one published
     * again, in the tenant given.
     *
     * @param  int  $count
     * @param  \Tests\Feature\Stubs\StubTenant|null  $tenant
     * @return ($tenant is null ? list<\Tests\Fixtures\QueryScoping\ScopedPost> : list<\Tests\Fixtures\QueryScoping\TenantScopedPost>)
     */
    private function posts(int $count, ?StubTenant $tenant = null): array
    {
        $posts = [];

        for ($index = 0; $index < $count; $index++) {
            $attributes = ['title' => 'post-' . $index, 'status' => $index % 3 === 1 || $index === 3 ? 'draft' : self::PUBLISHED];

            $posts[] = $tenant === null
                ? ScopedPost::query()->create($attributes)
                : TenantScopedPost::query()->create([...$attributes, 'tenant_type' => $tenant->getMorphClass(), 'tenant_id' => $tenant->getKey()]);
        }

        return $posts;
    }

    /**
     * Register the provider for the posts' type and return it.
     *
     * @template TProvider of object
     *
     * @param  TProvider  $provider
     * @return TProvider
     */
    private function attributes(object $provider): object
    {
        $this->app?->instance($provider::class, $provider);
        $this->config()->set('authorization.attributes.resources', [
            (new ScopedPost)->getMorphClass()       => $provider::class,
            (new TenantScopedPost)->getMorphClass() => $provider::class,
        ]);

        return $provider;
    }

    /**
     * Return a policy allowing reading a published post, and listing any.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     */
    private function statusPolicy(): EvaluationPolicy
    {
        return EvaluationPolicy::fromArray(['name' => 'status', 'statements' => [
            ['effect' => 'allow', 'actions' => [self::ACTION], 'conditions' => ['eq' => ['resource.status' => self::PUBLISHED]]],
            ['effect' => 'deny', 'actions' => ['posts:list']],
        ]]);
    }

    /**
     * Return the post's key, as text.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $post
     * @return string
     */
    private static function key(Model $post): string
    {
        $key = $post->getKey();

        return \is_int($key) || \is_string($key) ? (string) $key : '';
    }

    /**
     * Return the tenant columns of a record the tenant owns, or of one with
     * none.
     *
     * @param  \Tests\Feature\Stubs\StubTenant|null  $tenant
     * @return array{tenant_type: string|null, tenant_id: mixed}
     */
    private static function ownerOf(?StubTenant $tenant): array
    {
        return ['tenant_type' => $tenant?->getMorphClass(), 'tenant_id' => $tenant?->getKey()];
    }

    /**
     * Determine whether the decision allows.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return bool
     */
    private static function isAllowed(Decision $decision): bool
    {
        return $decision->isAllowed();
    }

    /**
     * Return the configuration repository.
     *
     * @return \Illuminate\Config\Repository
     */
    private function config(): ConfigRepository
    {
        /** @var \Illuminate\Config\Repository */
        return $this->app?->make(ConfigRepository::class);
    }
}
