<?php

declare(strict_types = 1);

namespace Tests\Feature\Evaluation;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\CheckBatch;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed;
use SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\Fixtures\BulkChecks\BulkStatusAttributes;
use Tests\Fixtures\BulkChecks\CountingBulkTenants;
use Tests\Fixtures\BulkChecks\StatusAttributes;
use Tests\Fixtures\QueryScoping\ScopedPost;
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
     * a check repeated included, with the check's action, resource and context,
     * as `check()` dispatches it.
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
        self::assertSame(['flag' => 'on'], $events[0]->context);
        self::assertFalse($events[1]->decision->isAllowed());
        self::assertSame($user, $events[0]->principal);
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
        self::assertSame($events[0]->decision, $manager->lastDecision());
        self::assertSame([self::key($posts[0]), self::key($posts[1])], $provider->calls);
        self::assertTrue($events[0]->decision->isAllowed());
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
     * time, the decisions keyed and ordered as the checks are across chunks; a
     * size that is not a whole number of at least 1 takes the default.
     *
     * @return void
     */
    public function testTheChecksAreDecidedInChunks(): void
    {
        $posts = $this->posts(5);

        $this->subject();

        $provider  = $this->attributes(new BulkStatusAttributes);
        $resources = ['e' => $posts[4], 'a' => $posts[0], 'd' => $posts[3], 'b' => $posts[1], 'c' => $posts[2]];

        $this->config()->set('authorization.bulk.chunk_size', 2);

        $allowed = Authorization::withPolicies([$this->statusPolicy()])->canEach(self::ACTION, $resources);

        self::assertSame(['e' => false, 'a' => true, 'd' => false, 'b' => false, 'c' => true], $allowed);

        $this->config()->set('authorization.bulk.chunk_size', 0);

        self::assertSame($allowed, Authorization::withPolicies([$this->statusPolicy()])->canEach(self::ACTION, $resources));
        self::assertSame([2, 2, 1, 5], \array_map(\count(...), $provider->bulkCalls));
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
