<?php

declare(strict_types = 1);

namespace Tests\Feature\ForgettingDecisions;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\CheckBatch;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Feature\Stubs\ChangingRequirementChecker;
use Tests\Feature\Stubs\ChangingSubjectResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\Fixtures\BulkChecks\StatusAttributes;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\TestCase;

/**
 * Feature tests for a batch of checks still running when the decisions of the
 * request are forgotten (N112): it reads ahead again from its next chunk, the
 * attributes of a reference it shares across chunks and where its checks are
 * made included, once for each time they are forgotten, and the request's
 * subject when it is about it, while a subject it was given by name, and the
 * scope a `Subject` names, are kept, and the decisions it already returned
 * stand.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckBatch::class)]
final class CheckBatchTest extends TestCase
{
    /** @var string The action the checks decide. */
    private const string ACTION = 'posts:read';

    /** @var string The action a step-up allows. */
    private const string EXPORT = 'reports:export';

    /**
     * A call made between the first two chunks has the second read the
     * attributes of the reference the checks share again, and the third keep
     * what the second read; the decisions already made stand.
     *
     * @return void
     */
    public function testACallBetweenChunksHasTheNextChunkReadAheadAgain(): void
    {
        $user     = StubIdentity::create(['id' => 'user-1']);
        $resolver = $this->resolveAs(new Subject($user, $user));
        $posts    = [ScopedPost::query()->create(['title' => 'shared', 'status' => 'published']), ScopedPost::query()->create(['title' => 'other', 'status' => 'draft'])];
        $shared   = ResourceReference::record((new ScopedPost)->getMorphClass(), self::key($posts[0]), null, $posts[0]);
        $provider = $this->attributes();
        $checks   = [
            'a' => new CheckInput(self::ACTION, $shared),
            'b' => new CheckInput(self::ACTION, $posts[1]),
            'c' => new CheckInput(self::ACTION, $shared),
            'd' => new CheckInput(self::ACTION, $posts[1]),
            'e' => new CheckInput(self::ACTION, $shared),
        ];

        $this->config()->set('authorization.bulk.chunk_size', 2);
        $this->forgetAfter(2, $resolver);

        $decisions = Authorization::withPolicies([self::statusPolicy()])->checkMany($checks);

        self::assertSame(['a' => true, 'b' => false, 'c' => true, 'd' => false, 'e' => true], self::allowed($decisions));
        self::assertSame([self::key($posts[0]), self::key($posts[1]), self::key($posts[0]), self::key($posts[1])], $provider->calls);
    }

    /**
     * Where the checks are made is read again too: once the tenant is switched
     * and the decisions forgotten between chunks, the checks of the next chunk
     * are made, and reported, in the new tenant, those already made in the old
     * one.
     *
     * @return void
     */
    public function testTheNextChunkIsMadeInTheTenantResolvedAfresh(): void
    {
        $first    = StubTenant::query()->create(['id' => 'tenant-a', 'name' => 'A']);
        $second   = StubTenant::query()->create(['id' => 'tenant-b', 'name' => 'B']);
        $user     = StubIdentity::create(['id' => 'user-1']);
        $resolver = $this->resolveAs(new Subject($user, $user, $first));
        $tenants  = [];

        $this->config()->set('authorization.bulk.chunk_size', 2);
        $this->forgetAfter(2, $resolver, new Subject($user, $user, $second));

        $this->container()->make(Dispatcher::class)->listen(DecisionEvaluated::class, static function (DecisionEvaluated $event) use (&$tenants): void {
            $tenants[] = $event->tenant?->id;
        });

        $checks = \array_fill(0, 4, new CheckInput(self::ACTION));

        self::assertSame([false, false, false, false], self::allowed(Authorization::forUser(null)->checkMany($checks)));
        self::assertSame(['tenant-a', 'tenant-a', 'tenant-b', 'tenant-b'], $tenants);
    }

    /**
     * A batch about the request's subject asks the subject resolver for it
     * again once the decisions are forgotten between chunks: the session signed
     * out meanwhile, the checks still to come are refused for want of the
     * step-up, and the last decision after the batch is the refusal, while the
     * allows already returned stand.
     *
     * @return void
     */
    public function testABatchAboutTheRequestsSubjectAsksForItAgain(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $checker = new ChangingRequirementChecker(RequirementResult::met());

        $this->container()->instance(AuthenticationRequirementChecker::class, $checker);

        $resolver = $this->resolveAs(new Subject($user, $user, null, null, 'web', 'session-1'));

        $this->config()->set('authorization.bulk.chunk_size', 2);
        $this->forgetAfter(2, $resolver, new Subject($user, $user, null, null, 'web'));

        $decisions = Authorization::withPolicies([self::requiringPolicy()])->checkMany(\array_fill(0, 4, new CheckInput(self::EXPORT)));

        self::assertSame([true, true, false, false], self::allowed($decisions));
        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, Authorization::lastDecision()?->reason);
        self::assertSame(2, $checker->calls);
    }

    /**
     * A manager from `for()` of a `Subject` naming the request's own tenant
     * keeps deciding about that subject, in that tenant, for its whole batch,
     * though the request's subject and tenant move and the decisions are
     * forgotten between chunks; the request's tenant is read afresh once the
     * batch is done.
     *
     * @return void
     */
    public function testAManagerForASubjectKeepsItsSubjectAndScope(): void
    {
        $first    = StubTenant::query()->create(['id' => 'tenant-a', 'name' => 'A']);
        $second   = StubTenant::query()->create(['id' => 'tenant-b', 'name' => 'B']);
        $user     = StubIdentity::create(['id' => 'user-1']);
        $other    = StubIdentity::create(['id' => 'user-2']);
        $scoped   = StubIdentity::create(['id' => 'user-3']);
        $resolver = $this->resolveAs(new Subject($user, $user, $first));
        $reported = [];

        $this->config()->set('authorization.bulk.chunk_size', 2);
        $this->forgetAfter(2, $resolver, new Subject($other, $other, $second));

        $this->container()->make(Dispatcher::class)->listen(DecisionEvaluated::class, static function (DecisionEvaluated $event) use (&$reported): void {
            $reported[] = [$event->subject?->id, $event->tenant?->id];
        });

        Authorization::for(new Subject($scoped, $scoped, $first))->checkMany(\array_fill(0, 4, new CheckInput(self::ACTION)));

        self::assertSame(\array_fill(0, 4, ['user-3', 'tenant-a']), $reported);
        self::assertSame('tenant-b', TenantScope::currentTenant()[1] ?? null);
    }

    /**
     * Have a listener forget the decisions once the given number of decisions
     * has been reported, after resolving the subject given, when one is.
     *
     * @param  int  $after
     * @param  \Tests\Feature\Stubs\ChangingSubjectResolver  $resolver
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @return void
     */
    private function forgetAfter(int $after, ChangingSubjectResolver $resolver, ?Subject $subject = null): void
    {
        $reported = 0;

        $this->container()->make(Dispatcher::class)->listen(DecisionEvaluated::class, static function () use (&$reported, $after, $resolver, $subject): void {
            if (++$reported !== $after) {
                return;
            }

            $resolver->subject = $subject ?? $resolver->subject;

            Authorization::forgetDecisionsFor();
        });
    }

    /**
     * Bind a resolver answering the subject, which the test may change, with
     * the manager and the tenant built afresh.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return \Tests\Feature\Stubs\ChangingSubjectResolver
     */
    private function resolveAs(Subject $subject): ChangingSubjectResolver
    {
        $resolver = new ChangingSubjectResolver($subject);
        $app      = $this->container();

        $app->instance(SubjectResolver::class, $resolver);

        foreach (['authorization', AuthorizationManager::class, CheckContextFactory::class, ResolvedTenant::class] as $abstract) {
            $app->forgetInstance($abstract);
        }

        Authorization::clearResolvedInstance('authorization');

        return $resolver;
    }

    /**
     * Bind a provider reading each post's status one record at a time, which
     * records each record it is asked about.
     *
     * @return \Tests\Fixtures\BulkChecks\StatusAttributes
     */
    private function attributes(): StatusAttributes
    {
        $provider = new StatusAttributes;

        $this->container()->instance(StatusAttributes::class, $provider);
        $this->config()->set('authorization.attributes.resources', [(new ScopedPost)->getMorphClass() => StatusAttributes::class]);

        return $provider;
    }

    /**
     * Return a policy allowing the action on a published post.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     */
    private static function statusPolicy(): EvaluationPolicy
    {
        return EvaluationPolicy::fromArray(['name' => 'status', 'statements' => [
            ['effect' => 'allow', 'actions' => [self::ACTION], 'conditions' => ['eq' => ['resource.status' => 'published']]],
        ]]);
    }

    /**
     * Return a policy allowing the export once multifactor is proved.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     */
    private static function requiringPolicy(): EvaluationPolicy
    {
        return EvaluationPolicy::fromArray(['name' => 'step-up', 'statements' => [[
            'sid'        => 'Export',
            'effect'     => 'allow',
            'actions'    => [self::EXPORT],
            'conditions' => ['authentication_requirement' => ['authentication' => ['multifactor' => ['max_age' => 900]]]],
        ]]]);
    }

    /**
     * Return whether each decision allows, keyed as the decisions are.
     *
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Evaluation\Decision>  $decisions
     * @return array<array-key, bool>
     */
    private static function allowed(array $decisions): array
    {
        return \array_map(static fn (Decision $decision): bool => $decision->isAllowed(), $decisions);
    }

    /**
     * Return the post's key as a string.
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
        return $this->container()->make('config');
    }
}
