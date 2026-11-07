<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Context\ResourceAttributeBatch;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\PrefetchedResourceTenants;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\ResourceReferences;

/**
 * Decides the checks of the authorization manager, one or many at a time (D22,
 * AUTHZ-10.3): the one path every check takes, `check()` as a batch of one.
 *
 * Each check is decided by the decision pipeline, in the order given, exactly
 * as it would be on its own: the same admission stages, the same scope and the
 * same evaluator, so its decision is the one a single check would make. What
 * the checks share is read once rather than for each: the subject is resolved
 * once for the batch; what the subject's grants, policies, boundaries and caps,
 * the guardrails and the resource types' policies resolve to is read once in
 * each scope the checks are decided in, through the resolution cache, which
 * keeps each scope's apart for the batch (see `ResolutionCache::batch()`); and,
 * for each chunk of the checks, the resources' tenants, the policies attached
 * to the records and the records' attributes are read in bulk. Bulk reading
 * only supplies data: a resolver or provider that cannot read in bulk is asked
 * about each resource on its own, and a resource whose data cannot be read
 * fails its own check alone, when that check is reached.
 *
 * Each check is recorded as the last decision, and its `DecisionEvaluated`
 * dispatched, as soon as it is decided, before the next is decided, so the last
 * decision is the last check completed, a check failing part way leaves the one
 * before it, and an empty batch leaves it untouched. A write made meanwhile, by
 * a listener reacting to a decision say, empties what the cache holds, so every
 * later check reads the subject's grants, policies and the policies attached to
 * its resource afresh, as it would one check at a time. The resources' tenants
 * and attributes are read for a chunk as it starts, and a change to them made
 * while it is decided is seen from the next chunk.
 *
 * The checks are decided in chunks of `authorization.bulk.chunk_size` (500 by
 * default), and what a chunk read is released once it is decided.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CheckBatch
{
    /** @var int How many checks a chunk holds when the configuration sets none. */
    public const int CHUNK_SIZE = 500;

    /**
     * Create a new batch of checks.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\DecisionPipeline  $pipeline
     * @param  \SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore  $lastDecisionStore
     * @param  \SineMacula\Laravel\Authorization\Contracts\SubjectResolver  $subjectResolver
     * @param  \Illuminate\Contracts\Events\Dispatcher|null  $events
     */
    public function __construct(

        /** Decides each check. */
        private DecisionPipeline $pipeline,

        /** Holds the last decision. */
        private LastDecisionStore $lastDecisionStore,

        /** Gives the session of the request, which a decision that read an authentication requirement is recorded with. */
        private SubjectResolver $subjectResolver,

        /** Dispatches each check's decision event; null dispatches none. */
        private ?Dispatcher $events = null,
    ) {}

    /**
     * Decide each check for the subject, in the order given, and return the
     * decisions keyed as the checks are. Every check is refused before any is
     * decided when one is not a `CheckInput`.
     *
     * @template TKey of array-key
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @param  array<TKey, mixed>  $checks
     * @return array<TKey, \SineMacula\Laravel\Authorization\Evaluation\Decision>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    public function decide(?Subject $subject, array $checks): array
    {
        $inputs = [];

        foreach ($checks as $key => $check) {
            $inputs[$key] = $check instanceof CheckInput ? $check : throw InvalidCheckArgumentException::notACheck($key);
        }

        $decide = function () use ($subject, $inputs): array {
            $decisions = [];

            foreach (\array_chunk($inputs, self::chunkSize(), true) as $chunk) {
                $decisions += $this->decideChunk($subject, $chunk);
            }

            return $decisions;
        };

        $cache = $inputs === [] ? null : ResolutionCache::instance();

        return $cache === null ? $decide() : $cache->batch($decide);
    }

    /**
     * Decide each check of one chunk, having read its resources' tenants, the
     * policies attached to its records and, as they are first needed, its
     * records' attributes in bulk, recording each decision as it is made. A
     * check whose resource could not be told throws when it is reached.
     *
     * @template TKey of array-key
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @param  array<TKey, \SineMacula\Laravel\Authorization\Evaluation\CheckInput>  $chunk
     * @return array<TKey, \SineMacula\Laravel\Authorization\Evaluation\Decision>
     *
     * @throws \Throwable
     */
    private function decideChunk(?Subject $subject, array $chunk): array
    {
        $references = self::references($chunk);

        // A check on its own reads exactly what it would read ahead.
        if (\count($chunk) > 1 && ResolutionCache::instance() !== null) {
            $this->pipeline->prepare($subject, $references);
        }

        $attributes = new ResourceAttributeBatch($references);
        $decisions  = [];

        foreach ($chunk as $key => $check) {
            $reference = $references[$key];

            if ($reference instanceof \Throwable) {
                throw $reference;
            }

            $decisions[$key] = $this->record($subject, $check, $reference, $this->pipeline->decide($subject, $check->action, $reference, $check->context, $attributes));

            $attributes->forget($reference);
            unset($references[$key]);
        }

        return $decisions;
    }

    /**
     * Return the reference to each check's resource, keyed as the checks are,
     * with the tenants of the chunk's models and records read in bulk, or what
     * telling it threw, for its check to throw when it is reached.
     *
     * @template TKey of array-key
     *
     * @param  array<TKey, \SineMacula\Laravel\Authorization\Evaluation\CheckInput>  $chunk
     * @return array<TKey, false|\SineMacula\Laravel\Authorization\Support\ResourceReference|\Throwable|null>
     */
    private static function references(array $chunk): array
    {
        $container = Container::getInstance();

        /** @var \SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver|null $resolver */
        $resolver = $container->bound(ResourceTenantResolver::class) ? $container->make(ResourceTenantResolver::class) : null;
        $tenants  = $resolver === null ? null : PrefetchedResourceTenants::of(\array_map(static fn (CheckInput $check): mixed => $check->resource, $chunk), $resolver);

        $references = [];

        foreach ($chunk as $key => $check) {
            $references[$key] = self::attempt(static fn (): false|ResourceReference|null => ResourceReferences::of($check->resource, $tenants));
        }

        return $references;
    }

    /**
     * Return what the callback returns, or what it throws, so a check whose
     * resource cannot be told throws when it is reached rather than before.
     *
     * @param  \Closure(): (false|\SineMacula\Laravel\Authorization\Support\ResourceReference|null)  $tell
     * @return false|\SineMacula\Laravel\Authorization\Support\ResourceReference|\Throwable|null
     */
    private static function attempt(\Closure $tell): false|ResourceReference|\Throwable|null
    {
        try {
            return $tell();
        } catch (\Throwable $exception) {
            return $exception;
        }
    }

    /**
     * Record the decision as the last decision, with the session of the request
     * when it read an authentication requirement, and dispatch its decision
     * event when a dispatcher is available.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckInput  $check
     * @param  false|\SineMacula\Laravel\Authorization\Support\ResourceReference|null  $reference
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    private function record(?Subject $subject, CheckInput $check, false|ResourceReference|null $reference, Decision $decision): Decision
    {
        $this->lastDecisionStore->put($decision, $decision->freshness === null ? null : $this->subjectResolver->resolve()?->session);
        $this->events?->dispatch(new DecisionEvaluated($subject?->subject, $check->action, ResourceReferences::identifierOf($reference), $check->context, $decision));

        return $decision;
    }

    /**
     * Return how many checks a chunk holds: `authorization.bulk.chunk_size`, or
     * 500 when it sets none.
     *
     * @return int
     */
    private static function chunkSize(): int
    {
        $container = Container::getInstance();
        $size      = $container->bound('config') ? $container->make('config')->get('authorization.bulk.chunk_size', self::CHUNK_SIZE) : self::CHUNK_SIZE;

        return \is_int($size) && $size > 0 ? $size : self::CHUNK_SIZE;
    }
}
