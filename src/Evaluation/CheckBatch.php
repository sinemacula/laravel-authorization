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
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\PrefetchedResourceTenants;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\ResourceReferences;

/**
 * Decides the checks of the authorization manager, one or many at a time (D22,
 * AUTHZ-10.3): the one path every check takes, `check()` as a batch of one.
 *
 * Each check is decided by the decision pipeline, in the order given, exactly
 * as it would be on its own: the same admission stages, the same scope and the
 * same evaluator, so its decision is the one a single check would make. A batch
 * of one is decided as it stands, reading nothing ahead and holding nothing for
 * later, so a single check costs what it did before bulk checks. What the
 * checks of a larger batch share is read once rather than for each: the subject
 * is resolved once for the batch; what the subject's grants, policies,
 * boundaries and caps, the guardrails and the resource types' policies resolve
 * to is read once in each scope the checks are decided in, through the
 * resolution cache, which keeps each scope's apart for the batch, as it keeps
 * what the tenant tree answers (see `ResolutionCache::batch()`); and, for each
 * chunk of the checks, the resources' tenants and the policies attached to the
 * records are read in bulk as the chunk starts, and the records' attributes
 * when the first check on a type reads `resource`, for the records of that type
 * still to be decided in that check's scope. A reference several checks share,
 * as every action `permissionsFor()` lists shares its one resource, has its
 * attributes read once for all of them, across chunks too. Bulk reading only
 * supplies data: a resolver or provider that cannot read in bulk is asked about
 * each resource on its own, and a resource whose data cannot be read fails its
 * own check alone, when that check is reached.
 *
 * Each check is recorded as the last decision, with its provenance, made in the
 * scope the check was decided in (see `DecisionProvenance`), and its
 * `DecisionEvaluated` dispatched, as soon as it is decided, before the next is
 * decided, so the last decision is the last check completed, a check failing
 * part way leaves the one before it, and an empty batch leaves it untouched. A
 * write made meanwhile, by a listener reacting to a decision say, empties what
 * the cache holds, so every later check reads the subject's grants, policies,
 * the policies attached to its resource and the tenant tree afresh, as it would
 * one check at a time. The resources' tenants are read for a chunk as it
 * starts, and their attributes when the first check on a type reads `resource`;
 * a change to either made after it was read is seen from the next chunk, except
 * by the later checks of a reference whose attributes they share.
 *
 * The checks are decided in chunks of `authorization.bulk.chunk_size` (500 by
 * default), and what a chunk read is released once it is decided, the
 * attributes of a shared reference once the last check on it is.
 *
 * Dispatching the events and storing the last decision are two switches. A
 * batch that does neither decides its checks the same way, through the same
 * stages, but records nothing: the last decision is left untouched and no
 * `DecisionEvaluated` is dispatched. `permissionsFor()` lists a subject's
 * actions through one, since listing them is introspection, not a check (N70);
 * the break-glass reporting of BL-70 is to define how it treats it. A batch may
 * also dispatch without storing, leaving the last decision untouched while
 * every decision is reported, or store without dispatching. A preview's listing
 * dispatches without storing (N86): each action it evaluates is reported,
 * naming both parties, and the last decision is left untouched.
 *
 * The checks of a preview are made with its previewer, which every decision's
 * provenance, and so its event and the last decision, names beside the subject
 * (see `DecisionProvenance`); any other batch names none.
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
     * @param  bool  $isDispatching
     * @param  bool  $isStoring
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $previewer
     */
    public function __construct(

        /** Decides each check. */
        private DecisionPipeline $pipeline,

        /** Holds the last decision. */
        private LastDecisionStore $lastDecisionStore,

        /** Gives the session of the request, which a decision that read an authentication requirement is recorded with. */
        private SubjectResolver $subjectResolver,

        /** Dispatches each check's decision event; null dispatches none. */
        private ?Dispatcher $events,

        /** Whether each decision's event is dispatched; false for introspection, which reports nothing. */
        private bool $isDispatching,

        /** Whether each decision is stored as the last decision; false for introspection, which leaves it untouched. */
        private bool $isStoring,

        /** Who previews the subject, for a preview's checks; null for any other. */
        private ?Reference $previewer = null,
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

        $cache = \count($inputs) > 1 ? ResolutionCache::instance() : null;

        if ($cache === null) {
            return $this->decideChunks($subject, $inputs);
        }

        return $cache->batch(fn (): array => $this->decideChunks($subject, $inputs));
    }

    /**
     * Decide the check for the subject, as it stands: its resource told through
     * the bound resolver, nothing read ahead, and the decision recorded and
     * reported. Every check takes this path or `decideChunk()`, each deciding
     * through the pipeline's `decide()` and recording through `record()`.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckInput  $check
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    public function decideOne(?Subject $subject, CheckInput $check): Decision
    {
        return $this->decideRecorded($subject, DecisionProvenance::of($subject, $this->previewer), $check, ResourceReferences::of($check->resource));
    }

    /**
     * Record and report a decision the pipeline did not make for the check, as
     * `decideOne()` records and reports the one it makes, and return it: what
     * refuses a delegated operation that conflicted on every try.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckInput  $check
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    public function recordOne(?Subject $subject, CheckInput $check, Decision $decision): Decision
    {
        return $this->record(DecisionProvenance::of($subject, $this->previewer), $check, ResourceReferences::of($check->resource), $decision);
    }

    /**
     * Decide the checks a chunk at a time, or, for one check, as it stands.
     *
     * @template TKey of array-key
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @param  array<TKey, \SineMacula\Laravel\Authorization\Evaluation\CheckInput>  $inputs
     * @return array<TKey, \SineMacula\Laravel\Authorization\Evaluation\Decision>
     *
     * @throws \Throwable
     */
    private function decideChunks(?Subject $subject, array $inputs): array
    {
        if (\count($inputs) === 1) {
            return \array_map(fn (CheckInput $check): Decision => $this->decideOne($subject, $check), $inputs);
        }

        $attributes = new ResourceAttributeBatch([], self::activeTenant());
        $holders    = self::lastHolders($inputs);
        $about      = DecisionProvenance::of($subject, $this->previewer);
        $decisions  = [];

        foreach (\array_chunk($inputs, self::chunkSize(), true) as $chunk) {
            $decisions += $this->decideChunk($subject, $about, $chunk, $attributes, $holders);
        }

        return $decisions;
    }

    /**
     * Decide each check of one chunk, having read its resources' tenants and
     * the policies attached to its records in bulk, and, as they are first
     * needed, its records' attributes, recording each decision as it is made. A
     * check whose resource could not be told throws when it is reached. A
     * record's attributes are forgotten once the last check on it is decided,
     * so a reference a later check shares keeps what was read for it.
     *
     * @template TKey of array-key
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @param  \SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance  $about
     * @param  array<TKey, \SineMacula\Laravel\Authorization\Evaluation\CheckInput>  $chunk
     * @param  \SineMacula\Laravel\Authorization\Context\ResourceAttributeBatch  $attributes
     * @param  \WeakMap<\SineMacula\Laravel\Authorization\Support\ResourceReference, array-key>  $holders
     * @return array<TKey, \SineMacula\Laravel\Authorization\Evaluation\Decision>
     *
     * @throws \Throwable
     */
    private function decideChunk(?Subject $subject, DecisionProvenance $about, array $chunk, ResourceAttributeBatch $attributes, \WeakMap $holders): array
    {
        $references = self::references($chunk);

        // Read ahead only into the cache, from which each check then reads.
        if (ResolutionCache::instance() !== null) {
            $this->pipeline->prepare($subject, $references);
        }

        $attributes->track($references);

        $decisions = [];

        foreach ($chunk as $key => $check) {
            $reference = $references[$key];

            if ($reference instanceof \Throwable) {
                throw $reference;
            }

            $decisions[$key] = $this->decideRecorded($subject, $about, $check, $reference, $attributes);

            if (!$reference instanceof ResourceReference || ($holders[$reference] ?? $key) === $key) {
                $attributes->forget($reference);
            }

            unset($references[$key]);
        }

        return $decisions;
    }

    /**
     * Decide the check on the resource for the subject, through the pipeline,
     * and record it with its provenance: who it is about, as given, made in the
     * scope it was decided in, which the pipeline's witness reads where the
     * grants are weighed, or, for a check denied before then, in the scope in
     * place, as the provenance given was read.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @param  \SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance  $about
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckInput  $check
     * @param  false|\SineMacula\Laravel\Authorization\Support\ResourceReference|null  $reference
     * @param  \SineMacula\Laravel\Authorization\Context\ResourceAttributeBatch|null  $attributes
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    private function decideRecorded(
        ?Subject $subject,
        DecisionProvenance $about,
        CheckInput $check,
        false|ResourceReference|null $reference,
        ?ResourceAttributeBatch $attributes = null,
    ): Decision {
        $provenance = $about;
        $decision   = $this->pipeline->decide($subject, $check->action, $reference, $check->context, $attributes, static function () use ($about, &$provenance): void {
            $provenance = $about->inCurrentScope();
        });

        return $this->record($provenance, $check, $reference, $decision);
    }

    /**
     * Return the key of the last check on each reference the checks were given
     * as it is, so a reference several checks share, across chunks too, is read
     * for once and forgotten only after the last of them.
     *
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Evaluation\CheckInput>  $inputs
     * @return \WeakMap<\SineMacula\Laravel\Authorization\Support\ResourceReference, array-key>
     */
    private static function lastHolders(array $inputs): \WeakMap
    {
        /** @var \WeakMap<\SineMacula\Laravel\Authorization\Support\ResourceReference, array-key> $holders */
        $holders = new \WeakMap;

        foreach ($inputs as $key => $check) {
            if (!$check->resource instanceof ResourceReference) {
                continue;
            }

            $holders[$check->resource] = $key;
        }

        return $holders;
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
     * Return the tenant the checks are decided in, which tells the scope each
     * resource's check is decided in, or null for none, or for one that cannot
     * be read, whose checks each fail on their own when they read it.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    private static function activeTenant(): ?Reference
    {
        try {
            $tenant = TenantScope::currentTenant();
        } catch (\Throwable) {
            return null;
        }

        return $tenant === null ? null : new Reference(...$tenant);
    }

    /**
     * Store the decision as the last decision, with its provenance and the
     * session of the request when it read an authentication requirement, when
     * the batch stores, and dispatch its decision event when the batch
     * dispatches and a dispatcher is available.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance  $provenance
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckInput  $check
     * @param  false|\SineMacula\Laravel\Authorization\Support\ResourceReference|null  $reference
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    private function record(DecisionProvenance $provenance, CheckInput $check, false|ResourceReference|null $reference, Decision $decision): Decision
    {
        if ($this->isStoring) {
            $this->lastDecisionStore->put($decision, $provenance, $decision->freshness === null ? null : $this->subjectResolver->resolve()?->session);
        }

        if ($this->isDispatching) {
            $this->events?->dispatch(DecisionEvaluated::of($provenance, $check->action, ResourceReferences::identifierOf($reference), $decision));
        }

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
