<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Traits;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Events\PolicyAttached;
use SineMacula\Laravel\Authorization\Events\PolicyDetached;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Models\Policy;

/**
 * Policy attachment trait for authorizable models.
 *
 * Manages the polymorphic pivot between an identity and one or more
 * policy rows. The `getPolicies()` helper hydrates each attached row
 * into an evaluation-ready value object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 */
trait HasPolicies // @phpstan-ignore trait.unused
{
    /**
     * Morph-to-many relation onto policies.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Policy, static>
     */
    public function policies(): MorphToMany
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $model */
        $model = config('authorization.models.policy', Policy::class);

        /** @var string $pivot */
        $pivot = config('authorization.tables.authorizable_policies', 'authorizable_policies');

        return $this->morphToMany(
            related: $model,
            name: 'authorizable',
            table: $pivot,
            foreignPivotKey: 'authorizable_id',
            relatedPivotKey: 'policy_id',
        );
    }

    /**
     * Attach the given policy to this identity.
     *
     * Accepts a `Policy` instance or any Eloquent model — consumers
     * who swap the policy model via `authorization.models.policy`
     * may pass their own subclass (or a duck-typed model persisted
     * in the same pivot) without jumping through inheritance
     * hoops. The shipped `PolicyAttached` event expects a `Policy`
     * instance, so non-Policy models are attached silently; use
     * a Policy-shaped class when event wiring matters.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy|\Illuminate\Database\Eloquent\Model  $policy
     * @return static
     */
    public function attachPolicy(Policy|Model $policy): static
    {
        $this->policies()->syncWithoutDetaching([$policy->getKey()]);

        if (isset($this->relations['policies'])) {
            unset($this->relations['policies']);
        }

        if ($policy instanceof Policy) {
            Event::dispatch(new PolicyAttached($this, $policy));
        }

        return $this;
    }

    /**
     * Detach the given policy from this identity.
     *
     * Accepts a `Policy` instance or any Eloquent model — same
     * widened contract as `attachPolicy()`.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy|\Illuminate\Database\Eloquent\Model  $policy
     * @return static
     */
    public function detachPolicy(Policy|Model $policy): static
    {
        $this->policies()->detach($policy->getKey());

        if (isset($this->relations['policies'])) {
            unset($this->relations['policies']);
        }

        if ($policy instanceof Policy) {
            Event::dispatch(new PolicyDetached($this, $policy));
        }

        return $this;
    }

    /**
     * Replace the identity's attached policies with the supplied set.
     *
     * Accepts `Policy` instances or any Eloquent model — same
     * widened contract as `attachPolicy()`.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Policy|\Illuminate\Database\Eloquent\Model>  $policies
     * @return static
     */
    public function syncPolicies(array $policies): static
    {
        $ids = \array_values(\array_map(
            static fn (Policy|Model $policy): string => (string) $policy->getKey(),
            $policies,
        ));

        $this->policies()->sync($ids);

        if (isset($this->relations['policies'])) {
            unset($this->relations['policies']);
        }

        // sync() bypasses attachPolicy / detachPolicy and so fires
        // no PolicyAttached / PolicyDetached events — invalidate
        // the resolution cache directly so the next evaluation
        // observes the fresh policy set.
        if (app()->bound(ResolutionCache::class)) {
            app(ResolutionCache::class)->forget($this);
        }

        return $this;
    }

    /**
     * Return the evaluation-ready policies attached to this identity.
     *
     * A single malformed row must not short-circuit the entire
     * evaluation — §12.3 mandates "fail closed (denied)" rather
     * than "fail loud (500)". Each hydration runs inside its own
     * try/catch: the offending row is logged through the
     * `authorization` channel (or Laravel's default if the
     * channel is unconfigured) and skipped. An excluded `ALLOW`
     * cannot win, so the net decision stays deny-biased.
     *
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    public function getPolicies(): array
    {
        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Policy> $models */
        $models = $this->policies;

        $hydrated = [];

        foreach ($models as $policy) {
            try {
                $hydrated[] = $policy->toEvaluationPolicy();
            } catch (InvalidPolicyDocumentException $exception) {
                self::logMalformedPolicy($policy, $exception);
            }
        }

        return \array_values($hydrated);
    }

    /**
     * Report a malformed policy row without raising — the engine
     * stays fail-closed because the bad row is excluded from the
     * evaluation set.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \SineMacula\Laravel\Authorization\Exceptions\InvalidPolicyDocumentException  $exception
     * @return void
     */
    private static function logMalformedPolicy(Policy $policy, InvalidPolicyDocumentException $exception): void
    {
        if (!\function_exists('logger')) {
            return;
        }

        try {
            /** @var \Illuminate\Log\LogManager $logger */
            $logger  = logger();
            $channel = null;

            try {
                $channel = $logger->channel('authorization');
            } catch (\Throwable) {
                $channel = $logger;
            }

            $channel->warning(
                "Authorization: skipping malformed policy '{$policy->getKey()}' — " . $exception->getMessage(),
                [
                    'policy_id'   => (string) $policy->getKey(),
                    'policy_name' => (string) ($policy->name ?? ''),
                    'reason'      => $exception->getMessage(),
                ],
            );
        } catch (\Throwable) {
            // Logging failures are not allowed to abort the check.
        }
    }
}
