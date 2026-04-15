<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Traits;

use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Events\PolicyAttached;
use SineMacula\Laravel\Authorization\Events\PolicyDetached;
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
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return static
     */
    public function attachPolicy(Policy $policy): static
    {
        $this->policies()->syncWithoutDetaching([$policy->getKey()]);

        if (isset($this->relations['policies'])) {
            unset($this->relations['policies']);
        }

        Event::dispatch(new PolicyAttached($this, $policy));

        return $this;
    }

    /**
     * Detach the given policy from this identity.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return static
     */
    public function detachPolicy(Policy $policy): static
    {
        $this->policies()->detach($policy->getKey());

        if (isset($this->relations['policies'])) {
            unset($this->relations['policies']);
        }

        Event::dispatch(new PolicyDetached($this, $policy));

        return $this;
    }

    /**
     * Replace the identity's attached policies with the supplied set.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Policy>  $policies
     * @return static
     */
    public function syncPolicies(array $policies): static
    {
        $ids = \array_values(\array_map(
            static fn (Policy $policy): string => (string) $policy->getKey(),
            $policies,
        ));

        $this->policies()->sync($ids);

        if (isset($this->relations['policies'])) {
            unset($this->relations['policies']);
        }

        return $this;
    }

    /**
     * Return the evaluation-ready policies attached to this identity.
     *
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    public function getPolicies(): array
    {
        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Policy> $models */
        $models = $this->policies;

        return \array_values($models
            ->map(static fn (Policy $policy): EvaluationPolicy => $policy->toEvaluationPolicy())
            ->all());
    }
}
