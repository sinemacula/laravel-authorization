<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Traits;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Events\IdentityPolicyAttached;
use SineMacula\Laravel\Authorization\Events\IdentityPolicyDetached;
use SineMacula\Laravel\Authorization\Events\IdentityPolicyExpiryChanged;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Models\AuthorizablePolicyPivot;
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
    use ResolvesPivotExpiry;

    /**
     * Morph-to-many relation onto policies.
     *
     * Filters out pivot rows whose `expires_at` is in the past —
     * temporal policy attachments disappear from the relation
     * automatically at expiry without requiring a sweeper run.
     * The pivot's `expires_at` column is surfaced via
     * `withPivot()`.
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
        )
            ->using(AuthorizablePolicyPivot::class)
            ->withPivot('expires_at')
            ->where(static function ($query) use ($pivot): void {
                $query->whereNull($pivot . '.expires_at')
                    ->orWhere($pivot . '.expires_at', '>', Carbon::now());
            });
    }

    /**
     * Attach the given policy to this identity.
     *
     * Accepts a `Policy` instance or any Eloquent model — consumers
     * who swap the policy model via `authorization.models.policy`
     * may pass their own subclass (or a duck-typed model persisted
     * in the same pivot) without jumping through inheritance
     * hoops. The shipped `IdentityPolicyAttached` event expects a `Policy`
     * instance, so non-Policy models are attached silently; use
     * a Policy-shaped class when event wiring matters.
     *
     * An optional `$expiresAt` makes the attachment temporal — the
     * row is filtered out of `$user->policies` the moment the
     * clock passes the supplied instant, without requiring a
     * sweeper run. Passing null (the default) creates a forever
     * attachment.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \DateTimeInterface|null  $expiresAt
     * @return static
     */
    public function attachPolicy(Model|Policy $policy, ?\DateTimeInterface $expiresAt = null): static
    {
        /** @var string $table */
        $table   = config('authorization.tables.authorizable_policies', 'authorizable_policies');
        $columns = self::authorizationResolveGrantPivotColumns('authorizable_policies', 'policy_column', 'policy_id');
        $prior   = $this->authorizationReadGrantPivot($table, $columns, (string) $policy->getKey());

        $this->policies()->syncWithoutDetaching([
            (string) $policy->getKey() => ['expires_at' => $expiresAt],
        ]);

        if (isset($this->relations['policies'])) {
            unset($this->relations['policies']);
        }

        if ($policy instanceof Policy) {
            Event::dispatch(new IdentityPolicyAttached($this, $policy));

            if ($prior['exists'] && !self::authorizationGrantExpiriesEqual($prior['expires_at'], $expiresAt)) {
                Event::dispatch(new IdentityPolicyExpiryChanged(
                    $this,
                    $policy,
                    $prior['expires_at'],
                    $expiresAt,
                ));
            }
        }

        return $this;
    }

    /**
     * Detach the given policy from this identity.
     *
     * Accepts a `Policy` instance or any Eloquent model — same
     * widened contract as `attachPolicy()`.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return static
     */
    public function detachPolicy(Model|Policy $policy): static
    {
        $this->policies()->detach($policy->getKey());

        if (isset($this->relations['policies'])) {
            unset($this->relations['policies']);
        }

        if ($policy instanceof Policy) {
            Event::dispatch(new IdentityPolicyDetached($this, $policy));
        }

        return $this;
    }

    /**
     * Replace the identity's attached policies with the supplied set.
     *
     * Accepts `Policy` instances or any Eloquent model — same
     * widened contract as `attachPolicy()`.
     *
     * Each net attachment fires `IdentityPolicyAttached` and
     * each net detachment fires `IdentityPolicyDetached` for
     * Policy-shaped rows, mirroring the per-row signal of
     * `attachPolicy()` / `detachPolicy()`. The cache invalidation
     * listener wired to those events keeps the resolution cache
     * coherent without a separate forget call in this method.
     * Non-Policy models are still synced silently — the events
     * carry a `Policy` instance by contract, so detached IDs
     * that resolve to a non-Policy model (or nothing) are
     * skipped without raising.
     *
     * @param  array<int, \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Models\Policy>  $policies
     * @return static
     */
    public function syncPolicies(array $policies): static
    {
        $resolved = [];

        foreach ($policies as $policy) {
            $resolved[(string) $policy->getKey()] = $policy;
        }

        $ids    = \array_keys($resolved);
        $result = $this->policies()->sync($ids);

        if (isset($this->relations['policies'])) {
            unset($this->relations['policies']);
        }

        /** @var array{attached?: array<int, mixed>, detached?: array<int, mixed>, updated?: array<int, mixed>} $result */
        foreach ($result['attached'] ?? [] as $id) {
            $model = $resolved[(string) $id] ?? $this->lookupPolicyById((string) $id);

            if ($model instanceof Policy) {
                Event::dispatch(new IdentityPolicyAttached($this, $model));
            }
        }

        foreach ($result['detached'] ?? [] as $id) {
            $model = $this->lookupPolicyById((string) $id);

            if ($model instanceof Policy) {
                Event::dispatch(new IdentityPolicyDetached($this, $model));
            }
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
     * Look up a policy model by primary key, used by
     * `syncPolicies()` when the sync delta surfaces an ID that
     * was not part of the caller's input set (the detachment
     * list). Returns null when the row no longer exists or
     * resolves to a non-Policy model — both branches are
     * handled by the caller as "skip the event.".
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Models\Policy|null
     */
    private function lookupPolicyById(string $id): ?Policy
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $class */
        $class = config('authorization.models.policy', Policy::class);

        /** @var \SineMacula\Laravel\Authorization\Models\Policy|null $model */
        return $class::query()->whereKey($id)->first();
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
