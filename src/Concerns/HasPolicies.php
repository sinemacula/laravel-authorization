<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Concerns;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyAttached as IdentityPolicyAttached;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyDetached as IdentityPolicyDetached;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyExpiryChanged as IdentityPolicyExpiryChanged;
use SineMacula\Laravel\Authorization\Models\Pivots\AuthorizablePolicyPivot;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Support\AuthorizationLog;

/**
 * Policy attachment trait for authorizable models.
 *
 * Manages the polymorphic pivot between an identity and one or more policy
 * rows. The `getPolicies()` helper hydrates each attached row into an
 * evaluation-ready value object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authorization\Contracts\SupportsPolicies
 */
trait HasPolicies // @phpstan-ignore trait.unused
{
    use ResolvesPivotExpiry;

    /**
     * Morph-to-many relation onto policies.
     *
     * Filters out pivot rows whose `expires_at` is in the past — temporal
     * policy attachments disappear from the relation automatically at expiry
     * without requiring a sweeper run. The pivot's `expires_at` column is
     * surfaced via `withPivot()`, and the attachment's timestamps are kept. The
     * scope columns keep their defaults: every attachment made here is
     * platform-wide, for every application.
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Policy, $this,
     *     \SineMacula\Laravel\Authorization\Models\Pivots\AuthorizablePolicyPivot, 'pivot'>
     *
     * @formatter:on
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     */
    public function policies(): MorphToMany
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $model */
        $model = config('authorization.models.policy', Policy::class);

        /** @var string $pivot */
        $pivot = config('authorization.tables.authorizable_policies', 'authorizable_policies');

        // The `where(...)` and inner `whereNull()/orWhere()` calls are resolved
        // by PHPStan to static methods on Eloquent's Builder via Laravel's
        // annotation soup — the underlying dispatch is instance-level. Same
        // pattern, same justification, as `GuardScopedLookup`.
        // @phpstan-ignore staticMethod.dynamicCall
        return $this->morphToMany(
            related: $model,
            name: 'authorizable',
            table: $pivot,
            foreignPivotKey: 'authorizable_id',
            relatedPivotKey: 'policy_id',
        )
            ->using(AuthorizablePolicyPivot::class)
            ->withPivot('expires_at')
            ->withTimestamps()
            ->where(static function (Builder $query) use ($pivot): void {
                // @phpstan-ignore staticMethod.dynamicCall
                $query->whereNull($pivot . '.expires_at')
                    ->orWhere($pivot . '.expires_at', '>', Carbon::now());
            });
    }

    /**
     * Attach the given policy to this identity.
     *
     * Accepts a `Policy` instance or any Eloquent model — consumers who swap
     * the policy model via `authorization.models.policy` may pass their own
     * subclass (or a duck-typed model persisted in the same pivot) without
     * jumping through inheritance hoops. The shipped `IdentityPolicyAttached`
     * event expects a `Policy` instance, so non-Policy models are attached
     * silently; use a Policy-shaped class when event wiring matters.
     *
     * An optional `$expiresAt` makes the attachment temporal — the row is
     * filtered out of `$user->policies` the moment the clock passes the
     * supplied instant, without requiring a sweeper run. Passing null (the
     * default) creates a forever attachment.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \DateTimeInterface|null  $expiresAt
     * @return static
     */
    public function attachPolicy(Model|Policy $policy, ?\DateTimeInterface $expiresAt = null): static
    {
        $prior = self::authorizationReadGrantPivot($this, $this->policies()->newPivotStatement(), 'policy_id', (string) $policy->getKey());

        $this->policies()->syncWithoutDetaching([
            (string) $policy->getKey() => ['expires_at' => $expiresAt],
        ]);

        if (isset($this->relations['policies'])) {
            unset($this->relations['policies']);
        }

        if ($policy instanceof Policy) {
            Event::dispatch(new IdentityPolicyAttached($this, $policy));

            if ($prior['exists'] && !self::areAuthorizationGrantExpiriesEqual($prior['expires_at'], $expiresAt)) {
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
     * Accepts a `Policy` instance or any Eloquent model — same widened contract
     * as `attachPolicy()`.
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
     * Accepts `Policy` instances or any Eloquent model — same widened contract
     * as `attachPolicy()`.
     *
     * Each net attachment fires `IdentityPolicyAttached` and each net
     * detachment fires `IdentityPolicyDetached` for Policy-shaped rows,
     * mirroring the per-row signal of `attachPolicy()` / `detachPolicy()`. The
     * cache invalidation listener wired to those events keeps the resolution
     * cache coherent without a separate forget call in this method. Non-Policy
     * models are still synced silently — the events carry a `Policy` instance
     * by contract, so detached IDs that resolve to a non-Policy model (or
     * nothing) are skipped without raising.
     *
     * @formatter:off
     *
     * @param  array<int, \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Models\Policy>  $policies
     *
     * @formatter:on
     *
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

        foreach ($result['attached'] as $id) {
            $model = $resolved[(string) $id] ?? $this->lookupPolicyById((string) $id);

            if (!($model instanceof Policy)) {
                continue;
            }

            Event::dispatch(new IdentityPolicyAttached($this, $model));
        }

        foreach ($result['detached'] as $id) {
            $model = $this->lookupPolicyById((string) $id);

            if (!($model instanceof Policy)) {
                continue;
            }

            Event::dispatch(new IdentityPolicyDetached($this, $model));
        }

        return $this;
    }

    /**
     * Return the evaluation-ready policies attached to this identity.
     *
     * A row whose document cannot be read is never skipped, because skipping it
     * would also drop its denies. The row is logged and the exception is
     * rethrown; the authorization manager turns it into a denial of the check
     * with the `invalid_policy` reason, so every check for this identity denies
     * until the document is fixed.
     *
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
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

                throw $exception;
            }
        }

        return $hydrated;
    }

    /**
     * Return the seconds until the nearest attached policy lapses, or null when
     * none of them expires.
     *
     * The caching policy resolver bounds its entries by this, as `getRoles()`
     * and `getPermissions()` bound theirs, so a temporary policy stops applying
     * when it lapses. With `$reload`, which the resolver passes once its entry
     * has lapsed, the attachments are read afresh rather than from the relation
     * already loaded on this instance.
     *
     * @param  bool  $reload
     * @return int|null
     */
    public function secondsUntilPolicyExpiry(bool $reload = false): ?int
    {
        if ($reload) {
            $this->unsetRelation('policies');
        }

        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Policy> $models */
        $models = $this->policies;

        return self::authorizationNearestPivotExpirySeconds($models);
    }

    /**
     * Look up a policy model by primary key, used by `syncPolicies()` when the
     * sync delta surfaces an ID that was not part of the caller's input set
     * (the detachment list). Returns null when the row no longer exists or
     * resolves to a non-Policy model — both branches are handled by the caller
     * as "skip the event.".
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Models\Policy|null
     */
    private function lookupPolicyById(string $id): ?Policy
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $class */
        $class = config('authorization.models.policy', Policy::class);

        $model = $class::query()->whereKey($id)->first();

        return $model instanceof Policy ? $model : null;
    }

    /**
     * Report a malformed policy row. Logging never raises; the caller rethrows
     * so the check denies.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException  $exception
     * @return void
     */
    private static function logMalformedPolicy(Policy $policy, InvalidPolicyDocumentException $exception): void
    {
        AuthorizationLog::warning(
            "Authorization: malformed policy '{$policy->getKey()}' denies every check for its holder: " . $exception->getMessage(),
            [
                'policy_id'   => (string) $policy->getKey(),
                'policy_name' => $policy->name ?? '',
                'reason'      => $exception->getMessage(),
            ],
        );
    }
}
