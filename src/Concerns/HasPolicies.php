<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Models\Pivots\AuthorizablePolicyPivot;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Resolvers\GrantResolver;
use SineMacula\Laravel\Authorization\Support\Reference;

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

        /** @var string $table */
        $table = config('authorization.tables.authorizable_policies', 'authorizable_policies');

        return $this->authorizationGrantRelation($model, $table, 'policy_id', AuthorizablePolicyPivot::class);
    }

    /**
     * Attach the given policy to this identity, through the grant service.
     *
     * Only a saved model of the shipped `Policy` class, or of any subclass of
     * it, is attached; anything else is refused.
     *
     * An optional `$expiresAt` makes the attachment temporal — the row is
     * filtered out of `$user->policies` the moment the clock passes the
     * supplied instant, without requiring a sweeper run. Passing null (the
     * default) creates a forever attachment. Attaching a policy the identity
     * holds with the same expiry changes nothing and dispatches no event; an
     * attachment that has expired is re-armed with the new expiry.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return static
     *
     * @throws \Throwable
     */
    public function attachPolicy(Policy $policy, ?\DateTimeInterface $expiresAt = null, Model|Reference|null $tenant = null): static
    {
        self::authorizationGrants()->attachPolicy($this, $policy, $expiresAt, null, $tenant);

        return $this;
    }

    /**
     * Detach the given policy from this identity, through the grant service.
     * `IdentityPolicyDetached` fires only when the policy was attached.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return static
     *
     * @throws \Throwable
     */
    public function detachPolicy(Policy $policy, Model|Reference|null $tenant = null): static
    {
        self::authorizationGrants()->detachPolicy($this, $policy, null, $tenant);

        return $this;
    }

    /**
     * Replace the identity's attached policies with the supplied set, through
     * the grant service.
     *
     * Each entry must be a saved policy model; anything else is refused with
     * `InvalidGrantTargetException` before anything is written. Each net
     * attachment fires `IdentityPolicyAttached` and each net detachment fires
     * `IdentityPolicyDetached`, mirroring the per-row signal of
     * `attachPolicy()` / `detachPolicy()`. The cache invalidation listener
     * wired to those events keeps the resolution cache coherent without a
     * separate forget call in this method. A listed policy whose attachment has
     * expired is re-armed with no expiry; to re-arm it for a limited time, call
     * `GrantService::syncPolicies()` with an expiry.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Policy>  $policies
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return static
     *
     * @throws \Throwable
     */
    public function syncPolicies(array $policies, Model|Reference|null $tenant = null): static
    {
        self::authorizationGrants()->syncPolicies($this, $policies, null, null, $tenant);

        return $this;
    }

    /**
     * Return the evaluation-ready policies attached to this identity.
     *
     * The policies are read through the resolution cache: memoised for the
     * request or job, and kept in the persistent store when one is configured,
     * for no longer than the nearest attachment expiry or the configured
     * maximum. An attachment, detachment or change to an attached policy takes
     * effect on the next check.
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
        $resolve = fn (ResolutionPins $pins): Resolution => GrantResolver::policies($this->policies(), $pins);

        return ResolutionCache::instance()?->rememberPolicies($this, $resolve) ?? $resolve(new ResolutionPins)->value;
    }
}
