<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Models\Pivots\AuthorizablePolicyPivot;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Resolvers\GrantResolver;
use SineMacula\Laravel\Authorization\Services\PolicyService;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\RolePolicies;

/**
 * Policy attachment trait for authorizable models and roles.
 *
 * Manages the polymorphic pivot between a grantee, an identity or a role, and
 * one or more policy rows. The `getPolicies()` helper hydrates each attached
 * row into an evaluation-ready value object; an identity that holds roles also
 * gets the policies attached to those roles and to the roles above them
 * (AUTHZ-7.2).
 *
 * A grantee may own inline policies (`createInlinePolicy()`), attached to it
 * alone. They are deleted once the model is deleted; a model that soft-deletes
 * keeps them until it is force-deleted (AUTHZ-6.9).
 *
 * Each write helper takes an optional `actor:`, an acting context it hands to
 * the service, so the change is delegated and decided as that actor
 * (AUTHZ-11.1). Without one it is trusted system work: nothing is decided, so a
 * helper called without an actor is an integration surface for the
 * application's own code, never an endpoint for user-controlled administration.
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
     * surfaced via `withPivot()`, and the attachment's timestamps are kept.
     * Only the attachments that hold in the current tenant and application
     * count.
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
     * Attach the given policy to this grantee, through the grant service.
     *
     * Only a saved model of the shipped `Policy` class, or of any subclass of
     * it, is attached; anything else is refused, as is an inline policy that
     * belongs to another grantee.
     *
     * An optional `$expiresAt` makes the attachment temporal — the row is
     * filtered out of `$user->policies` the moment the clock passes the
     * supplied instant, without requiring a sweeper run. Passing null (the
     * default) creates a forever attachment. Attaching a policy the grantee
     * holds with the same expiry and reach changes nothing and dispatches no
     * event; an attachment that has expired is re-armed with the new expiry.
     *
     * A grant in a tenant also holds in the tenants below it in the tenant
     * tree, unless `$includeSubtree` is false.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @param  string|null  $application
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return static
     *
     * @throws \Throwable
     */
    public function attachPolicy(
        Policy $policy,
        ?\DateTimeInterface $expiresAt = null,
        Model|Reference|null $tenant = null,
        bool $includeSubtree = true,
        ?string $application = null,
        ?ActingContext $actor = null,
    ): static {
        self::authorizationGrants()->attachPolicy($this, $policy, $expiresAt, $actor, $tenant, $includeSubtree, $application);

        return $this;
    }

    /**
     * Detach the given policy from this grantee, through the grant service.
     * `IdentityPolicyDetached` fires only when the policy was attached.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string|null  $application
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return static
     *
     * @throws \Throwable
     */
    public function detachPolicy(Policy $policy, Model|Reference|null $tenant = null, ?string $application = null, ?ActingContext $actor = null): static
    {
        self::authorizationGrants()->detachPolicy($this, $policy, $actor, $tenant, $application);

        return $this;
    }

    /**
     * Replace the grantee's attached policies with the supplied set, through
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
     * @param  string|null  $application
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return static
     *
     * @throws \Throwable
     */
    public function syncPolicies(array $policies, Model|Reference|null $tenant = null, ?string $application = null, ?ActingContext $actor = null): static
    {
        self::authorizationGrants()->syncPolicies($this, $policies, actor: $actor, tenant: $tenant, application: $application);

        return $this;
    }

    /**
     * Create an inline policy that belongs to this grantee, through the policy
     * service, validated as any policy's document is. The policy is attached to
     * this grantee alone and deleted with it; creating it does not attach it,
     * so attach it with `attachPolicy()`, in the scope it holds in.
     *
     * @param  string  $name
     * @param  array<array-key, mixed>|string  $document
     * @param  string|null  $description
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     *
     * @throws \Throwable
     */
    public function createInlinePolicy(string $name, array|string $document, ?string $description = null): Policy
    {
        return self::authorizationPolicies()->createInline($this, $name, $document, $description);
    }

    /**
     * Return the evaluation-ready policies attached to this grantee, and, for
     * an identity that holds roles, those attached to its roles and to the
     * roles above them, each within both grants' scopes.
     *
     * The policies are read through the resolution cache: memoised for the
     * request or job, and kept in the persistent store when one is configured,
     * for no longer than the nearest expiry of an attachment, or of a grant of
     * a role a policy is held through, or the configured maximum. An
     * attachment, detachment or change to an attached policy takes effect on
     * the next check.
     *
     * A row whose document cannot be read is never skipped, because skipping it
     * would also drop its denies. The row is logged and the exception is
     * rethrown; the authorization manager turns it into a denial of the check
     * with the `invalid_policy` reason, so every check for this grantee denies
     * until the document is fixed.
     *
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    public function getPolicies(): array
    {
        $resolve = fn (ResolutionPins $pins): Resolution => GrantResolver::policies($this->policies(), $pins, RolePolicies::heldBy($this));

        return ResolutionCache::instance()?->rememberPolicies($this, $resolve) ?? $resolve(new ResolutionPins)->value;
    }

    /**
     * Delete the grantee's inline policies once the model is deleted, each
     * reported as deleted, with its attachments. A soft delete keeps them.
     *
     * @return void
     */
    protected static function bootHasPolicies(): void
    {
        static::deleted(static function (self $model): void {
            if (!InlinePolicies::isDeletedForGood($model)) {
                return;
            }

            InlinePolicies::deleteOwnedBy($model);
        });
    }

    /**
     * Return the policy service inline policies are created through, as the
     * container binds it.
     *
     * @return \SineMacula\Laravel\Authorization\Services\PolicyService
     *
     * @throws \LogicException
     */
    private static function authorizationPolicies(): PolicyService
    {
        return PolicyService::instance() ?? throw new \LogicException('The authorization policy service is not bound; register the package\'s service provider.');
    }
}
