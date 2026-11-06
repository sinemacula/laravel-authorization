<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Observers;

use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Events\Policy\Created as PolicyCreated;
use SineMacula\Laravel\Authorization\Events\Policy\Deleted as PolicyDeleted;
use SineMacula\Laravel\Authorization\Events\Policy\Updated as PolicyUpdated;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Observers\Support\RecordChanges;
use SineMacula\Laravel\Authorization\Support\DocumentDigest;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\PolicyBoundaries;
use SineMacula\Laravel\Authorization\Support\PolicyPrincipals;
use SineMacula\Laravel\Authorization\Support\RecordOwner;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Row-lifecycle observer for the `Policy` model.
 *
 * Translates Eloquent's native `updating` / `created` / `updated` / `deleting`
 * / `deleted` events into the package's typed record events and enforces the
 * tenant-columns both-or-neither invariant on save. System-protection hooks
 * (`deleting`, `updating` guard, `saved` bypass reset) live in
 * `HasSystemProtection::bootHasSystemProtection()` and run independently of
 * this observer.
 *
 * The events are snapshots of plain values, dispatched once the write commits
 * on the package's connection, and carry the operation the write belongs to:
 * the management service call that made it, with its actor, or a write of its
 * own with no actor. The document is reported by its version and digest, never
 * its body, and a delete reads, before the row goes, every grantee the policy
 * was attached to. A policy in use as a permission boundary is never deleted:
 * the delete is refused until every boundary it is has been removed.
 *
 * A policy is owned by the platform (both tenant columns null) or by one tenant
 * (both set), as roles and permissions are. Unlike theirs, policy reads are not
 * yet filtered by the current tenant.
 *
 * Registered via `#[ObservedBy(PolicyObserver::class)]` on the `Policy` model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PolicyObserver
{
    /**
     * Enforce the owner rules before any persistence: both tenant columns or
     * neither, and a tenant fixed once the policy is created (see
     * `RecordOwner`); likewise both owner columns or neither, the grantee an
     * inline policy belongs to fixed once it is created, and an inline policy
     * never a system one (see `InlinePolicies`); and a rewritten document that
     * keeps the `principals` rule for where the policy is attached (see
     * `PolicyPrincipals`).
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPolicyOwnerException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\OwnerChangedException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\SystemInlinePolicyException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\ResourcePolicyException
     */
    public function saving(Policy $policy): void
    {
        RecordOwner::assertValid($policy, 'policy');
        InlinePolicies::assertValid($policy);
        PolicyPrincipals::assertRewritable($policy);
    }

    /**
     * Capture the changed fields' values before the update, other than the
     * document, and the digest of the document it replaces when it is
     * rewritten, so the paired `updated` hook can report the change.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return void
     */
    public function updating(Policy $policy): void
    {
        RecordChanges::capture($policy, ['document']);
        RecordChanges::hold($policy, [
            'document' => $policy->isDirty('document') ? self::digest($policy->getOriginal('document')) : null,
        ]);
    }

    /**
     * Report the policy created.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return void
     */
    public function created(Policy $policy): void
    {
        OperationScope::dispatch(new PolicyCreated(
            OperationScope::current($policy),
            Reference::of($policy),
            $policy->name,
            Reference::tenantOf($policy),
            self::digest($policy->document),
            $policy->getAttribute('is_system') === true,
        ));
    }

    /**
     * Report the policy updated, with the before/after diff and the previous
     * document's digest captured in the paired `updating` hook.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return void
     */
    public function updated(Policy $policy): void
    {
        /** @var array{document?: \SineMacula\Laravel\Authorization\Support\DocumentDigest|null} $held */
        $held = RecordChanges::release($policy);

        OperationScope::dispatch(new PolicyUpdated(
            OperationScope::current($policy),
            Reference::of($policy),
            $policy->name,
            Reference::tenantOf($policy),
            RecordChanges::diff($policy),
            self::digest($policy->document),
            $held['document'] ?? null,
        ));
    }

    /**
     * Refuse the delete of a policy in use as a permission boundary (see
     * `PolicyBoundaries`), then read, before the row goes, every grantee the
     * policy is attached to, which the delete takes with it.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\BoundaryException
     */
    public function deleting(Policy $policy): void
    {
        PolicyBoundaries::assertDeletable($policy);

        RecordChanges::hold($policy, ['grantees' => GrantTarget::POLICY->holders(Reference::of($policy)->id)]);
    }

    /**
     * Report the policy deleted, with the grantees read in the paired
     * `deleting` hook.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return void
     */
    public function deleted(Policy $policy): void
    {
        /** @var array{grantees?: list<\SineMacula\Laravel\Authorization\Support\Reference>} $held */
        $held = RecordChanges::release($policy);

        OperationScope::dispatch(new PolicyDeleted(
            OperationScope::current($policy),
            Reference::of($policy),
            $policy->name,
            Reference::tenantOf($policy),
            self::digest($policy->document),
            $held['grantees'] ?? [],
        ));
    }

    /**
     * Return the digest of a document as the model casts it: a decoded array,
     * or anything else as an empty document.
     *
     * @param  mixed  $document
     * @return \SineMacula\Laravel\Authorization\Support\DocumentDigest
     */
    private static function digest(mixed $document): DocumentDigest
    {
        return DocumentDigest::of(\is_array($document) ? $document : []);
    }
}
