<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Exceptions\InlinePolicyAttachmentException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPolicyOwnerException;
use SineMacula\Laravel\Authorization\Exceptions\OwnerChangedException;
use SineMacula\Laravel\Authorization\Models\Policy;

/**
 * The rules an inline policy keeps about the grantee it belongs to (AUTHZ-6.9).
 *
 * An inline policy names its grantee in `owner_type` and `owner_id`, both or
 * neither, and the grantee is fixed once the policy is created. It is attached
 * to that grantee alone: the grant service, and a write through a grantee's
 * `policies()` relation, refuse any other with
 * `InlinePolicyAttachmentException`. It is deleted with its grantee: the
 * `HasPolicies` trait deletes a grantee's inline policies once the model is
 * deleted, and `authorization:prune` deletes those of a grantee that no longer
 * exists, since grantees are morphs and the columns carry no foreign key. A
 * policy deleted takes its attachments with it.
 *
 * A managed policy, with neither column, is attached to any grantee or role.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InlinePolicies
{
    /**
     * Return the grantee an inline policy belongs to, or null for a managed
     * policy.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     *
     * @throws \InvalidArgumentException
     */
    public static function ownerOf(Policy $policy): ?Reference
    {
        $type = $policy->getAttribute('owner_type');
        $id   = $policy->getAttribute('owner_id');

        if (!\is_string($type) || !\is_scalar($id)) {
            return null;
        }

        return new Reference($type, (string) $id);
    }

    /**
     * Refuse a policy with one owner column and not the other, and a saved
     * policy whose owner would change.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPolicyOwnerException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\OwnerChangedException
     */
    public static function assertValid(Policy $policy): void
    {
        $type = $policy->getAttribute('owner_type');
        $id   = $policy->getAttribute('owner_id');
        $name = PolicyDocument::nameOf($policy->getAttribute('name'));

        if (($type === null) !== ($id === null)) {
            throw new InvalidPolicyOwnerException($name, $type === null ? 'owner_type' : 'owner_id');
        }

        if ($policy->exists && $policy->isDirty(['owner_type', 'owner_id'])) {
            throw new OwnerChangedException('policy', $name);
        }
    }

    /**
     * Refuse to attach an inline policy to any grantee but the one it belongs
     * to. A managed policy, or a target that is not a policy, passes.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $target
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InlinePolicyAttachmentException
     */
    public static function assertAttachable(Model $target, Reference $grantee): void
    {
        $owner = $target instanceof Policy ? self::ownerOf($target) : null;

        if ($owner === null || ($owner->type === $grantee->type && $owner->id === $grantee->id)) {
            return;
        }

        throw new InlinePolicyAttachmentException(PolicyDocument::nameOf($target->getAttribute('name')), $owner, $grantee);
    }

    /**
     * Delete the inline policies the grantee owns, each through the model so
     * its observer reports it and its attachments go with it, as one operation
     * with no actor, and return how many were deleted.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $owner
     * @return int
     *
     * @throws \Throwable
     */
    public static function deleteOwnedBy(Model|Reference $owner): int
    {
        /** @var list<\SineMacula\Laravel\Authorization\Models\Policy> $policies */
        $policies = self::ownedBy(Reference::of($owner))->orderBy('name')->get()->all();

        if ($policies === []) {
            return 0;
        }

        OperationScope::run(Operation::begin(), static function () use ($policies): void {
            foreach ($policies as $policy) {
                $policy->delete();
            }
        });

        return \count($policies);
    }

    /**
     * Count the inline policies the grantee owns.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $owner
     * @return int
     */
    public static function countOwnedBy(Reference $owner): int
    {
        return self::ownedBy($owner)->count();
    }

    /**
     * Query the inline policies the grantee owns, through the configured policy
     * class and outside any global scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $owner
     * @return \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Authorization\Models\Policy>
     */
    private static function ownedBy(Reference $owner): Builder
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $class */
        $class = config('authorization.models.policy', Policy::class);

        return $class::query()->withoutGlobalScopes()->where('owner_type', $owner->type)->where('owner_id', $owner->id);
    }
}
