<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder as QueryBuilder;
use SineMacula\Laravel\Authorization\Config\ModelClasses;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Exceptions\InlinePolicyAttachmentException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPolicyOwnerException;
use SineMacula\Laravel\Authorization\Exceptions\OwnerChangedException;
use SineMacula\Laravel\Authorization\Exceptions\SystemInlinePolicyException;
use SineMacula\Laravel\Authorization\Models\Policy;

/**
 * The rules an inline policy keeps about the grantee it belongs to (AUTHZ-6.9).
 *
 * An inline policy names its grantee in `owner_type` and `owner_id`, both or
 * neither, and the grantee is fixed once the policy is created. It is never a
 * system policy, since it is deleted with its grantee. It is attached to that
 * grantee alone: the grant service, and a write through a grantee's
 * `policies()` relation, refuse any other with
 * `InlinePolicyAttachmentException`, reading the grantee from the stored row on
 * the write connection rather than from the model in hand, which may have been
 * loaded without its owner columns or changed since. A resolution leaves out
 * any attachment of an inline policy to another grantee that reached the table
 * all the same. It is deleted with its grantee: the `HasPolicies` trait deletes
 * a grantee's inline policies once the model is deleted, and
 * `authorization:prune` deletes those of a grantee that no longer exists, since
 * grantees are morphs and the columns carry no foreign key. A policy deleted
 * takes its attachments with it.
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
     * Refuse a policy with one owner column and not the other, a saved policy
     * whose grantee would change, and an inline policy marked as a system one.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPolicyOwnerException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\OwnerChangedException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\SystemInlinePolicyException
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
            throw new OwnerChangedException('policy', $name, 'grantee');
        }

        if ($type !== null && (bool) $policy->getAttribute('is_system')) {
            throw new SystemInlinePolicyException($name);
        }
    }

    /**
     * Refuse to attach an inline policy to any grantee but the one it belongs
     * to, a policy naming `principals`, and a policy whose row is gone. A
     * managed policy naming none, or a target that is not a policy, passes.
     *
     * The grantee is read from the stored row, not from the model in hand: a
     * model loaded without its owner columns, or with them changed and not
     * saved, would otherwise pass as a managed policy. Called inside the
     * grant's transaction, the read sees the row the grant writes against.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $target
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InlinePolicyAttachmentException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\ResourcePolicyException
     */
    public static function assertAttachable(Model $target, Reference $grantee): void
    {
        if (!$target instanceof Policy) {
            return;
        }

        self::assertStoredAttachable(self::storedTarget($target), $grantee);
    }

    /**
     * Refuse to attach a policy, as `stored()` read it, to any grantee but the
     * one it belongs to, and a policy naming `principals`, which only a
     * resource policy does, with `ResourcePolicyException` (see
     * `PolicyPrincipals`). A managed policy naming none passes.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $stored
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InlinePolicyAttachmentException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\ResourcePolicyException
     */
    public static function assertStoredAttachable(Policy $stored, Reference $grantee): void
    {
        self::assertOwnedBy($stored, $grantee);

        PolicyPrincipals::assertAttachableToGrantee($stored);
    }

    /**
     * Read the name, owner columns and document of the policy with the given
     * key as stored, through the configured policy class, outside any global
     * scope and on the write connection, so a replica that has not caught up
     * never hides a policy just created; null when no policy has the key.
     *
     * @param  mixed  $key
     * @return \SineMacula\Laravel\Authorization\Models\Policy|null
     */
    public static function stored(mixed $key): ?Policy
    {
        return self::storedThrough(self::policyClass()::query(), $key);
    }

    /**
     * Read the policy with the given key as `stored()` does, under a lock on
     * its row held until the transaction ends, so a change to the policy that
     * another transaction makes waits for this one, and this read sees the row
     * as last committed; null when no policy has the key.
     *
     * @param  mixed  $key
     * @return \SineMacula\Laravel\Authorization\Models\Policy|null
     */
    public static function storedForUpdate(mixed $key): ?Policy
    {
        return self::storedThrough(self::policyClass()::query()->lockForUpdate(), $key);
    }

    /**
     * Determine whether the policy with the given key is gone, by a locking
     * read on the write connection outside any global scope, so a deletion
     * another transaction committed since this one began is seen, as a plain
     * read of a MySQL snapshot would not see it.
     *
     * @param  mixed  $key
     * @return bool
     */
    public static function isGone(mixed $key): bool
    {
        return self::policyClass()::query()->withoutGlobalScopes()->useWritePdo()->whereKey($key)->sharedLock()->doesntExist();
    }

    /**
     * Limit a query of the attachments table to the rows whose policy is
     * managed, or is inline and belongs to the grantee the row names, so a
     * resolution never applies an inline policy that reached another grantee. A
     * managed policy's null owner columns compare unequal to nothing, so its
     * rows always stay.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $table
     * @return \Illuminate\Database\Query\Builder
     */
    public static function attachedToTheirGrantee(QueryBuilder $query, string $table): QueryBuilder
    {
        $policies = TableNames::get('policies');

        return $query->whereNotExists(static function (QueryBuilder $stray) use ($policies, $table): void {
            $stray->selectRaw('1')
                ->from($policies . ' as inline_policies')
                ->whereColumn('inline_policies.id', $table . '.policy_id')
                ->where(static function (QueryBuilder $other) use ($table): void {
                    $other->whereColumn('inline_policies.owner_type', '<>', $table . '.authorizable_type')
                        ->orWhereColumn('inline_policies.owner_id', '<>', $table . '.authorizable_id');
                });
        });
    }

    /**
     * Determine whether a model's deletion removed it for good, rather than
     * soft deleting it, so its inline policies are deleted with it.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return bool
     */
    public static function isDeletedForGood(Model $model): bool
    {
        return !\method_exists($model, 'isForceDeleting') || $model->isForceDeleting() === true;
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
     * Refuse a policy, as `stored()` read it, that belongs to a grantee other
     * than the given one. A managed policy belongs to none, and passes.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $stored
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InlinePolicyAttachmentException
     */
    private static function assertOwnedBy(Policy $stored, Reference $grantee): void
    {
        $owner = self::ownerOf($stored);

        if ($owner === null || ($owner->type === $grantee->type && $owner->id === $grantee->id)) {
            return;
        }

        throw new InlinePolicyAttachmentException(PolicyDocument::nameOf($stored->getAttribute('name')), $owner, $grantee);
    }

    /**
     * Read the policy a grant targets as stored, refusing one whose row is
     * gone.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $target
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     */
    private static function storedTarget(Policy $target): Policy
    {
        return self::stored($target->getKey()) ?? throw new InvalidGrantTargetException('policy', $target);
    }

    /**
     * Query the inline policies the grantee owns, through the configured policy
     * class, outside any global scope and on the write connection, so the
     * grantee's `deleted` hook and the pruner see a policy created moments
     * before.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $owner
     * @return \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Authorization\Models\Policy>
     */
    private static function ownedBy(Reference $owner): Builder
    {
        return self::policyClass()::query()->withoutGlobalScopes()->useWritePdo()->where('owner_type', $owner->type)->where('owner_id', $owner->id);
    }

    /**
     * Read the name, owner columns and document of the policy with the given
     * key through the query, outside any global scope and on the write
     * connection; null when no policy has the key.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Authorization\Models\Policy>  $query
     * @param  mixed  $key
     * @return \SineMacula\Laravel\Authorization\Models\Policy|null
     */
    private static function storedThrough(Builder $query, mixed $key): ?Policy
    {
        $policy = $query->withoutGlobalScopes()->useWritePdo()->find($key, [$query->getModel()->getKeyName(), 'name', 'owner_type', 'owner_id', 'document']);

        return $policy instanceof Policy ? $policy : null;
    }

    /**
     * Return the policy class `authorization.models.policy` configures.
     *
     * @return class-string<\SineMacula\Laravel\Authorization\Models\Policy>
     */
    private static function policyClass(): string
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> */
        return ModelClasses::get('policy');
    }
}
