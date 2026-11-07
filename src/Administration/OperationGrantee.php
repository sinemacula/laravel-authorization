<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Who an operation is for, as the administration stage weighs it: whether its
 * grantee is a subject, a principal or an identity, rather than a role or the
 * resource a resource policy is attached to; whether that subject is the actor
 * itself; and the grantee's model, for its rank.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class OperationGrantee
{
    /**
     * Determine whether the operation is a grant or a removal for a subject: a
     * principal or an identity. A change to a definition, a grant to or from a
     * role and a resource policy's attachment are not.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @return bool
     */
    public static function isSubject(OperationResource $operation): bool
    {
        $grantee = $operation->change?->grantee;

        return $grantee !== null
            && !\in_array($operation->action, [PackagePermissions::RESOURCE_POLICY_ATTACH, PackagePermissions::RESOURCE_POLICY_DETACH], true)
            && !self::isRole($grantee);
    }

    /**
     * Determine whether the reference is to a role of the configured role
     * model.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return bool
     */
    public static function isRole(Reference $grantee): bool
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $class */
        $class = config('authorization.models.role', Role::class);

        return $grantee->type === (new $class)->getMorphClass();
    }

    /**
     * Determine whether the operation's grantee is the actor: its principal, or
     * the identity behind it.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Subject  $actor
     * @return bool
     */
    public static function isSelf(OperationResource $operation, Subject $actor): bool
    {
        $grantee = $operation->change?->grantee;

        foreach ([$actor->subject, $actor->identity] as $side) {
            if ($grantee !== null && $side instanceof Model && self::isSame(Reference::of($side), $grantee)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return the model the reference names, read past every global scope on its
     * own connection, or null when its type names no model class or the record
     * does not exist.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return \Illuminate\Database\Eloquent\Model|null
     */
    public static function model(Reference $grantee): ?Model
    {
        $class = Relation::getMorphedModel($grantee->type) ?? $grantee->type;

        if (!\class_exists($class) || !\is_subclass_of($class, Model::class)) {
            return null;
        }

        $model = (new $class)->newQueryWithoutScopes()->useWritePdo()->find($grantee->id);

        return $model instanceof Model ? $model : null;
    }

    /**
     * Determine whether two references name the same record, byte for byte.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $left
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $right
     * @return bool
     */
    private static function isSame(Reference $left, Reference $right): bool
    {
        return $left->type === $right->type && $left->id === $right->id;
    }
}
