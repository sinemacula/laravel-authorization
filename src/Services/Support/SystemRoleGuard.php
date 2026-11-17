<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\OperationGrantee;
use SineMacula\Laravel\Authorization\Config\ModelClasses;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Dispatches the events of a grant service write, guarded by the system
 * protection of a role that is the grantee (see `HasSystemProtection`), so a
 * change to a system role's grants is refused unless `forceSystem()` unlocked
 * it, and is reported. The role is guarded as given to a trusted call; as
 * stored for a delegated call or a role named by a reference, so neither can
 * carry the unlock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SystemRoleGuard
{
    /**
     * Dispatch the events of a write to the grantee, through the role's
     * protection when the grantee is a role, labelled as the operation given,
     * such as `policy-change`.
     *
     * @param  string  $operation
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  \SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent  ...$events
     * @return void
     *
     * @throws \Throwable
     */
    public static function dispatch(string $operation, Model|Reference $grantee, ?ActingContext $actor, AuthorizationEvent ...$events): void
    {
        $role = $grantee instanceof Role && $actor === null ? $grantee : self::stored(Reference::of($grantee));

        if ($role === null) {
            OperationScope::dispatch(...$events);

            return;
        }

        $role->dispatchRelationChange($operation, ...$events);
    }

    /**
     * Return the role the reference names, read as stored through the class
     * `authorization.models.role` configures, or null when it names no role:
     * none of its type, none with its key, or a key that is not a UUID, which
     * keys no role on any database (PostgreSQL would refuse to compare it).
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return \SineMacula\Laravel\Authorization\Models\Role|null
     */
    private static function stored(Reference $grantee): ?Role
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $class */
        $class = ModelClasses::get('role');
        $role  = OperationGrantee::isRole($grantee) && Str::isUuid($grantee->id) ? (new $class)->newQueryWithoutScopes()->useWritePdo()->find($grantee->id) : null;

        return $role instanceof Role ? $role : null;
    }
}
