<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Concerns;

use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Convenience trait that composes the three individual authorization traits so
 * consumers can opt a model in with a single `use` clause. Named
 * `HasAuthorization` to avoid the collision with Laravel's own
 * `Illuminate\Foundation\Auth\Access\Authorizable` trait that every stock
 * `User` model already imports.
 *
 * It also answers that the grantee is active, which a model overrides to report
 * one suspended, and removes the grantee's grants once the model is deleted. A
 * model that soft-deletes keeps them until it is force-deleted, so restoring it
 * restores its access; `authorization:prune` removes the grants of a grantee
 * that is gone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 */
trait HasAuthorization // @phpstan-ignore trait.unused
{
    use HasPermissions, HasPolicies, HasRoles;

    /**
     * Determine whether the grantee is active. Override to report a suspended
     * or disabled grantee, which is then denied everything.
     *
     * @return bool
     */
    public function isAuthorizationActive(): bool
    {
        return true;
    }

    /**
     * Remove the grantee's grants once the model is deleted, through the grant
     * service, so each revocation is reported. A soft delete keeps them.
     *
     * @return void
     */
    protected static function bootHasAuthorization(): void
    {
        static::deleted(static function (self $model): void {
            if (!InlinePolicies::isDeletedForGood($model)) {
                return;
            }

            self::authorizationGrants()->revokeAll(Reference::of($model));
        });
    }
}
