<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Traits;

/**
 * Convenience trait that composes the three individual authorization
 * traits so consumers can opt a model in with a single `use` clause.
 * Named `HasAuthorization` to avoid the collision with Laravel's own
 * `Illuminate\Foundation\Auth\Access\Authorizable` trait that every
 * stock `User` model already imports.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 */
trait HasAuthorization // @phpstan-ignore trait.unused
{
    use HasPermissions, HasPolicies, HasRoles;
}
