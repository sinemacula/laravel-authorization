<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Traits;

/**
 * Convenience trait that composes the three individual authorization
 * traits so consumers can opt a model in with a single `use` clause.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 */
trait Authorizable
{
    use HasPermissions;
    use HasPolicies;
    use HasRoles;
}
