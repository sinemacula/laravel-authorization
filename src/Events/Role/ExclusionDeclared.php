<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Role;

use SineMacula\Laravel\Authorization\Enums\MutationOperation;

/**
 * Dispatched once two roles are declared mutually exclusive (AUTHZ-11.8), by
 * the role exclusion service; declaring a pair already declared dispatches
 * nothing.
 *
 * It carries what every change to a pair does (see `ExclusionEvent`): the
 * operation, with the actor that declared it, the two roles, their names and
 * the tenant that owns the pair.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExclusionDeclared extends ExclusionEvent
{
    /**
     * Return the stable identifier of the change: `role.exclusion.declared`.
     *
     * @return string
     */
    #[\Override]
    public function operation(): string
    {
        return MutationOperation::ROLE_EXCLUSION_DECLARED->value;
    }
}
