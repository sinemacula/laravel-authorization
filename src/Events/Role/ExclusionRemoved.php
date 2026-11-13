<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Role;

use SineMacula\Laravel\Authorization\Enums\MutationOperation;

/**
 * Dispatched once a pair of mutually exclusive roles is removed (AUTHZ-11.8),
 * by the role exclusion service; removing a pair that was not declared
 * dispatches nothing, and nor does a role's deletion, which takes its pairs
 * with it and is reported as `Deleted`.
 *
 * It carries what every change to a pair does (see `ExclusionEvent`): the
 * operation, with the actor that removed it, the two roles, their names and the
 * tenant that owned the pair.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExclusionRemoved extends ExclusionEvent
{
    /**
     * Return the stable identifier of the change: `role.exclusion.removed`.
     *
     * @return string
     */
    #[\Override]
    public function operation(): string
    {
        return MutationOperation::ROLE_EXCLUSION_REMOVED->value;
    }
}
