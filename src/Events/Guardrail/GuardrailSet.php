<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Guardrail;

use SineMacula\Laravel\Authorization\Enums\MutationOperation;

/**
 * Dispatched when a policy is set as a guardrail on a tenant or on the platform
 * (AUTHZ-7.6), by the guardrail service.
 *
 * It carries what every change to a guardrail does (see `GuardrailEvent`): the
 * operation, with the actor that set it, the policy, its name and the scope.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class GuardrailSet extends GuardrailEvent
{
    /**
     * Return the stable identifier of the change: `guardrail.set`.
     *
     * @return string
     */
    #[\Override]
    public function operation(): string
    {
        return MutationOperation::GUARDRAIL_SET->value;
    }
}
