<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Identity;

/**
 * Dispatched when a break-glass activation is revoked before it expires
 * (AUTHZ-11.7). The operation's actor is the revoker, or no one for a trusted
 * call.
 *
 * It carries what every ended activation does (see `BreakGlassEnded`).
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class BreakGlassRevoked extends BreakGlassEnded
{
    /**
     * Return the stable identifier of the change:
     * `identity.break_glass.revoked`.
     *
     * @return string
     */
    #[\Override]
    public function operation(): string
    {
        return 'identity.break_glass.revoked';
    }
}
