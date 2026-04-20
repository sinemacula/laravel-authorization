<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Http\Middleware;

use LogicException;

/**
 * Raised when an authorization middleware is applied to a route whose
 * authenticated identity does not implement the capability contract the
 * middleware probes.
 *
 * Extends `LogicException` deliberately: the situation is a programmer bug
 * (middleware wired onto the wrong route, or a user model that forgot to
 * compose the matching trait), not a legitimate authorization deny. Laravel's
 * default exception handler renders unhandled logic exceptions as HTTP 500,
 * which is the correct signal for security-audit consumers and monitoring
 * dashboards — distinct from the HTTP 403 raised for a real deny.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class AuthorizationMiddlewareMisconfiguredException extends \LogicException
{
    /**
     * Construct the exception with a concrete, actionable message.
     *
     * @param  string  $contract
     * @param  string  $middleware
     */
    public function __construct(string $contract, string $middleware)
    {
        $short = \substr($contract, \strrpos($contract, '\\') !== false ? \strrpos($contract, '\\') + 1 : 0);

        parent::__construct(
            "Middleware {$middleware} requires the authenticated identity to implement {$short}; "
            . 'apply the appropriate trait on the user model or remove the middleware from this route.',
        );
    }
}
