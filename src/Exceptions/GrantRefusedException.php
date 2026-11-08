<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown by a grant hook to refuse a grant that widens an identity's scope
 * (AUTHZ-11.3, N80).
 *
 * The package throws it on to the caller as the hook threw it: the call's
 * transaction rolls back, nothing is written, no change event is dispatched and
 * the call is not tried again. It is the hook's refusal, never a decision of
 * the package's: it is not an `AuthorizationException`, and no denial is
 * recorded or reported for it. A hook may throw any other exception too, which
 * rolls the call back the same way, and an application may extend this one for
 * refusals of its own.
 *
 * @inheritable
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class GrantRefusedException extends \RuntimeException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $message
     * @param  \Throwable|null  $previous
     */
    public function __construct(string $message = 'A grant hook refused the grant.', ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }
}
