<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

use Illuminate\Auth\Access\AuthorizationException as LaravelAuthorizationException;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;

/**
 * Thrown when the authorization manager's `authorize()` entry point denies a
 * request.
 *
 * Extends Laravel's own authorization exception, so the application's handler
 * renders it as a `403`. It carries the decision's reason code and nothing
 * else: the action, the resource, the matched statement and the trace stay out
 * of the exception, and the message is the translated
 * `authorization::authorization.denied` line. A consumer that needs the full
 * decision reads it from the `AuthorizationFailed` event or the manager's last
 * decision.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class AuthorizationException extends LaravelAuthorizationException
{
    /** @var string Translation key of the message a denial carries. */
    public const string MESSAGE_KEY = 'authorization::authorization.denied';

    /**
     * Create a new authorization exception instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason  $reason
     * @param  string|null  $message
     */
    public function __construct(

        /** Reason code of the decision that denied the request. */
        private readonly DecisionReason $reason,

        // Translated message; null keeps Laravel's English default.
        ?string $message = null,
    ) {
        parent::__construct($message, 403);
    }

    /**
     * Return the reason code of the decision that denied the request.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason
     */
    public function getReason(): DecisionReason
    {
        return $this->reason;
    }
}
