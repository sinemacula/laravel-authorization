<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

use Illuminate\Auth\Access\AuthorizationException as LaravelAuthorizationException;
use Illuminate\Contracts\Translation\Translator;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Support\Messages;

/**
 * Thrown when the authorization manager's `authorize()` entry point, or one of
 * the package's route middleware, denies a request.
 *
 * Extends Laravel's own authorization exception, so the application's handler
 * renders it as a `403`. It carries the decision's reason code and nothing
 * else: the action, the resource, the matched statement and the trace stay out
 * of the exception, and the message is the generic `denied` line of the
 * package's `authorization` language file, whatever the reason, so an
 * application that words a message per reason reads the reason code. A denied
 * decision, from `authorize()` or the `permission` and `authorize` middleware,
 * is recorded as the manager's last decision and fires the
 * `AuthorizationFailed` event first, so a consumer that needs the full decision
 * reads it there. A missing role is not a decision: it carries `no_match`,
 * records nothing and fires no event.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class AuthorizationException extends LaravelAuthorizationException
{
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
     * Create an exception whose message is the `denied` line the translator
     * words, in its current locale.
     *
     * Without a translator, or when it has no line for the key, the message is
     * Laravel's English default.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason  $reason
     * @param  \Illuminate\Contracts\Translation\Translator|null  $translator
     * @return self
     */
    public static function translated(DecisionReason $reason, ?Translator $translator): self
    {
        return new self($reason, Messages::line(Messages::DENIED, $translator));
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
