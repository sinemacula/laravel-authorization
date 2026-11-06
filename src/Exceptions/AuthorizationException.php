<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

use Illuminate\Auth\Access\AuthorizationException as LaravelAuthorizationException;
use Illuminate\Contracts\Translation\Translator;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;

/**
 * Thrown when the authorization manager's `authorize()` entry point, or one of
 * the package's route middleware, denies a request.
 *
 * Extends Laravel's own authorization exception, so the application's handler
 * renders it as a `403`. It carries the decision's reason code and nothing
 * else: the action, the resource, the matched statement and the trace stay out
 * of the exception, and the message is a translated line of the package's
 * `authorization` language file: `denied` for a decision, `role_required` for a
 * role the subject does not hold. A denied decision, from `authorize()` or the
 * `permission` and `authorize` middleware, is recorded as the manager's last
 * decision and fires the `AuthorizationFailed` event first, so a consumer that
 * needs the full decision reads it there. A missing role is not a decision: it
 * carries `no_match`, records nothing and fires no event.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class AuthorizationException extends LaravelAuthorizationException
{
    /** @var string Translation key of the message a denial carries. */
    public const string MESSAGE_KEY = 'authorization::authorization.denied';

    /** @var string Translation key of the message a missing role carries. */
    public const string ROLE_REQUIRED_KEY = 'authorization::authorization.role_required';

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
     * Create an exception whose message is the line the translator words for
     * the key, in its current locale.
     *
     * Without a translator, or when it has no line for the key, the message is
     * Laravel's English default.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason  $reason
     * @param  \Illuminate\Contracts\Translation\Translator|null  $translator
     * @param  string  $key
     * @return self
     */
    public static function translated(DecisionReason $reason, ?Translator $translator, string $key = self::MESSAGE_KEY): self
    {
        $line = $translator?->get($key);

        return new self($reason, \is_string($line) && $line !== $key ? $line : null);
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
