<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

use Illuminate\Auth\Access\AuthorizationException as LaravelAuthorizationException;
use Illuminate\Contracts\Translation\Translator;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Support\Messages;

/**
 * Thrown when `authorize()`, or one of the package's route middleware, decides
 * a check as `insufficient_authentication` (AUTHZ-7.8, AUTHZ-9.6, N36): an
 * allow would apply once the subject's session meets an authentication
 * requirement.
 *
 * Extends Laravel's own authorization exception, so an application that does
 * not map it to a step-up response still renders it as a `403`. It carries the
 * reason code and the candidate requirements, each with its unmet parts, any
 * one of which met would allow the check, once each; never the policy, the
 * statements, the trace or any proof. Its message is the generic `denied` line
 * of the package's `authorization` language file, as every denial's is, so an
 * application words its own step-up prompt from the reason code. The decision
 * is recorded as the manager's last decision and fires the
 * `AuthorizationFailed` event first, as any denial does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InsufficientAuthenticationException extends LaravelAuthorizationException
{
    /** @var list<\SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement> The candidate requirements, once each. */
    private readonly array $requirements;

    /**
     * Create a new insufficient authentication exception.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement>  $requirements
     * @param  string|null  $message
     */
    public function __construct(array $requirements, ?string $message = null)
    {
        parent::__construct($message, 403);

        $unique = [];

        foreach ($requirements as $requirement) {
            $unique[\serialize($requirement->toArray())] ??= $requirement;
        }

        $this->requirements = \array_values($unique);
    }

    /**
     * Create an exception whose message is the `denied` line the translator
     * words, in its current locale.
     *
     * Without a translator, or when it has no line for the key, the message is
     * Laravel's English default.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement>  $requirements
     * @param  \Illuminate\Contracts\Translation\Translator|null  $translator
     * @return self
     */
    public static function translated(array $requirements, ?Translator $translator): self
    {
        return new self($requirements, Messages::line(Messages::DENIED, $translator));
    }

    /**
     * Return the reason code of the decision: always
     * `insufficient_authentication`.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason
     */
    public function getReason(): DecisionReason
    {
        return DecisionReason::INSUFFICIENT_AUTHENTICATION;
    }

    /**
     * Return the candidate requirements, each with its unmet parts: any one of
     * them met would allow the check.
     *
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement>
     */
    public function requirements(): array
    {
        return $this->requirements;
    }
}
