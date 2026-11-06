<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Auth\Access\Response;
use Illuminate\Container\Container;
use Illuminate\Contracts\Translation\Translator;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;

/**
 * Turns a decision into the response a Laravel policy method returns
 * (AUTHZ-9.2), for the `DecidesThroughAuthorization` trait.
 *
 * An allowed decision is `Response::allow()`. A denied one is
 * `Response::deny()` with the decision's reason code as its code and, as its
 * message, the generic `denied` line of the package's `authorization` language
 * file (AUTHZ-9.7, N61), whatever the reason, in the translator's current
 * locale; an application that words a message per reason reads the code.
 * Without a translator, or when it has no line for the key, the message is left
 * to Laravel's English default. An `insufficient_authentication` denial keeps
 * its own code, and carries neither the requirements nor the step-up exception
 * `authorize()` raises. A denial is never turned into a not-found response.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PolicyResponses
{
    /**
     * Return the policy response of the supplied decision.
     *
     * The translator defaults to the container's, when one is bound.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @param  \Illuminate\Contracts\Translation\Translator|null  $translator
     * @return \Illuminate\Auth\Access\Response
     */
    public static function of(Decision $decision, ?Translator $translator = null): Response
    {
        if ($decision->isAllowed()) {
            return Response::allow();
        }

        $reason = $decision->reason ?? DecisionReason::NO_MATCH;

        return Response::deny(Messages::line(Messages::DENIED, $translator ?? self::translator()), $reason->value);
    }

    /**
     * Return the container's translator, or null when none is bound.
     *
     * @return \Illuminate\Contracts\Translation\Translator|null
     */
    private static function translator(): ?Translator
    {
        $container = Container::getInstance();

        return $container->bound(Translator::class) ? $container->make(Translator::class) : null;
    }
}
