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
 * message, the line of the package's `authorization` language file keyed by
 * that code (AUTHZ-9.7), in the translator's current locale. Without a
 * translator, or when it has no line for the code, the message is left to
 * Laravel's English default. An `insufficient_authentication` denial keeps its
 * own code, and carries neither the requirements nor the step-up exception
 * `authorize()` raises. A denial is never turned into a not-found response.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PolicyResponses
{
    /** @var string Prefix of the translation key of a denial's message, completed by its reason code. */
    public const string KEY_PREFIX = 'authorization::authorization.';

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

        return Response::deny(self::message($reason, $translator ?? self::translator()), $reason->value);
    }

    /**
     * Return the translated message of the supplied reason, or null when there
     * is no translator or it has no line for the reason.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason  $reason
     * @param  \Illuminate\Contracts\Translation\Translator|null  $translator
     * @return string|null
     */
    private static function message(DecisionReason $reason, ?Translator $translator): ?string
    {
        $key  = self::KEY_PREFIX . $reason->value;
        $line = $translator?->get($key);

        return \is_string($line) && $line !== $key ? $line : null;
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
