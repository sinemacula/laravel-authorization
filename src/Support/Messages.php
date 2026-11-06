<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Contracts\Translation\Translator;

/**
 * Words the messages the package puts in front of a client (AUTHZ-9.7, N61,
 * N62), from the lines of its `authorization` language file.
 *
 * Every denial carries the one generic `denied` line, whatever its reason: the
 * reason code travels beside it, on the exception or the policy response, for
 * an application that words its own message per reason. A request without a
 * subject carries the `unauthenticated` line. Validation, service and
 * configuration messages are diagnostics for developers and are not translated.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Messages
{
    /** @var string Translation key of the message every denial carries. */
    public const string DENIED = 'authorization::authorization.denied';

    /** @var string Translation key of the message an unauthenticated request carries. */
    public const string UNAUTHENTICATED = 'authorization::authorization.unauthenticated';

    /**
     * Return the line the translator words for the key, in its current locale,
     * or null when there is no translator, or it has no line for the key (it
     * answers with the key) or answers with something other than a line.
     *
     * @param  string  $key
     * @param  \Illuminate\Contracts\Translation\Translator|null  $translator
     * @return string|null
     */
    public static function line(string $key, ?Translator $translator): ?string
    {
        $line = $translator?->get($key);

        return \is_string($line) && $line !== $key ? $line : null;
    }
}
