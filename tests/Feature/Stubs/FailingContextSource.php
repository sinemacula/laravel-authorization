<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\ContextSource;

/**
 * An application context source supplying the `ledger` namespace whose values
 * cannot be read: reading them throws, with a value in the message.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FailingContextSource implements ContextSource
{
    /** @var string The message reading the values throws with. */
    public const string MESSAGE = 'ledger unreachable for balance 4711';

    /**
     * Return the namespace the source supplies.
     *
     * @return string
     */
    #[\Override]
    public function namespace(): string
    {
        return 'ledger';
    }

    /**
     * Throw, as a source whose store cannot be read does.
     *
     * @return array<string, mixed>
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function values(): array
    {
        throw new \RuntimeException(self::MESSAGE);
    }
}
