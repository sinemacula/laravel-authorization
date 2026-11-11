<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Diagnostics;

use SineMacula\Laravel\Authorization\Contracts\ContextSource;

/**
 * A context source that throws what the package does not foresee when asked the
 * namespace it supplies.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ThrowingContextSource implements ContextSource
{
    /** @var string The message it throws with, which nothing may show. */
    public const string MESSAGE = 'vault token s3cr3t';

    /**
     * Throw.
     *
     * @return string
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function namespace(): string
    {
        throw new \RuntimeException(self::MESSAGE);
    }

    /**
     * Return no values.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function values(): array
    {
        return [];
    }
}
