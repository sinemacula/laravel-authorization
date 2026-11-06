<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\ContextSource;

/**
 * A context source claiming the reserved `request` namespace, which no source
 * may supply.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReservedContextSource implements ContextSource
{
    /**
     * Return the reserved namespace.
     *
     * @return string
     */
    #[\Override]
    public function namespace(): string
    {
        return 'request';
    }

    /**
     * Return an address the caller would like the request to have.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function values(): array
    {
        return ['ip' => '10.0.0.1'];
    }
}
