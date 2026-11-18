<?php

declare(strict_types = 1);

namespace Tests\Fixtures\QueryScoping;

use SineMacula\Laravel\Authorization\Contracts\ContextSource;
use SineMacula\Laravel\Authorization\Contracts\ScopeInvariant;

/**
 * A context source, marked `ScopeInvariant`, that supplies the `plan` namespace
 * with the same tier for every check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class InvariantPlanContextSource implements ContextSource, ScopeInvariant
{
    /**
     * Return the namespace the source supplies.
     *
     * @return string
     */
    #[\Override]
    public function namespace(): string
    {
        return 'plan';
    }

    /**
     * Return the pro tier.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function values(): array
    {
        return ['tier' => 'pro'];
    }
}
