<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\ContextSource;

/**
 * An application context source supplying the `plan` namespace, counting how
 * many times its values are read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PlanContextSource implements ContextSource
{
    /** @var int How many times the values were read. */
    public int $reads = 0;

    /**
     * Create a new plan context source.
     *
     * @param  string  $tier
     */
    public function __construct(

        /** The plan's tier the source supplies. */
        public string $tier = 'pro',
    ) {}

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
     * Return the plan's tier, counting the read.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function values(): array
    {
        $this->reads++;

        return ['tier' => $this->tier];
    }
}
