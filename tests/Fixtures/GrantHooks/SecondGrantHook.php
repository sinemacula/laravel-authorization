<?php

declare(strict_types = 1);

namespace Tests\Fixtures\GrantHooks;

use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Hooks\GrantWidening;

/**
 * A second grant hook class, so a configuration can list two hooks, running
 * what a test gives it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SecondGrantHook implements GrantHook
{
    /**
     * Create a new hook running what the test gives it.
     *
     * @param  \Closure(\SineMacula\Laravel\Authorization\Hooks\GrantWidening): void  $during
     */
    public function __construct(

        /** What the hook runs with each widening. */
        private \Closure $during,
    ) {}

    /**
     * Run what the test gave the hook.
     *
     * @param  \SineMacula\Laravel\Authorization\Hooks\GrantWidening  $widening
     * @return void
     */
    #[\Override]
    public function beforeWidening(GrantWidening $widening): void
    {
        ($this->during)($widening);
    }
}
