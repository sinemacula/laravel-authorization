<?php

declare(strict_types = 1);

namespace Tests\Fixtures\GrantHooks;

use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Hooks\GrantWidening;

/**
 * A grant hook recording every widening it is handed, in order, then running
 * what a test gives it, which may throw to refuse the grant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingGrantHook implements GrantHook
{
    /** @var list<\SineMacula\Laravel\Authorization\Hooks\GrantWidening> The widenings handed to the hook, in order. */
    public array $widenings = [];

    /**
     * Create a new recording hook.
     *
     * @param  (\Closure(\SineMacula\Laravel\Authorization\Hooks\GrantWidening): void)|null  $during
     */
    public function __construct(

        /** What the hook runs once it has recorded a widening, or null for nothing. */
        private readonly ?\Closure $during = null,
    ) {}

    /**
     * Record the widening, then run what the test gave the hook.
     *
     * @param  \SineMacula\Laravel\Authorization\Hooks\GrantWidening  $widening
     * @return void
     */
    #[\Override]
    public function beforeWidening(GrantWidening $widening): void
    {
        $this->widenings[] = $widening;

        if ($this->during === null) {
            return;
        }

        ($this->during)($widening);
    }

    /**
     * Return the reasons of each widening recorded, in order, by value.
     *
     * @return list<list<string>>
     */
    public function reasons(): array
    {
        return \array_map(static fn (GrantWidening $widening): array => \array_map(static fn ($reason): string => $reason->value, $widening->reasons), $this->widenings);
    }
}
