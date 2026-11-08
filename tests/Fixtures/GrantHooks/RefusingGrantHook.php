<?php

declare(strict_types = 1);

namespace Tests\Fixtures\GrantHooks;

use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Exceptions\GrantRefusedException;
use SineMacula\Laravel\Authorization\Hooks\GrantWidening;

/**
 * A grant hook that refuses every widening it is handed, counting them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RefusingGrantHook implements GrantHook
{
    /** @var int How many widenings the hook refused. */
    public int $refused = 0;

    /**
     * Refuse the widening.
     *
     * @param  \SineMacula\Laravel\Authorization\Hooks\GrantWidening  $widening
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GrantRefusedException
     */
    #[\Override]
    public function beforeWidening(GrantWidening $widening): void
    {
        $this->refused++;

        throw new GrantRefusedException('Refused by the test hook.');
    }
}
