<?php

declare(strict_types = 1);

namespace Tests\Unit\Query;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Query\Reentrancy;
use Tests\TestCase;

/**
 * Unit tests for the mark kept while a query scope is being decided.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Reentrancy::class)]
final class ReentrancyTest extends TestCase
{
    /**
     * The mark holds while the callback runs, a nested call included, and is
     * removed by the outermost call however it ends.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheMarkHoldsWhileDecidingAndIsRemovedAfter(): void
    {
        self::assertFalse(Reentrancy::isDeciding());

        $nested = static fn (): bool => Reentrancy::guarded(static fn (): bool => Reentrancy::isDeciding());
        $inner  = Reentrancy::guarded(static fn (): array => [Reentrancy::isDeciding(), $nested(), Reentrancy::isDeciding()]);

        self::assertSame([true, true, true], $inner);
        self::assertFalse(Reentrancy::isDeciding());

        try {
            Reentrancy::guarded(static function (): never {
                throw new \RuntimeException('failed');
            });
        } catch (\RuntimeException) {
            self::assertFalse(Reentrancy::isDeciding());
        }
    }
}
