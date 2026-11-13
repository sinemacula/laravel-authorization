<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Enums\BreakGlassRefusal;
use SineMacula\Laravel\Authorization\Exceptions\BreakGlassRefusedException;

/**
 * Unit tests for the refusal of a break-glass call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BreakGlassRefusedException::class)]
final class BreakGlassRefusedExceptionTest extends TestCase
{
    /**
     * The refusal carries its reason and message, as a runtime exception.
     *
     * @return void
     */
    public function testCarriesTheReason(): void
    {
        $exception = new BreakGlassRefusedException(BreakGlassRefusal::DURATION, 'Too long.');

        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertSame(BreakGlassRefusal::DURATION, $exception->getReason());
        self::assertSame('Too long.', $exception->getMessage());
    }
}
