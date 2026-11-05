<?php

declare(strict_types = 1);

namespace Tests\Feature\Cache;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Cache\Resolution;

/**
 * Unit tests for what a resolution found.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Resolution::class)]
final class ResolutionTest extends TestCase
{
    /**
     * A resolution with nothing else said never expires and may be stored.
     *
     * @return void
     */
    public function testDefaultsToStableWithoutExpiry(): void
    {
        $resolution = new Resolution(['posts:read']);

        self::assertSame(['posts:read'], $resolution->value);
        self::assertNull($resolution->expiresIn);
        self::assertTrue($resolution->stable);
    }
}
