<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime;

/**
 * Unit tests for the lifetimes the configuration report shows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Lifetime::class)]
final class LifetimeTest extends TestCase
{
    /**
     * The lifetimes are part of the report's versioned shape, so they never
     * change.
     *
     * @return void
     */
    public function testTheLifetimesAreStable(): void
    {
        self::assertSame(['transient', 'singleton', 'scoped', 'instance'], \array_column(Lifetime::cases(), 'value'));
    }
}
