<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Origin;

/**
 * Unit tests for the origins of a seam's binding the configuration report
 * shows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Origin::class)]
final class OriginTest extends TestCase
{
    /**
     * The origins are part of the report's versioned shape, so they never
     * change.
     *
     * @return void
     */
    public function testTheOriginsAreStable(): void
    {
        self::assertSame([
            'package_default', 'configured', 'earlier_binding', 'later_binding', 'declared', 'deferred', 'alias', 'external_binding', 'unbound',
        ], \array_column(Origin::cases(), 'value'));
    }
}
