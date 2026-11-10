<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\PackageStatus;

/**
 * Unit tests for where the package stands in an application that registered it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PackageStatus::class)]
final class PackageStatusTest extends TestCase
{
    /**
     * The package is pending, healthy or refusing, and nothing else.
     *
     * @return void
     */
    public function testTheStatusesAreStable(): void
    {
        self::assertSame(['pending', 'healthy', 'refusing'], \array_column(PackageStatus::cases(), 'value'));
    }
}
