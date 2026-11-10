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
            'package_default', 'configured', 'earlier_binding', 'later_binding', 'declared', 'deferred', 'deferred_loaded', 'alias', 'external_binding', 'unbound',
        ], \array_column(Origin::cases(), 'value'));
    }

    /**
     * The package's own bindings are its default and the configured class;
     * those made by others are the earlier and later bindings, a loaded
     * deferred provider's and any of a contract the package does not bind.
     *
     * @return void
     */
    public function testWhoMadeTheBindingIsTold(): void
    {
        $packages = \array_filter(Origin::cases(), static fn (Origin $origin): bool => $origin->isPackages());
        $others   = \array_filter(Origin::cases(), static fn (Origin $origin): bool => $origin->isOthers());

        self::assertSame(['package_default', 'configured'], \array_column($packages, 'value'));
        self::assertSame(['earlier_binding', 'later_binding', 'deferred_loaded', 'external_binding'], \array_column($others, 'value'));
    }
}
