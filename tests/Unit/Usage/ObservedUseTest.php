<?php

declare(strict_types = 1);

namespace Tests\Unit\Usage;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Usage\ObservedUse;

/**
 * Unit tests for what a usage store keeps of one grant route.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ObservedUse::class)]
final class ObservedUseTest extends TestCase
{
    /**
     * A use counts for the grant created at its grant's creation or before,
     * never for a grant created after it, a regrant; a use that recorded no
     * creation counts only for a grant that records none.
     *
     * @return void
     */
    public function testAUseCountsOnlyForTheGrantItWasObservedThrough(): void
    {
        $created = CarbonImmutable::createFromTimestampUTC(1794218400);
        $use     = new ObservedUse(CarbonImmutable::create(2026, 11, 9, 11), $created);

        self::assertTrue($use->isOf($created));
        self::assertTrue($use->isOf($created->subSecond()));
        self::assertTrue($use->isOf(null));
        self::assertFalse($use->isOf($created->addSecond()));
        self::assertFalse((new ObservedUse(CarbonImmutable::create(2026, 11, 9, 11)))->isOf($created));
        self::assertTrue((new ObservedUse(CarbonImmutable::create(2026, 11, 9, 11)))->isOf(null));
        self::assertNull((new ObservedUse(CarbonImmutable::create(2026)))->grantCreatedAt);
    }
}
