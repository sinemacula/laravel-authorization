<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;
use SineMacula\Laravel\Authorization\Models\Pivots\AuthorizableRolePivot;
use Tests\TestCase;

/**
 * Coverage for the UTC cast the grant pivots use for `expires_at`: every
 * instant is written as UTC wall-clock time and read back as a UTC instant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(UtcDateTime::class)]
final class UtcDateTimeTest extends TestCase
{
    /**
     * A date in another zone is written as the same instant in UTC.
     *
     * @return void
     */
    public function testSetWritesADateInAnotherZoneAsUtc(): void
    {
        $stored = (new UtcDateTime)->set(new AuthorizableRolePivot, 'expires_at', Carbon::parse('2030-01-01 12:00:00', 'Asia/Tokyo'), []);

        self::assertSame('2030-01-01 03:00:00', $stored);
    }

    /**
     * An immutable date is converted as well.
     *
     * @return void
     */
    public function testSetWritesAnImmutableDateAsUtc(): void
    {
        $stored = (new UtcDateTime)->set(new AuthorizableRolePivot, 'expires_at', new \DateTimeImmutable('2030-01-01 12:00:00', new \DateTimeZone('America/New_York')), []);

        self::assertSame('2030-01-01 17:00:00', $stored);
    }

    /**
     * A string without an offset is taken to be UTC; one with an offset keeps
     * the instant it names.
     *
     * @return void
     */
    public function testSetReadsAStringAsUtcUnlessItNamesAnOffset(): void
    {
        $cast  = new UtcDateTime;
        $pivot = new AuthorizableRolePivot;

        self::assertSame('2030-01-01 12:00:00', $cast->set($pivot, 'expires_at', '2030-01-01 12:00:00', []));
        self::assertSame('2030-01-01 10:00:00', $cast->set($pivot, 'expires_at', '2030-01-01T12:00:00+02:00', []));
    }

    /**
     * No value is written as null.
     *
     * @return void
     */
    public function testSetWritesNullForNoValue(): void
    {
        $cast  = new UtcDateTime;
        $pivot = new AuthorizableRolePivot;

        self::assertNull($cast->set($pivot, 'expires_at', null, []));
        self::assertNull($cast->set($pivot, 'expires_at', '', []));
    }

    /**
     * The stored wall-clock time is read back as a UTC instant, whatever the
     * application's zone.
     *
     * @return void
     */
    public function testGetReadsTheStoredValueAsUtc(): void
    {
        $default = \date_default_timezone_get();

        \date_default_timezone_set('Asia/Tokyo');

        try {
            $read = (new UtcDateTime)->get(new AuthorizableRolePivot, 'expires_at', '2030-01-01 03:00:00', []);
        } finally {
            \date_default_timezone_set($default);
        }

        self::assertInstanceOf(Carbon::class, $read);
        self::assertSame('UTC', $read->getTimezone()->getName());
        self::assertSame('2030-01-01 03:00:00', $read->format('Y-m-d H:i:s'));
        self::assertSame(Carbon::parse('2030-01-01 12:00:00', 'Asia/Tokyo')->getTimestamp(), $read->getTimestamp());
    }

    /**
     * A date is converted to UTC; anything that is neither a date nor a
     * non-empty string is no instant.
     *
     * @return void
     */
    public function testToUtcConvertsDatesAndRefusesEverythingElse(): void
    {
        $source = Carbon::parse('2030-01-01 12:00:00', 'Asia/Tokyo');
        $utc    = UtcDateTime::toUtc($source);

        self::assertInstanceOf(Carbon::class, $utc);
        self::assertSame('2030-01-01 03:00:00 UTC', $utc->format('Y-m-d H:i:s T'));
        self::assertSame('Asia/Tokyo', $source->getTimezone()->getName());

        self::assertNull(UtcDateTime::toUtc(null));
        self::assertNull(UtcDateTime::toUtc(''));
        self::assertNull(UtcDateTime::toUtc(42));
        self::assertNull(UtcDateTime::toUtc(new \stdClass));
    }
}
