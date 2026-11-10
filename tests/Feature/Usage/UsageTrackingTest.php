<?php

declare(strict_types = 1);

namespace Tests\Feature\Usage;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Usage\UsageTracking;
use Tests\TestCase;

/**
 * Feature tests for the settings of grant usage tracking: off by default,
 * hourly buckets that every worker agrees on, a batch's worth, a retention, the
 * queue named, and a setting changed after boot refused rather than replaced.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UsageTracking::class)]
final class UsageTrackingTest extends TestCase
{
    /**
     * The defaults: off, an hour, a thousand, 400 days, and the default queue.
     *
     * @return void
     */
    public function testTheDefaults(): void
    {
        self::assertFalse(UsageTracking::isEnabled());
        self::assertSame([3600, 250, 400], [UsageTracking::interval(), UsageTracking::batch(), UsageTracking::retention()]);
        self::assertSame([null, null], [UsageTracking::connection(), UsageTracking::queue()]);

        config(['authorization.usage' => []]);

        self::assertFalse(UsageTracking::isEnabled());
        self::assertSame([3600, 250, 400], [UsageTracking::interval(), UsageTracking::batch(), UsageTracking::retention()]);
    }

    /**
     * Each setting is read as configured.
     *
     * @return void
     */
    public function testEachSettingIsReadAsConfigured(): void
    {
        config(['authorization.usage' => ['enabled' => true, 'interval' => 86400, 'batch' => 50, 'retention' => 30, 'connection' => 'redis', 'queue' => 'usage']]);

        self::assertTrue(UsageTracking::isEnabled());
        self::assertSame([86400, 50, 30], [UsageTracking::interval(), UsageTracking::batch(), UsageTracking::retention()]);
        self::assertSame(['redis', 'usage'], [UsageTracking::connection(), UsageTracking::queue()]);
    }

    /**
     * A bucket starts at a whole multiple of the interval since the epoch, so
     * every instant within it shares its start.
     *
     * @return void
     */
    public function testABucketStartsAtAWholeMultipleOfTheInterval(): void
    {
        self::assertSame(7200, UsageTracking::bucketOf(7200, 3600));
        self::assertSame(7200, UsageTracking::bucketOf(10799, 3600));
        self::assertSame(10800, UsageTracking::bucketOf(10800, 3600));
        self::assertSame(-3600, UsageTracking::bucketOf(-1, 3600));
        self::assertSame(86400, UsageTracking::bucketOf(100000, 86400));
    }

    /**
     * A setting changed after boot to one the config check refuses is refused
     * when read.
     *
     * @return void
     */
    public function testASettingChangedAfterBootIsRefused(): void
    {
        config(['authorization.usage.interval' => 59]);

        $this->expectException(InvalidAuthorizationConfigException::class);
        $this->expectExceptionMessage('authorization.usage.interval');

        UsageTracking::interval();
    }
}
