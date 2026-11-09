<?php

declare(strict_types = 1);

namespace Tests\Feature\Usage;

use Carbon\CarbonImmutable;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Console\UsageHeartbeatCommand;
use SineMacula\Laravel\Authorization\Contracts\GrantUsageStore;
use SineMacula\Laravel\Authorization\Usage\CoveragePeriod;
use SineMacula\Laravel\Authorization\Usage\DatabaseGrantUsageStore;
use Tests\Fixtures\Usage\CountingUsageStore;
use Tests\TestCase;

/**
 * Feature tests for `authorization:usage-heartbeat`: it keeps a quiet but
 * tracking site covered by extending the coverage to now through the bound
 * store, and records nothing while tracking is off.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UsageHeartbeatCommand::class)]
final class UsageHeartbeatCommandTest extends TestCase
{
    /**
     * Reset the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * Heartbeats an interval apart keep one period open across a quiet site,
     * through the store bound.
     *
     * @return void
     */
    public function testAHeartbeatKeepsAQuietSiteCovered(): void
    {
        config(['authorization.usage.enabled' => true]);

        $store = new CountingUsageStore(new DatabaseGrantUsageStore);

        $this->app?->instance(GrantUsageStore::class, $store);

        foreach (['08:00:00', '09:00:00', '10:00:00'] as $time) {
            Carbon::setTestNow('2026-11-09 ' . $time);

            self::assertSame(0, Artisan::call('authorization:usage-heartbeat'));
            self::assertSame('Grant usage coverage extended to 2026-11-09T' . $time . 'Z.', \trim(Artisan::output()));
        }

        $periods = $store->coverage(CarbonImmutable::parse('2026-11-09 00:00:00'), CarbonImmutable::parse('2026-11-10 00:00:00'));

        $bounds = static fn (CoveragePeriod $period): array => [$period->from->format('Y-m-d H:i:s'), $period->until->format('Y-m-d H:i:s')];

        self::assertSame([['2026-11-09 08:00:00', '2026-11-09 10:00:00']], \array_map($bounds, $periods));
        self::assertCount(3, $store->batches);
        self::assertSame([], $store->batches[0]->observations);
    }

    /**
     * With tracking off the heartbeat records nothing, so coverage never claims
     * a period nothing was watched in.
     *
     * @return void
     */
    public function testWithTrackingOffNothingIsRecorded(): void
    {
        $store = new CountingUsageStore(new DatabaseGrantUsageStore);

        $this->app?->instance(GrantUsageStore::class, $store);

        self::assertSame(0, Artisan::call('authorization:usage-heartbeat'));
        self::assertSame('Grant usage tracking is off; no coverage was recorded.', \trim(Artisan::output()));

        self::assertSame([], $store->batches);
    }
}
