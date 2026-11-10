<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Contracts\GrantUsageStore;
use SineMacula\Laravel\Authorization\Usage\UsageBatch;
use SineMacula\Laravel\Authorization\Usage\UsageTracking;

/**
 * Extends the coverage of grant usage tracking to now (N102), as every flush of
 * observations does, so a site that is quiet but tracking stays covered and its
 * unused grants read as unused rather than unknown.
 *
 * Schedule it at least once an interval (`authorization.usage.interval`, an
 * hour by default): coverage is continuous only while no two flushes or
 * heartbeats are more than two intervals apart. With tracking off it records
 * nothing, so coverage never claims a period nothing was watched in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class UsageHeartbeatCommand extends Command
{
    /** @var string The console command's name. */
    public const string NAME = 'authorization:usage-heartbeat';

    /** @var string The console command signature. */
    protected $signature = self::NAME;

    /** @var string The console command description. */
    protected $description = 'Extend the coverage of grant usage tracking to now, so a quiet site stays covered';

    /**
     * Execute the console command.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\GrantUsageStore  $store
     * @return int
     */
    public function handle(GrantUsageStore $store): int
    {
        if (!UsageTracking::isEnabled()) {
            $this->warn('Grant usage tracking is off; no coverage was recorded.');

            return self::SUCCESS;
        }

        $store->record(UsageBatch::of([], Carbon::now()->getTimestamp()));

        $this->info('Grant usage coverage extended to ' . Carbon::now('UTC')->format('Y-m-d\TH:i:s\Z') . '.');

        return self::SUCCESS;
    }
}
