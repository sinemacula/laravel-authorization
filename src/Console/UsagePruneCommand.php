<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Authorization\Usage\UsagePruner;
use SineMacula\Laravel\Authorization\Usage\UsageTracking;

/**
 * Prunes the package's grant usage tables (N102): the usage of every route
 * whose stored grant no longer exists, and the coverage that ended more than
 * `authorization.usage.retention` days ago.
 *
 * Schedulable, and shaped like `authorization:prune`: `--pretend` reports what
 * would be removed without removing it. It prunes the package's own tables,
 * whatever store is bound; a store an application binds keeps its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class UsagePruneCommand extends Command
{
    /** @var string The console command signature. */
    protected $signature = <<<'EOD'
        authorization:usage-prune
                                    {--pretend : Report how many rows would be removed, without removing them}
        EOD;

    /** @var string The console command description. */
    protected $description = 'Remove the usage of grants that no longer exist and the coverage older than the retention';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        $pretend = $this->option('pretend') === true;

        [$usage, $coverage] = UsagePruner::prune(UsageTracking::retention(), $pretend);

        $this->info(\sprintf(
            '%s the usage of %d grant route(s) whose grant no longer exists and %d coverage period(s) older than %d day(s).',
            $pretend ? 'Would prune' : 'Pruned',
            $usage,
            $coverage,
            UsageTracking::retention(),
        ));

        return self::SUCCESS;
    }
}
