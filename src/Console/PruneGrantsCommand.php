<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Authorization\Services\GrantPruner;

/**
 * Removes the grants that no longer count: those that have expired, and those
 * whose grantee no longer exists (AUTHZ-17.6).
 *
 * Schedulable, and shaped like Laravel's `model:prune`: `--pretend` reports
 * what would be removed without removing it, and `--chunk` sets how many rows
 * each pass reads. Grants that have expired already stop counting at their
 * expiry, so pruning keeps the grant tables small rather than making checks
 * correct. A grantee type that names no model class is reported and its grants
 * are left.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PruneGrantsCommand extends Command
{
    /** @var string The console command signature. */
    protected $signature = <<<'EOD'
        authorization:prune
                                    {--pretend : Report how many grants would be removed, without removing them}
                                    {--chunk=1000 : How many rows each pass reads}
        EOD;

    /** @var string The console command description. */
    protected $description = 'Remove expired grants and the grants of grantees that no longer exist';

    /**
     * Execute the console command.
     *
     * @param  \SineMacula\Laravel\Authorization\Services\GrantPruner  $pruner
     * @return int
     *
     * @throws \Throwable
     */
    public function handle(GrantPruner $pruner): int
    {
        $chunk = \filter_var($this->option('chunk'), \FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);

        if ($chunk === false) {
            $this->error('The chunk must be a whole number of at least 1.');

            return self::INVALID;
        }

        $pretend = (bool) $this->option('pretend');
        $result  = $pruner->prune($chunk, $pretend);

        foreach ($result->unresolvedTypes as $type) {
            $this->warn("Grantee type '{$type}' names no model class; its grants were left.");
        }

        $this->info(\sprintf(
            '%s %d expired grant(s) and %d grant(s) of grantees that no longer exist.',
            $pretend ? 'Would prune' : 'Pruned',
            $result->expired,
            $result->orphaned,
        ));

        return self::SUCCESS;
    }
}
