<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Authorization\Services\GrantPruner;

/**
 * Removes the grants that no longer count: those that have expired, those whose
 * grantee no longer exists, and the resource policy attachments whose record no
 * longer exists (AUTHZ-17.6).
 *
 * Schedulable, and shaped like Laravel's `model:prune`: `--pretend` reports
 * what would be removed without removing it, and `--chunk` sets how many rows
 * each pass reads. Grants that have expired already stop counting at their
 * expiry, so pruning keeps the grant tables small rather than making checks
 * correct. The permission boundaries and inline policies of a grantee that no
 * longer exists are removed too, the boundaries counted apart from the grants.
 * A grantee type that names no model class is reported and its grants,
 * boundaries and inline policies are left; a resource type that names no model
 * class is reported and its records' attachments are left. A whole type's
 * attachments are never removed. A break-glass activation that expired without
 * ending is kept, its expiry recorded.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PruneGrantsCommand extends Command
{
    /** @var string The console command's name. */
    public const string NAME = 'authorization:prune';

    /** @var string The console command signature. */
    protected $signature = self::NAME . <<<'EOD'

                                    {--pretend : Report how many grants would be removed and break-glass expiries recorded, without writing them}
                                    {--chunk=1000 : How many rows each pass reads}
        EOD;

    /** @var string The console command description. */
    protected $description = 'Remove expired grants, the grants, boundaries and inline policies of grantees that are gone and the resource policies of records that are gone,'
        . ' and record the expiry of break-glass activations that expired without ending';

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

        $pretend = $this->option('pretend') === true;
        $result  = $pruner->prune($chunk, $pretend);

        foreach ($result->unresolvedTypes as $type) {
            $this->warn("Grantee type '{$type}' names no model class; its grants, boundaries and inline policies were left.");
        }

        foreach ($result->unresolvedResourceTypes as $type) {
            $this->warn("Resource type '{$type}' names no model class; the policies attached to its records were left.");
        }

        $this->info(\sprintf(
            '%s %d expired grant(s), %d grant(s) of grantees that no longer exist, %d boundar(ies) of grantees that no longer exist,'
                . ' %d inline polic(ies) of grantees that no longer exist and %d resource polic(ies) attached to records that no longer exist;'
                . ' %s the expiry of %d break-glass activation(s).',
            $pretend ? 'Would prune' : 'Pruned',
            $result->expired,
            $result->orphaned,
            $result->boundaries,
            $result->inlinePolicies,
            $result->resourcePolicies,
            $pretend ? 'would record' : 'recorded',
            $result->activations,
        ));

        return self::SUCCESS;
    }
}
