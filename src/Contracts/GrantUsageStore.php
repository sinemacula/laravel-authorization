<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authorization\Usage\UsageBatch;

/**
 * Where grant usage is kept (N102): each grant route's last observed use, and
 * the periods tracking was on, so a review can tell a grant nobody used from
 * one whose use was never watched.
 *
 * The package binds a store on its own tables (see
 * `Usage\DatabaseGrantUsageStore`); an application may bind its own, to send
 * usage elsewhere.
 *
 * - `record()` keeps a batch of observations: for each route, the start of the
 *   last bucket it was observed in, never moving it backwards, so a batch
 *   delivered twice, or after a later one, changes nothing; an observation of a
 *   grant created before the one already kept (a revoked grant made again) is
 *   ignored, and one of a grant created after it replaces it. It then extends
 *   the coverage to the batch's instant, opening a new period when the gap
 *   since the last one ended exceeds two intervals. A batch with no
 *   observations only extends the coverage, as the heartbeat does. A batch that
 *   names a `lostSince`, the start of the earliest bucket the worker dropped
 *   observations from, must not leave the time since then covered, so the
 *   routes whose use was dropped read `unknown` rather than `unused`.
 * - `lastObserved()` returns what is kept for each of the route keys asked
 *   about that has any.
 * - `coverage()` returns the periods tracking was on that overlap the window.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface GrantUsageStore
{
    /**
     * Keep the batch's observations, each only when it is newer than what is
     * kept for its route, and extend the coverage to the batch's instant.
     *
     * @param  \SineMacula\Laravel\Authorization\Usage\UsageBatch  $batch
     * @return void
     */
    public function record(UsageBatch $batch): void;

    /**
     * Return what is kept of each of the route keys that has any, by its key.
     *
     * @param  list<string>  $keys
     * @return array<string, \SineMacula\Laravel\Authorization\Usage\ObservedUse>
     */
    public function lastObserved(array $keys): array;

    /**
     * Return the periods tracking was on that overlap the UTC half-open window
     * `[from, until)`, in the order they began.
     *
     * @param  \Carbon\CarbonImmutable  $from
     * @param  \Carbon\CarbonImmutable  $until
     * @return list<\SineMacula\Laravel\Authorization\Usage\CoveragePeriod>
     */
    public function coverage(CarbonImmutable $from, CarbonImmutable $until): array;
}
