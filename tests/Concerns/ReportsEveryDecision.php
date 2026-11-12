<?php

declare(strict_types = 1);

namespace Tests\Concerns;

/**
 * Report every decision with `DecisionEvaluated`, allows included, for a test
 * that observes the decisions a call makes rather than which of them the
 * shipped settings report (see `authorization.events.decisions`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait ReportsEveryDecision
{
    /**
     * Report every allow as well as every denial and preview, as the settings
     * are read for each batch of checks made from now on.
     *
     * @return void
     */
    protected function reportEveryDecision(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->container()->make('config');
        $config->set('authorization.events.decisions.allows', 'all');
    }
}
