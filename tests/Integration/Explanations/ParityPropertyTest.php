<?php

declare(strict_types = 1);

namespace Tests\Integration\Explanations;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionPipeline;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Integration\BulkChecks\ParityScenario;
use Tests\TestCase;

/**
 * The explain mode parity property (N89, D22): for random scenarios, drawn as
 * the bulk check parity property draws them, the check `explain()` makes is
 * exactly the one `check()` makes, its effect, reason, stage, deciding
 * statements, requirements, freshness and trace alike, once the evidence only
 * explain mode records is set aside; and a check that throws throws the same.
 *
 * The scenarios are drawn from `AUTHZ_PARITY_SEED`, a random seed when it is
 * not set, and there are `AUTHZ_PARITY_RUNS` of them, 60 by default; a failure
 * names the seed and the scenario, so it can be replayed. Each scenario runs in
 * a transaction of its own, rolled back after it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DecisionPipeline::class)]
final class ParityPropertyTest extends TestCase
{
    /** @var int The scenarios run when `AUTHZ_PARITY_RUNS` is not set. */
    private const int DEFAULT_RUNS = 60;

    /**
     * Each check is decided in explain mode as `check()` decides it, from a
     * cold cache.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testExplainModeDecidesAsCheckDecides(): void
    {
        [$seed, $runs] = self::seeding();
        $compared      = 0;

        for ($run = 0; $run < $runs; $run++) {
            $compared += $this->inScenario($seed + $run, function (ParityScenario $scenario): int {
                $scenario->build();

                $compared = 0;

                foreach ($scenario->batch() as $key => $check) {
                    $plain     = $this->attempt(static fn (): Decision => $scenario->manager->check($check->action, $check->resource, $check->context));
                    $explained = $this->attempt(static fn (): Decision => self::explained($scenario, $check));

                    self::assertEquals(self::comparable($plain), self::comparable($explained), "Check {$key} was explained otherwise than checked.\n{$scenario->replay()}");

                    $compared++;
                }

                return $compared;
            });
        }

        self::assertGreaterThan(0, $compared, "No check was compared; seed {$seed}.");
    }

    /**
     * Explain the check, and return the decision it made, as it was recorded as
     * the last decision, carrying its evidence.
     *
     * @param  \Tests\Integration\BulkChecks\ParityScenario  $scenario
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckInput  $check
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    private static function explained(ParityScenario $scenario, CheckInput $check): Decision
    {
        $explanation = $scenario->manager->explain($check->action, $check->resource, $check->context);
        $decision    = $scenario->manager->lastDecision();

        self::assertNotNull($decision, $scenario->replay());
        self::assertTrue($decision->hasEvidence(), $scenario->replay());
        self::assertEquals($explanation, $decision->explain(), $scenario->replay());

        return $decision;
    }

    /**
     * Return what the callback returns, or what it throws, from a cold cache.
     *
     * @param  \Closure(): \SineMacula\Laravel\Authorization\Evaluation\Decision  $decide
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision|\Throwable
     */
    private function attempt(\Closure $decide): Decision|\Throwable
    {
        $this->app?->forgetInstance(ResolutionCache::class);

        try {
            return $decide();
        } catch (\Throwable $exception) {
            return $exception;
        }
    }

    /**
     * Return the decision with the evidence only explain mode records set
     * aside, or what was thrown, by its class and message.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision|\Throwable  $outcome
     * @return array<string, mixed>
     */
    private static function comparable(Decision|\Throwable $outcome): array
    {
        if ($outcome instanceof \Throwable) {
            return ['thrown' => $outcome::class, 'message' => $outcome->getMessage()];
        }

        return [
            'effect'       => $outcome->effect,
            'reason'       => $outcome->reason,
            'stage'        => $outcome->stage,
            'statements'   => $outcome->statements,
            'requirements' => $outcome->requirements,
            'freshness'    => $outcome->freshness,
            'trace'        => \array_map(self::everyday(...), $outcome->trace),
        ];
    }

    /**
     * Return the step as an everyday check records it, without the condition
     * tests and the unresolved references only explain mode records.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\TraceEntry  $entry
     * @return \SineMacula\Laravel\Authorization\Evaluation\TraceEntry
     */
    private static function everyday(TraceEntry $entry): TraceEntry
    {
        return new TraceEntry($entry->stage, $entry->outcome, $entry->statement, $entry->conditions, $entry->cap, $entry->permission, $entry->dependencies);
    }

    /**
     * Run the scenario of the seed in a transaction of its own, rolled back
     * after it, with the state the package keeps for a request forgotten, and a
     * persistent store for every other scenario.
     *
     * @param  int  $seed
     * @param  \Closure(\Tests\Integration\BulkChecks\ParityScenario): int  $run
     * @return int
     *
     * @throws \PHPUnit\Framework\AssertionFailedError
     * @throws \RuntimeException
     */
    private function inScenario(int $seed, \Closure $run): int
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app    = $this->app;
        $config = $app->make(ConfigRepository::class);

        $config->set('authorization.cache.store', $seed % 2 === 0 ? 'array' : null);
        $app->make('cache')->store('array')->clear();
        $app->forgetInstance(ResolutionCache::class);

        DB::beginTransaction();

        $scenario = new ParityScenario($seed, $app);

        try {
            return $run($scenario);
        } catch (AssertionFailedError $failure) {
            throw $failure;
        } catch (\Throwable $exception) {
            throw new \RuntimeException("The scenario failed: {$exception->getMessage()}\n{$scenario->replay()}", 0, $exception);
        } finally {
            DB::rollBack();
            Carbon::setTestNow();

            $config->set('authorization.attributes.resources', []);

            foreach ([ResolutionCache::class, ResolvedTenant::class, CheckContextFactory::class, TenantTree::class, ResourceTenantResolver::class] as $abstract) {
                $app->forgetInstance($abstract);
            }
        }
    }

    /**
     * Return the seed of the first scenario and how many to run.
     *
     * @return array{int, int}
     *
     * @throws \Random\RandomException
     */
    private static function seeding(): array
    {
        $seed = \getenv('AUTHZ_PARITY_SEED');
        $runs = \getenv('AUTHZ_PARITY_RUNS');

        return [
            \is_string($seed) && $seed !== '' ? (int) $seed : \random_int(1, 1000000),
            \is_string($runs) && $runs !== '' ? \max(1, (int) $runs) : self::DEFAULT_RUNS,
        ];
    }
}
