<?php

declare(strict_types = 1);

namespace Tests\Integration\BulkChecks;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Context\ResourceAttributeBatch;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\CheckBatch;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver;
use SineMacula\Laravel\Authorization\Support\PrefetchedResourceTenants;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\TestCase;

/**
 * The bulk check parity property (AUTHZ-10.3, D22): for random scenarios, the
 * decision `checkMany()` makes for each check is exactly the one a fresh
 * `check()` makes for it, its effect, reason, stage, deciding statements,
 * requirements, freshness and trace alike; a batch whose check throws stops at
 * that check, having decided and reported exactly the checks before it, and
 * throws what `check()` throws for it. Each batch is decided with a cold cache
 * and again with the cache it warmed, with and without a persistent store.
 *
 * The scenarios are drawn from `AUTHZ_PARITY_SEED`, a random seed when it is
 * not set, and there are `AUTHZ_PARITY_RUNS` of them, 150 by default; a failure
 * names the seed and the scenario, so it can be replayed. Each scenario runs in
 * a transaction of its own, rolled back after it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckBatch::class)]
#[CoversClass(PrefetchedResourceTenants::class)]
#[CoversClass(ResourceAttributeBatch::class)]
#[CoversClass(ResourcePolicyResolver::class)]
final class ParityPropertyTest extends TestCase
{
    /** @var int The scenarios run when `AUTHZ_PARITY_RUNS` is not set. */
    private const int DEFAULT_RUNS = 150;

    /**
     * Each check of a batch is decided as a fresh `check()` decides it, with a
     * cold cache and a warm one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachCheckOfABatchIsDecidedAsCheckDecidesIt(): void
    {
        [$seed, $runs] = self::seeding();
        $compared      = 0;

        for ($run = 0; $run < $runs; $run++) {
            $compared += $this->inScenario($seed + $run, function (ParityScenario $scenario): int {
                $scenario->build();

                $checks = $scenario->batch();
                $single = $this->singly($scenario, $checks);

                $this->forgetCache();

                return $this->assertParity($scenario, $checks, $single, 'cold') + $this->assertParity($scenario, $checks, $single, 'warm');
            });
        }

        self::assertGreaterThan(0, $compared, "No check was compared; seed {$seed}.");
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
        $this->forgetCache();

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
     * Return what a fresh `check()` gives each check, each with a cold cache:
     * its decision, or what it throws.
     *
     * @param  \Tests\Integration\BulkChecks\ParityScenario  $scenario
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Evaluation\CheckInput>  $checks
     * @return array<array-key, \SineMacula\Laravel\Authorization\Evaluation\Decision|\Throwable>
     */
    private function singly(ParityScenario $scenario, array $checks): array
    {
        $single = [];

        foreach ($checks as $key => $check) {
            $this->forgetCache();

            try {
                $single[$key] = $scenario->manager->check($check->action, $check->resource, $check->context);
            } catch (\Throwable $exception) {
                $single[$key] = $exception;
            }
        }

        return $single;
    }

    /**
     * Assert that the batch decides and reports each check as `check()` decided
     * it, up to the first check that threw, which the batch throws too, and
     * return how many checks were compared.
     *
     * @param  \Tests\Integration\BulkChecks\ParityScenario  $scenario
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Evaluation\CheckInput>  $checks
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Evaluation\Decision|\Throwable>  $single
     * @param  string  $cache
     * @return int
     */
    private function assertParity(ParityScenario $scenario, array $checks, array $single, string $cache): int
    {
        $reported = [];

        /** @var \Illuminate\Events\Dispatcher $events */
        $events = $this->app?->make(Dispatcher::class);
        $events->listen(DecisionEvaluated::class, static function (DecisionEvaluated $event) use (&$reported): void {
            $reported[] = $event->decision;
        });

        try {
            $bulk   = $scenario->manager->checkMany($checks);
            $thrown = null;
        } catch (\Throwable $exception) {
            $bulk   = null;
            $thrown = $exception;
        } finally {
            $events->forget(DecisionEvaluated::class);
        }

        $replay   = "With a {$cache} cache.\n{$scenario->replay()}";
        $expected = [];

        foreach ($single as $key => $outcome) {
            if ($outcome instanceof \Throwable) {
                self::assertNotNull($thrown, "The batch did not throw at check {$key}.\n{$replay}");
                self::assertSame($outcome::class, $thrown::class, $replay);
                self::assertSame($outcome->getMessage(), $thrown->getMessage(), $replay);

                break;
            }

            $expected[$key] = $outcome;
        }

        self::assertEquals(\array_values($expected), $reported, "The batch reported other decisions than check() makes.\n{$replay}");

        if ($thrown === null) {
            self::assertSame(\array_keys($checks), \array_keys($bulk ?? []), $replay);
            self::assertEquals($expected, $bulk, "The batch made other decisions than check() makes.\n{$replay}");
            $last = $reported === [] ? null : $reported[\count($reported) - 1];

            self::assertSame($last, $scenario->manager->lastDecision(), "The last decision is not the batch's last.\n{$replay}");
        }

        return \count($expected);
    }

    /**
     * Forget the resolution cache, so the next check starts cold.
     *
     * @return void
     */
    private function forgetCache(): void
    {
        $this->app?->forgetInstance(ResolutionCache::class);
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
