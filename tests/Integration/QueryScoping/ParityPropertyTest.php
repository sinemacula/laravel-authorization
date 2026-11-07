<?php

declare(strict_types = 1);

namespace Tests\Integration\QueryScoping;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException;
use SineMacula\Laravel\Authorization\Query\AuthorizedQuery;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Query\QueryAuthorizer;
use SineMacula\Laravel\Authorization\Query\StatementScreen;
use SineMacula\Laravel\Authorization\Registrars\QueryScopeRegistrar;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\TestCase;

/**
 * The query scoping parity property (AUTHZ-10.1, N64): for random scenarios
 * within this release's subset, the rows `whereAuthorized()` keeps are exactly
 * the rows of the query's candidate set that `check()` allows on a freshly
 * loaded model, a check that throws counting as a denial; and a construct
 * outside the subset that a check would weigh is refused.
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
#[CoversClass(QueryScopeRegistrar::class)]
#[CoversClass(QueryAuthorizer::class)]
#[CoversClass(StatementScreen::class)]
#[CoversClass(AuthorizedQuery::class)]
final class ParityPropertyTest extends TestCase
{
    /** @var int The scenarios run when `AUTHZ_PARITY_RUNS` is not set. */
    private const int DEFAULT_RUNS = 150;

    /**
     * The rows the scope keeps are the rows `check()` allows.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheScopeKeepsExactlyTheRowsCheckAllows(): void
    {
        [$seed, $runs] = self::seeding();
        $compared      = 0;

        for ($run = 0; $run < $runs; $run++) {
            $compared += $this->inScenario($seed + $run, function (ParityScenario $scenario): int {
                $scenario->build();

                return $this->assertParity($scenario);
            });
        }

        self::assertGreaterThan(0, $compared, "No scenario compiled; seed {$seed}.");
    }

    /**
     * A construct outside this release's subset that a check would weigh is
     * refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConstructOutsideTheSubsetIsRefusedWhenMaterial(): void
    {
        [$seed, $runs] = self::seeding();

        for ($run = 0; $run < $runs; $run++) {
            $this->inScenario($seed + $run, static function (ParityScenario $scenario): int {
                $scenario->build(true);

                $query   = $scenario->model::query();
                $scope   = static fn (): mixed => $query->whereAuthorized($scenario->action, $scenario->context, $scenario->manager); // @phpstan-ignore method.notFound
                $refusal = self::refusalOf($scope);

                self::assertNotNull($refusal, "The construct was not refused.\n{$scenario->replay()}");
                self::assertNotSame([], $refusal->refusals, $scenario->replay());

                return 1;
            });
        }
    }

    /**
     * Run the scenario of the seed in a transaction of its own, rolled back
     * after it, with the state the package keeps for a request forgotten.
     *
     * @param  int  $seed
     * @param  \Closure(\Tests\Integration\QueryScoping\ParityScenario): int  $run
     * @return int
     *
     * @throws \PHPUnit\Framework\AssertionFailedError
     * @throws \RuntimeException
     */
    private function inScenario(int $seed, \Closure $run): int
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

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

            $app->make(ConfigRepository::class)->set('authorization.context.sources', []);

            foreach ([ResolutionCache::class, ResolvedTenant::class, CheckContextFactory::class] as $abstract) {
                $app->forgetInstance($abstract);
            }
        }
    }

    /**
     * Assert that the scoped query keeps exactly the candidates `check()`
     * allows, and return 1, or 0 when the scope was refused for admitting rows
     * of other tenants, which this release does not compile.
     *
     * @param  \Tests\Integration\QueryScoping\ParityScenario  $scenario
     * @return int
     *
     * @throws \Throwable
     */
    private function assertParity(ParityScenario $scenario): int
    {
        $constraints = $scenario->constraints();
        $after       = $scenario->after();
        $identity    = $scenario->identity();

        try {
            $query  = $constraints($scenario->model::query());
            $scoped = $after($query->whereAuthorized($scenario->action, $scenario->context, $scenario->manager)); // @phpstan-ignore method.notFound
        } catch (QueryScopeRefusedException $exception) {
            self::assertSame([RefusalReason::PLATFORM_ADMISSION], $exception->reasons(), $exception->getMessage() . "\n{$scenario->replay()}");

            return 0;
        }

        $kept       = self::identities($scoped, $identity);
        $candidates = self::identities($after($constraints($scenario->model::query())), $identity);
        $allowed    = \array_values(\array_filter($candidates, fn (string $row): bool => $this->isAllowed($scenario, $identity, $row)));

        self::assertSame($allowed, $kept, "The scope kept other rows than check() allows.\nSQL: {$scoped->toRawSql()}\n{$scenario->replay()}");

        return 1;
    }

    /**
     * Determine whether `check()` allows the row, loaded afresh with every
     * column; a check that throws is a denial.
     *
     * @param  \Tests\Integration\QueryScoping\ParityScenario  $scenario
     * @param  string  $identity
     * @param  string  $row
     * @return bool
     */
    private function isAllowed(ParityScenario $scenario, string $identity, string $row): bool
    {
        $model = $scenario->model::query()->where($identity, $row)->first();

        try {
            return $model !== null && $scenario->manager->check($scenario->action, $model, $scenario->context)->isAllowed();
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Return the identities of the rows the query returns, as text, sorted.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>  $query
     * @param  string  $identity
     * @return list<string>
     */
    private static function identities(Builder $query, string $identity): array
    {
        $rows = \array_map(static fn (Model $model): string => (string) $model->getAttribute($identity), $query->get()->all()); // @phpstan-ignore cast.string

        \sort($rows, \SORT_STRING);

        return $rows;
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

    /**
     * Return the refusal the callback throws, or null when it throws none.
     *
     * @param  \Closure(): mixed  $callback
     * @return \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException|null
     */
    private static function refusalOf(\Closure $callback): ?QueryScopeRefusedException
    {
        try {
            $callback();
        } catch (QueryScopeRefusedException $exception) {
            return $exception;
        }

        return null;
    }
}
