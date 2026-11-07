<?php

declare(strict_types = 1);

namespace Tests\Integration\PermissionsFor;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\CheckBatch;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\PermissionCatalogue;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Feature\Stubs\FixedSubjectResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * The `permissionsFor()` parity property (AUTHZ-10.4, N69, N70): for random
 * scenarios, the actions `permissionsFor()` lists are exactly those of the
 * catalogue, in its order, each once, for which a fresh `check()` in the same
 * scope (entered with `TenantScope::within()`), about the same subject, with
 * the same context, allows; when one of those checks throws, the listing throws
 * what it throws. The listing records nothing: the last decision is the one
 * recorded before it, and no decision event is dispatched. Each listing is made
 * with a cold cache and again with the cache it warmed, with and without a
 * persistent store.
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
#[CoversClass(AuthorizationManager::class)]
#[CoversClass(AuthorizationScope::class)]
#[CoversClass(CheckBatch::class)]
final class ParityPropertyTest extends TestCase
{
    /** @var int The scenarios run when `AUTHZ_PARITY_RUNS` is not set. */
    private const int DEFAULT_RUNS = 150;

    /**
     * The actions listed are those a fresh `check()` allows, with a cold cache
     * and a warm one, and listing them records nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheActionsListedAreThoseCheckAllows(): void
    {
        [$seed, $runs] = self::seeding();
        $compared      = 0;

        for ($run = 0; $run < $runs; $run++) {
            $compared += $this->inScenario($seed + $run, function (ListingScenario $scenario): int {
                $scenario->build();

                $named   = $scenario->subject();
                $scope   = $scenario->scope();
                $context = $scenario->context;
                $single  = $this->singly($scenario, self::checkedSubject($scenario, $named, $scope), $scope, $context);

                $this->forgetCache();

                return $this->assertParity($scenario, $named, $scope, $context, $single, 'cold')
                    + $this->assertParity($scenario, $named, $scope, $context, $single, 'warm');
            });
        }

        self::assertGreaterThan(0, $compared, "No listing was compared; seed {$seed}.");
    }

    /**
     * Run the scenario of the seed in a transaction of its own, rolled back
     * after it, with the state the package keeps for a request forgotten, and a
     * persistent store for every other scenario.
     *
     * @param  int  $seed
     * @param  \Closure(\Tests\Integration\PermissionsFor\ListingScenario): int  $run
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

        $scenario = new ListingScenario($seed, $app);

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
            $config->set('authorization.permission_enums', []);
            $config->set('authorization.permission_providers', []);

            foreach ([ResolutionCache::class, ResolvedTenant::class, CheckContextFactory::class, TenantTree::class] as $abstract) {
                $app->forgetInstance($abstract);
            }
        }
    }

    /**
     * Return the actions of the catalogue, in its order, each once, that a
     * fresh `check()` in the scope, about the subject, with the context,
     * allows, each with a cold cache; or what the first check that throws
     * throws.
     *
     * @param  \Tests\Integration\PermissionsFor\ListingScenario  $scenario
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @param  \SineMacula\Laravel\Authorization\Support\AuthorizationScope  $scope
     * @param  array<string, mixed>  $context
     * @return list<string>|\Throwable
     */
    private function singly(ListingScenario $scenario, ?Subject $subject, AuthorizationScope $scope, array $context): array|\Throwable
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app     = $this->app;
        $request = $app->make(SubjectResolver::class);

        /** @var \SineMacula\Laravel\Authorization\Support\PermissionCatalogue $catalogue */
        $catalogue = $app->make(PermissionCatalogue::class);
        $actions   = [];

        foreach ($catalogue->definitions() as $definition) {
            $actions[$definition->name] = $definition;
        }

        $app->instance(SubjectResolver::class, new FixedSubjectResolver($subject));

        try {
            $manager = $scenario->manager();
            $allowed = [];

            foreach ($actions as $action => $definition) {
                if (!$this->isAllowed($manager, $definition, $scope, $context)) {
                    continue;
                }

                $allowed[] = $action;
            }
        } catch (\Throwable $exception) {
            return $exception;
        } finally {
            $app->instance(SubjectResolver::class, $request);
            $app->forgetInstance(ResolvedTenant::class);
        }

        return $allowed;
    }

    /**
     * Determine whether a fresh `check()` of the action, in the scope, on its
     * resource, with the context, allows, with a cold cache, throwing what the
     * check throws once the scope is left.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $manager
     * @param  \SineMacula\Laravel\Authorization\Support\PermissionDefinition  $definition
     * @param  \SineMacula\Laravel\Authorization\Support\AuthorizationScope  $scope
     * @param  array<string, mixed>  $context
     * @return bool
     *
     * @throws \Throwable
     */
    private function isAllowed(AuthorizationManager $manager, PermissionDefinition $definition, AuthorizationScope $scope, array $context): bool
    {
        $this->forgetCache();

        $outcome = TenantScope::within($scope->tenant, $scope->application, static function () use ($manager, $definition, $scope, $context): bool|\Throwable {
            try {
                return $manager->check($definition->name, $scope->resource, $context)->isAllowed();
            } catch (\Throwable $exception) {
                return $exception;
            }
        });

        return $outcome instanceof \Throwable ? throw $outcome : $outcome;
    }

    /**
     * Assert that `permissionsFor()` lists the actions a fresh `check()`
     * allows, or throws what it threw, and records nothing, and return how many
     * listings were compared.
     *
     * @param  \Tests\Integration\PermissionsFor\ListingScenario  $scenario
     * @param  \SineMacula\Laravel\Authorization\Subject|\Tests\Feature\Stubs\StubIdentity|null  $named
     * @param  \SineMacula\Laravel\Authorization\Support\AuthorizationScope  $scope
     * @param  array<string, mixed>  $context
     * @param  list<string>|\Throwable  $single
     * @param  string  $cache
     * @return int
     */
    private function assertParity(
        ListingScenario $scenario,
        StubIdentity|Subject|null $named,
        AuthorizationScope $scope,
        array $context,
        array|\Throwable $single,
        string $cache,
    ): int {
        $manager  = $scenario->manager();
        $before   = $manager->check('other:act');
        $reported = 0;

        /** @var \Illuminate\Events\Dispatcher $events */
        $events = $this->app?->make(Dispatcher::class);
        $events->listen([DecisionEvaluated::class, AuthorizationFailed::class], static function () use (&$reported): void {
            $reported++;
        });

        try {
            $listed = $manager->permissionsFor($named, $scope, $context);
            $thrown = null;
        } catch (\Throwable $exception) {
            $listed = null;
            $thrown = $exception;
        } finally {
            $events->forget(DecisionEvaluated::class);
            $events->forget(AuthorizationFailed::class);
        }

        $replay = "With a {$cache} cache.\n{$scenario->replay()}";

        self::assertSame(0, $reported, "The listing dispatched a decision event.\n{$replay}");
        self::assertSame($before, $manager->lastDecision(), "The listing recorded a decision.\n{$replay}");

        if ($single instanceof \Throwable) {
            self::assertNotNull($thrown, "The listing did not throw.\n{$replay}");
            self::assertSame($single::class, $thrown::class, $replay);
            self::assertSame($single->getMessage(), $thrown->getMessage(), $replay);

            return 0;
        }

        self::assertNull($thrown, "The listing threw: {$thrown?->getMessage()}\n{$replay}");
        self::assertSame($single, $listed, "The listing differs from what check() allows.\n{$replay}");

        return 1;
    }

    /**
     * Return the subject a check is about when the listing names the given one
     * in the scope: none for a guest, a resolved subject with the scope's
     * tenant and application, and a model as `for()` names it, from the
     * request's subject, in the scope.
     *
     * @param  \Tests\Integration\PermissionsFor\ListingScenario  $scenario
     * @param  \SineMacula\Laravel\Authorization\Subject|\Tests\Feature\Stubs\StubIdentity|null  $named
     * @param  \SineMacula\Laravel\Authorization\Support\AuthorizationScope  $scope
     * @return \SineMacula\Laravel\Authorization\Subject|null
     */
    private static function checkedSubject(ListingScenario $scenario, StubIdentity|Subject|null $named, AuthorizationScope $scope): ?Subject
    {
        if ($named instanceof Subject) {
            return new Subject($named->subject, $named->identity, $scope->tenant, $scope->application, $named->guard, $named->session);
        }

        // The model is the request's own, so `for()` keeps its identity and
        // guard, and drops its session.
        $request = $scenario->request;

        return $named === null ? null : new Subject($named, $request?->identity, $scope->tenant, $scope->application, $request?->guard);
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
