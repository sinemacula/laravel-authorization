<?php

declare(strict_types = 1);

namespace Tests\Integration\Administration;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\DependencyPins;
use SineMacula\Laravel\Authorization\Administration\OperationConstraints;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions as Actions;
use SineMacula\Laravel\Authorization\Support\PermissionCatalogue;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Concerns\AssertsDelegatedRefusals;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * The escalation property of delegated administration (AUTHZ-11.1): over random
 * scenarios, every delegated operation that commits leaves no subject with
 * authority beyond what the actor could hand out, and every operation refused
 * leaves nothing changed and dispatches no change event.
 *
 * `permissionsFor()` before and after each operation is the oracle, at the
 * platform and in every tenant of the scenario: for every subject that may take
 * an action after the operation that it could not before,
 *
 * - the actor may take the operation's own administration action there, so it
 *   administers the subject in that scope;
 * - the actor outranks the subject in that scope, its roles held there and
 *   above it counting, or the subject is the actor itself;
 * - a subject that is the actor was allowed `authorization:administration.self`
 *   there;
 * - the actor could take the action there itself, unless it holds a grantable
 *   right, or the operation lifts a boundary under
 *   `authorization:administration.unbounded`, which explicitly allow handing
 *   out what it does not hold.
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
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(OperationConstraints::class)]
#[CoversClass(DependencyPins::class)]
final class EscalationPropertyTest extends TestCase
{
    use AssertsDelegatedRefusals;

    /** @var int The scenarios run when `AUTHZ_PARITY_RUNS` is not set. */
    private const int DEFAULT_RUNS = 150;

    /** @var int The delegated operations each scenario makes. */
    private const int OPERATIONS = 2;

    /**
     * No committed operation hands out more than the actor could, and no
     * refused one changes anything.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoOperationEscalates(): void
    {
        [$seed, $runs] = self::seeding();
        $committed     = 0;

        for ($run = 0; $run < $runs; $run++) {
            $committed += $this->inScenario($seed + $run, function (EscalationScenario $scenario): int {
                $scenario->build();

                $made = 0;

                for ($index = 0; $index < self::OPERATIONS; $index++) {
                    $made += $this->assertOperation($scenario, ...$scenario->operation());
                }

                return $made;
            });
        }

        self::assertGreaterThan(0, $committed, "No operation committed; seed {$seed}.");
    }

    /**
     * Make the operation and assert the property of its outcome, returning 1
     * when it committed and 0 when it was refused.
     *
     * @param  \Tests\Integration\Administration\EscalationScenario  $scenario
     * @param  string  $description
     * @param  string  $action
     * @param  bool  $isUnbounding
     * @param  \Closure(): mixed  $call
     * @return int
     *
     * @throws \Throwable
     */
    private function assertOperation(EscalationScenario $scenario, string $description, string $action, bool $isUnbounding, \Closure $call): int
    {
        $before  = $this->listings($scenario);
        $rows    = self::writtenRows();
        $ranked  = $this->outranked($scenario);
        $changes = self::recording();
        $refusal = self::refusalOf($call);
        $after   = $this->listings($scenario);
        $replay  = "{$description}\n{$scenario->replay()}";

        if ($refusal !== null) {
            self::assertSame($before, $after, "A refused operation changed what a subject may do ({$refusal->getMessage()}).\n{$replay}");
            self::assertSame($rows, self::writtenRows(), "A refused operation wrote ({$refusal->getMessage()}).\n{$replay}");
            self::assertSame([], $changes->getArrayCopy(), "A refused operation dispatched a change event.\n{$replay}");

            return 0;
        }

        $isExplicit = $scenario->isGrantable || ($isUnbounding && self::isAllowedAnywhere($before['actor'], Actions::ADMINISTRATION_UNBOUNDED));

        foreach ($after as $subject => $scopes) {
            foreach ($scopes as $scope => $listed) {
                $gained = \array_values(\array_diff($listed, $before[$subject][$scope]));

                self::assertJustified($before['actor'][$scope], $subject, $gained, [$action, $ranked[$scope], $isExplicit, "in {$scope}.\n{$replay}"]);
            }
        }

        return 1;
    }

    /**
     * Assert that what the subject gained in a scope is justified by what the
     * actor could take there before the operation: the operation's action, so
     * it administers the scope; rank over the subject, or the subject is the
     * actor and was allowed `authorization:administration.self`; and every
     * action gained, unless the operation was explicitly allowed to hand out
     * what the actor does not hold.
     *
     * @param  list<string>  $actor
     * @param  string  $subject
     * @param  list<string>  $gained
     * @param  array{string, array<string, bool>, bool, string}  $operation
     * @return void
     */
    private static function assertJustified(array $actor, string $subject, array $gained, array $operation): void
    {
        [$action, $ranked, $isExplicit, $where] = $operation;

        if ($gained === []) {
            return;
        }

        $where = "{$subject} gained " . \implode(', ', $gained) . " {$where}";

        self::assertContains($action, $actor, "The actor does not administer the scope: {$where}");
        self::assertTrue($subject === 'actor' || ($ranked[$subject] ?? false), "The actor does not outrank the subject: {$where}");
        self::assertTrue($subject !== 'actor' || \in_array(Actions::ADMINISTRATION_SELF, $actor, true), "The actor benefited itself unallowed: {$where}");
        self::assertTrue($isExplicit || \array_diff($gained, $actor) === [], "The actor handed out what it could not take: {$where}");
    }

    /**
     * Make the call and return what refused it, or null when it committed; an
     * error or a database failure is no refusal, so it is thrown.
     *
     * @param  \Closure(): mixed  $call
     * @return \Throwable|null
     *
     * @throws \Error
     * @throws \Illuminate\Database\QueryException
     */
    private static function refusalOf(\Closure $call): ?\Throwable
    {
        try {
            $call();
        } catch (\Error|QueryException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            return $exception;
        }

        return null;
    }

    /**
     * Return what each subject may take at the platform and in every tenant, by
     * subject and scope, each listed with a cold cache.
     *
     * @param  \Tests\Integration\Administration\EscalationScenario  $scenario
     * @return array<string, array<string, list<string>>>
     */
    private function listings(EscalationScenario $scenario): array
    {
        $scopes = ['platform' => AuthorizationScope::platform()];

        foreach ($scenario->tenants as $tenant) {
            $scopes[EscalationScenario::key($tenant)] = AuthorizationScope::tenant($tenant);
        }

        $listings = [];

        foreach ($scenario->subjects as $subject) {
            foreach ($scopes as $name => $scope) {
                $this->forgetState();

                $listed = Authorization::permissionsFor($subject, $scope);

                \sort($listed);

                $listings[EscalationScenario::key($subject)][$name] = $listed;
            }
        }

        return $listings;
    }

    /**
     * Return, by scope, the platform and every tenant, and by subject, whether
     * the actor outranks it there, ranked as `canActOn()` ranks them in that
     * tenant's scope, so the actor's roles held in the tenant and above it
     * count, as the rank rule counts them in the tenant a change holds in.
     *
     * @param  \Tests\Integration\Administration\EscalationScenario  $scenario
     * @return array<string, array<string, bool>>
     */
    private function outranked(EscalationScenario $scenario): array
    {
        $ranked = [];

        foreach ([null, ...$scenario->tenants] as $tenant) {
            foreach ($scenario->subjects as $subject) {
                $this->forgetState();

                $actor = StubIdentity::query()->whereKey($scenario->actorModel->getKey())->firstOrFail();

                $scope = EscalationScenario::key($tenant, 'platform');

                $ranked[$scope][EscalationScenario::key($subject)] = TenantScope::within($tenant, null, static fn (): bool => $actor->canActOn($subject));
            }
        }

        return $ranked;
    }

    /**
     * Determine whether the actor may take the action in any scope.
     *
     * @param  array<string, list<string>>  $actor
     * @param  string  $action
     * @return bool
     */
    private static function isAllowedAnywhere(array $actor, string $action): bool
    {
        foreach ($actor as $listed) {
            if (\in_array($action, $listed, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Record the package's change events from now on, forgetting those recorded
     * before.
     *
     * @return \ArrayObject<int, string>
     */
    private static function recording(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $changes */
        $changes = new \ArrayObject;

        Event::forget('*');
        Event::listen('*', static function (string $name, array $payload) use ($changes): void {
            $event = $payload[0] ?? null;

            if (!$event instanceof AuthorizationEvent || $event instanceof DecisionEvaluated || $event instanceof AuthorizationFailed) {
                return;
            }

            $changes->append($event::class);
        });

        return $changes;
    }

    /**
     * Run the scenario of the seed in a transaction of its own, rolled back
     * after it, with the state the package keeps for a request forgotten.
     *
     * @param  int  $seed
     * @param  \Closure(\Tests\Integration\Administration\EscalationScenario): int  $run
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

        $this->forgetState();

        DB::beginTransaction();

        $scenario = null;

        try {
            $scenario = new EscalationScenario($seed, $app);

            return $run($scenario);
        } catch (AssertionFailedError $failure) {
            throw $failure;
        } catch (\Throwable $exception) {
            throw new \RuntimeException("The scenario failed: {$exception->getMessage()}\n" . ($scenario?->replay() ?? "Seed {$seed}."), 0, $exception);
        } finally {
            DB::rollBack();
            Event::forget('*');

            $config->set('authorization.permission_providers', []);

            foreach ([PermissionCatalogue::class, TenantTree::class] as $abstract) {
                $app->forgetInstance($abstract);
            }

            $this->forgetState();
        }
    }

    /**
     * Forget the state the package keeps for a request or job, so the next
     * listing starts cold.
     *
     * @return void
     */
    private function forgetState(): void
    {
        foreach ([ResolutionCache::class, ResolvedTenant::class, CheckContextFactory::class, 'authorization'] as $abstract) {
            $this->app?->forgetInstance($abstract);
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
