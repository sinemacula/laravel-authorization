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
 * platform and in every tenant of the scenario, with no resource and on a post,
 * which the resource policies of the scenario reach: for every subject that may
 * take an action after the operation that it could not before,
 *
 * - the actor may take the operation's own administration action there, so it
 *   administers the subject in that scope;
 * - the actor outranks the subject in that scope, its roles held there and
 *   above it counting, both before the operation and after it, or the subject
 *   is the actor itself;
 * - a subject that is the actor was allowed `authorization:administration.self`
 *   there;
 * - the actor could take the action there itself, or holds a grantable right
 *   covering it (every action under `authorization:*`, or the one permission a
 *   narrower right names), unless the operation lifts a boundary under
 *   `authorization:administration.unbounded`, which explicitly allows handing
 *   out what the actor does not hold.
 *
 * And no operation that changes a subject other than the actor leaves any
 * subject the actor outranked in a scope as senior as the actor there, gained
 * an action or not.
 *
 * The operations are grants of permissions, roles and policies, syncs of each,
 * attachments to the posts of policies naming principals, revocations, boundary
 * changes, and changes to what a role carries, its parent and a policy's
 * document. Two roles carry nothing, so a grant of either is weighed on one
 * rule alone: one of the most senior rank, and one a resource policy on the
 * posts names.
 *
 * The scenarios are drawn from `AUTHZ_PARITY_SEED`, a random seed when it is
 * not set, and there are `AUTHZ_PARITY_RUNS` of them, 150 by default; a failure
 * names the seed and the scenario, so it can be replayed. Each scenario runs in
 * a transaction of its own, rolled back after it. A sweep of more than one
 * scenario must commit some operation, so it is never vacuous; one scenario
 * replayed alone may refuse every operation it makes, as a scenario whose
 * escalation is now refused does.
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

        self::assertTrue($runs === 1 || $committed > 0, "No operation committed; seed {$seed}.");
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

        $grantable = $isUnbounding && self::isAllowedAnywhere($before['actor'], Actions::ADMINISTRATION_UNBOUNDED) ? ['*'] : $scenario->grantable;
        $still     = $this->outranked($scenario);

        self::assertNoneRanked($scenario->target === $scenario->actorModel ? [] : $ranked, $still, $replay);

        foreach ($after as $subject => $scopes) {
            foreach ($scopes as $scope => $listed) {
                $gained = \array_values(\array_diff($listed, $before[$subject][$scope]));
                $place  = \explode('@', $scope)[0];
                $senior = ($ranked[$place][$subject] ?? false) && ($still[$place][$subject] ?? false);

                self::assertJustified($before['actor'][$scope], $subject, $gained, [$action, $senior, $grantable, "in {$scope}.\n{$replay}"]);
            }
        }

        return 1;
    }

    /**
     * Assert that what the subject gained in a scope is justified by what the
     * actor could take there before the operation: the operation's action, so
     * it administers the scope; rank over the subject before and after the
     * operation, or the subject is the actor and was allowed
     * `authorization:administration.self`; and every action gained, held by the
     * actor or covered by a grantable right it holds.
     *
     * @param  list<string>  $actor
     * @param  string  $subject
     * @param  list<string>  $gained
     * @param  array{string, bool, list<string>, string}  $operation
     * @return void
     */
    private static function assertJustified(array $actor, string $subject, array $gained, array $operation): void
    {
        [$action, $isSenior, $grantable, $where] = $operation;

        if ($gained === []) {
            return;
        }

        $where    = "{$subject} gained " . \implode(', ', $gained) . " {$where}";
        $unbacked = \array_filter($gained, static fn (string $gain): bool => !\in_array($gain, $actor, true) && !self::isCovered($grantable, $gain));

        self::assertContains($action, $actor, "The actor does not administer the scope: {$where}");
        self::assertTrue($subject === 'actor' || $isSenior, "The actor does not outrank the subject before and after: {$where}");
        self::assertTrue($subject !== 'actor' || \in_array(Actions::ADMINISTRATION_SELF, $actor, true), "The actor benefited itself unallowed: {$where}");
        self::assertSame([], \array_values($unbacked), "The actor handed out what it could not take: {$where}");
    }

    /**
     * Assert that every subject but the actor the actor outranked in a scope
     * before an operation that changed someone else, it still outranks there
     * after it: no operation leaves a subject as senior as the actor, whether
     * or not it gained an action.
     *
     * @param  array<string, array<string, bool>>  $before
     * @param  array<string, array<string, bool>>  $after
     * @param  string  $replay
     * @return void
     */
    private static function assertNoneRanked(array $before, array $after, string $replay): void
    {
        foreach ($before as $scope => $subjects) {
            foreach ($subjects as $subject => $isOutranked) {
                self::assertTrue($subject === 'actor' || !$isOutranked || $after[$scope][$subject], "The operation left {$subject} as senior as the actor in {$scope}.\n{$replay}");
            }
        }
    }

    /**
     * Determine whether a grantable right covers the action: one of the
     * patterns matches it.
     *
     * @param  list<string>  $grantable
     * @param  string  $action
     * @return bool
     */
    private static function isCovered(array $grantable, string $action): bool
    {
        foreach ($grantable as $pattern) {
            if (\fnmatch($pattern, $action, \FNM_NOESCAPE)) {
                return true;
            }
        }

        return false;
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
     * Return what each subject may take at the platform and in every tenant,
     * with no resource and on a post, by subject and scope, each listed with a
     * cold cache.
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

        foreach ($scopes as $name => $scope) {
            $scopes[$name . '@post'] = $scope->withResource(['post', 'p1']);
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
