<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Carbon\CarbonImmutable;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\DependencyPins;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\VersionedStore;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\Identity\RoleAssigned;
use SineMacula\Laravel\Authorization\Events\SystemOverrideUsed;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException;
use SineMacula\Laravel\Authorization\Exceptions\GrantHookRecursionException;
use SineMacula\Laravel\Authorization\Exceptions\TransactionConflictException;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\UsesAnAuthorizationConnection;
use Tests\Feature\Stubs\FailingCacheStore;
use Tests\Feature\Stubs\RecordingLogger;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `OperationScope`, which runs a management service call as
 * one operation and dispatches the events of its writes once they commit on the
 * package's connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(OperationScope::class)]
final class OperationScopeTest extends TestCase
{
    use UsesAnAuthorizationConnection;

    /**
     * Fake the event the tests dispatch.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Event::fake([SystemOverrideUsed::class]);
    }

    /**
     * The work runs inside one transaction on the package's connection, with
     * the operation current, and its result is returned.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRunsTheWorkInATransactionOnThePackageConnection(): void
    {
        $this->useAnAuthorizationConnection();

        $operation = Operation::begin(new Reference('user', '1'));
        $seen      = [];

        $result = OperationScope::run($operation, static function (Operation $given) use (&$seen): string {
            $seen = [$given, OperationScope::current(new Role), self::authorizationConnection()->transactionLevel(), DB::connection()->transactionLevel()];

            return 'done';
        });

        self::assertSame('done', $result);
        self::assertSame([$operation, $operation, 1, 1], $seen);
    }

    /**
     * A call's operation is current, whatever the record, only while its work
     * runs or until it throws.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheOperationIsCurrentOnlyWhileItsWorkRuns(): void
    {
        $outer  = Operation::begin(new Reference('user', '1'));
        $inner  = Operation::begin(new Reference('user', '2'));
        $record = new Role;

        OperationScope::run($outer, static function () use ($outer, $inner, $record): void {
            OperationScope::run($inner, static function () use ($inner, $record): void {
                self::assertSame($inner, OperationScope::current($record));
            });

            self::assertSame($outer, OperationScope::current($record));
            self::assertSame($outer, OperationScope::current(new Role));
        });

        try {
            OperationScope::run($outer, static function (): never {
                throw new \RuntimeException('Refused.');
            });
        } catch (\RuntimeException) {
            self::assertNull(OperationScope::current($record)->actor);
        }

        self::assertNotSame($outer, OperationScope::current($record));
    }

    /**
     * Outside a call, every event of one write of a record shares one operation
     * with no actor; another record, or the next write of the same one, has an
     * operation of its own.
     *
     * @return void
     */
    public function testAWriteOutsideACallIsAnOperationOfItsOwn(): void
    {
        $record = new Role;
        $first  = OperationScope::current($record);

        self::assertNull($first->actor);
        self::assertSame($first, OperationScope::current($record));
        self::assertNotSame($first, OperationScope::current(new Role));

        OperationScope::beginWrite($record);

        self::assertNotSame($first->id, OperationScope::current($record)->id);
    }

    /**
     * An event queued inside a call is dispatched once the call commits, not
     * before, and once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDispatchesOnceTheWriteCommits(): void
    {
        $event = self::event();

        OperationScope::run($event->operation, static function () use ($event): void {
            OperationScope::dispatch($event);

            Event::assertNotDispatched(SystemOverrideUsed::class);
        });

        Event::assertDispatchedTimes(SystemOverrideUsed::class, 1);
        Event::assertDispatched(SystemOverrideUsed::class, static fn (SystemOverrideUsed $dispatched): bool => $dispatched === $event);
    }

    /**
     * Inside an enclosing transaction the events wait for its commit, and
     * nested calls dispatch each event once, at the outermost commit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWaitsForTheOutermostCommit(): void
    {
        $first  = self::event();
        $second = self::event();

        DB::transaction(static function () use ($first, $second): void {
            OperationScope::run($first->operation, static function () use ($first, $second): void {
                OperationScope::dispatch($first);

                OperationScope::run($second->operation, static fn () => OperationScope::dispatch($second));
            });

            Event::assertNotDispatched(SystemOverrideUsed::class);
        });

        Event::assertDispatchedTimes(SystemOverrideUsed::class, 2);
    }

    /**
     * An enclosing transaction that rolls back dispatches nothing, though the
     * call itself returned.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolledBackWriteDispatchesNothing(): void
    {
        $event = self::event();

        try {
            DB::transaction(static function () use ($event): never {
                OperationScope::run($event->operation, static fn () => OperationScope::dispatch($event));

                throw new \RuntimeException('Rolled back.');
            });
        } catch (\RuntimeException) {
            // The enclosing transaction rolled back.
        }

        try {
            OperationScope::run($event->operation, static function () use ($event): never {
                OperationScope::dispatch($event);

                throw new \RuntimeException('Refused.');
            });
        } catch (\RuntimeException) {
            // The call rolled back.
        }

        Event::assertNotDispatched(SystemOverrideUsed::class);
    }

    /**
     * With no transaction open on the package's connection the write has
     * committed, so its events are dispatched straight away, even while another
     * connection's transaction is open and then rolls back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDispatchesStraightAwayWhenThePackageConnectionHasNoTransaction(): void
    {
        $this->useAnAuthorizationConnection();

        $event = self::event();

        try {
            DB::transaction(static function () use ($event): never {
                OperationScope::dispatch($event);

                Event::assertDispatchedTimes(SystemOverrideUsed::class, 1);

                throw new \RuntimeException('Rolled back.');
            });
        } catch (\RuntimeException) {
            // The other connection's transaction rolled back.
        }

        Event::assertDispatchedTimes(SystemOverrideUsed::class, 1);
    }

    /**
     * On the package's own connection, an event is dispatched once the
     * enclosing transaction there commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWaitsForTheCommitOnThePackageConnection(): void
    {
        $this->useAnAuthorizationConnection();

        $event = self::event();

        self::authorizationConnection()->transaction(static function () use ($event): void {
            OperationScope::dispatch($event);

            Event::assertNotDispatched(SystemOverrideUsed::class);
        });

        Event::assertDispatchedTimes(SystemOverrideUsed::class, 1);
    }

    /**
     * Inside a write's transaction the resolution cache is invalidated before
     * the commit, and a store that fails then rolls the write back, so it never
     * commits with entries that still allow what it took away.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedInvalidationRollsTheWriteBack(): void
    {
        $this->app?->instance('log', new RecordingLogger);
        $this->app?->instance(ResolutionCache::class, new ResolutionCache(new Repository(new FailingCacheStore)));

        try {
            OperationScope::run(Operation::begin(), static function (): void {
                $role = Role::query()->create(['name' => 'editor']);

                OperationScope::dispatch(new RoleAssigned(Operation::begin(), new Reference('user', 'user-1'), Reference::of($role), 'editor', GrantScope::platform(), null));
            });
            self::fail('The failed invalidation was not thrown.');
        } catch (\RuntimeException $exception) {
            self::assertSame('cache unavailable', $exception->getMessage());
        }

        self::assertSame(0, Role::query()->count());
        Event::assertNotDispatched(SystemOverrideUsed::class);
    }

    /**
     * Once the write commits, the versions are bumped again before any listener
     * runs, so an entry stored from the rows before the commit never holds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheVersionsAreBumpedAgainOnceTheWriteCommits(): void
    {
        $store    = new VersionedStore($repository = new Repository(new ArrayStore), 'authorization');
        $key      = $store->granteeKey(new Reference('user', 'user-1'));
        $event    = new RoleAssigned(Operation::begin(), new Reference('user', 'user-1'), new Reference('role', 'role-1'), 'editor', GrantScope::platform(), null);
        $tokens   = [];
        $listened = null;

        $this->app?->instance(ResolutionCache::class, new ResolutionCache($repository));

        Event::listen(RoleAssigned::class, static function () use ($store, $key, &$listened): void {
            $listened = $store->tokens([$key])[$key] ?? null;
        });

        OperationScope::run($event->operation, static function () use ($event, $store, $key, &$tokens): void {
            OperationScope::dispatch($event);

            $tokens[] = $store->tokens([$key])[$key] ?? null;
        });

        self::assertIsString($tokens[0]);
        self::assertIsString($listened);
        self::assertNotSame($tokens[0], $listened);
    }

    /**
     * A write made with no transaction open has already committed, so a store
     * that fails to invalidate it is thrown at once.
     *
     * @return void
     */
    public function testAFailedInvalidationWithoutATransactionIsThrown(): void
    {
        $this->app?->instance('log', new RecordingLogger);
        $this->app?->instance(ResolutionCache::class, new ResolutionCache(new Repository(new FailingCacheStore)));

        $this->expectExceptionObject(new \RuntimeException('cache unavailable'));

        OperationScope::dispatch(new RoleAssigned(Operation::begin(), new Reference('user', 'user-1'), new Reference('role', 'role-1'), 'editor', GrantScope::platform(), null));
    }

    /**
     * A delegated operation holds pins of its own while its work runs, a
     * trusted one none, and none is held outside every call; a trusted call
     * inside a delegated one holds none, and the delegated one's are current
     * again once it ends.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedOperationHoldsPinsWhileItsWorkRuns(): void
    {
        self::assertNull(OperationScope::pins());

        $seen = [];

        OperationScope::run(self::delegated(), static function () use (&$seen): void {
            $seen[] = OperationScope::pins();

            OperationScope::run(Operation::begin(), static function () use (&$seen): void {
                $seen[] = OperationScope::pins();
            });

            $seen[] = OperationScope::pins();
        });

        OperationScope::run(Operation::begin(), static function () use (&$seen): void {
            $seen[] = OperationScope::pins();
        });

        self::assertInstanceOf(DependencyPins::class, $seen[0]);
        self::assertNull($seen[1]);
        self::assertSame($seen[0], $seen[2]);
        self::assertNull($seen[3]);
        self::assertNull(OperationScope::pins());
    }

    /**
     * A delegated operation that conflicts is tried again, each try in a
     * transaction of its own, rolled back before the next, with fresh pins;
     * once every try has conflicted it is refused as `administration.conflict`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedOperationThatConflictsIsTriedAgain(): void
    {
        $this->useAnAuthorizationConnection();

        $pins   = [];
        $result = OperationScope::run(self::delegated(), static function () use (&$pins): int {
            $pins[] = OperationScope::pins();

            self::authorizationConnection()->table('roles')->insert(['id' => (string) \count($pins), 'name' => 'try-' . \count($pins)]);

            return \count($pins) < 3 ? self::conflict() : \count($pins);
        });

        self::assertSame(3, $result);
        self::assertCount(3, \array_unique(\array_map(\spl_object_id(...), \array_filter($pins))));
        self::assertSame(['try-3'], self::authorizationConnection()->table('roles')->pluck('name')->all());

        $refusal = null;

        try {
            OperationScope::run(self::delegated(), self::conflict(...));
        } catch (AuthorizationException $exception) {
            $refusal = $exception;
        }

        self::assertInstanceOf(AuthorizationException::class, $refusal);
        self::assertSame(DecisionReason::ADMINISTRATION_CONFLICT, $refusal->getReason());
    }

    /**
     * A trusted operation runs once, as it always has: anything it throws but a
     * widening its grant hooks did not cover, a concurrency error of the
     * database's and any other dependency conflict included, is thrown on,
     * never tried again or turned into a refusal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATrustedOperationRunsOnce(): void
    {
        $thrown = [new \RuntimeException('Deadlock found when trying to get lock', 40001), DependencyChangedException::tree(), DependencyChangedException::rows('roles')];

        foreach ($thrown as $throws) {
            $tries  = 0;
            $caught = null;

            try {
                OperationScope::run(Operation::begin(), static function () use (&$tries, $throws): never {
                    $tries++;

                    throw $throws;
                });
            } catch (\RuntimeException $exception) {
                $caught = $exception;
            }

            self::assertInstanceOf($throws::class, $caught);
            self::assertSame(1, $tries);
        }
    }

    /**
     * A trusted operation whose grant hook phase finds a widening it did not
     * cover conflicts, and, when it opened the outermost transaction, is tried
     * again `retries` times in a fresh transaction, then refused as
     * `administration.conflict`; one that stops conflicting returns what its
     * try returns.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATrustedOperationThatConflictsIsTriedAgain(): void
    {
        $this->useAnAuthorizationConnection();

        config(['authorization.administration.retries' => 1]);

        /** @var \ArrayObject<int, bool> $tries */
        $tries = new \ArrayObject;

        /** @var \ArrayObject<int, int> $levels */
        $levels = new \ArrayObject;

        $result = OperationScope::run(Operation::begin(), static function () use ($tries, $levels): string {
            $tries->append(true);
            $levels->append(self::authorizationConnection()->transactionLevel());

            return $tries->count() === 1 ? throw DependencyChangedException::widening() : 'written';
        });

        self::assertSame('written', $result);
        self::assertSame([1, 1], $levels->getArrayCopy());

        $refusal = null;

        try {
            OperationScope::run(Operation::begin(), self::widening(...));
        } catch (AuthorizationException $exception) {
            $refusal = $exception;
        }

        self::assertSame(DecisionReason::ADMINISTRATION_CONFLICT, $refusal->getReason());

        config(['authorization.administration.retries' => 0]);

        $once = 0;

        try {
            OperationScope::run(Operation::begin(), static function () use (&$once): never {
                $once++;

                throw DependencyChangedException::widening();
            });
        } catch (AuthorizationException) {
            self::assertSame(1, $once);
        }

        self::assertSame(1, $once);
    }

    /**
     * Inside a transaction the application opened, a trusted operation's
     * widening is never tried again, since the try's row locks stay held: it is
     * thrown as `TransactionConflictException`, keeping the conflict, after one
     * try.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATrustedWideningInsideAnOpenTransactionIsThrownForTheApplication(): void
    {
        $tries    = 0;
        $widening = DependencyChangedException::widening();
        $caught   = null;

        self::assertSame(1, DB::transactionLevel());

        try {
            OperationScope::run(Operation::begin(), static function () use (&$tries, $widening): never {
                $tries++;

                throw $widening;
            });
        } catch (TransactionConflictException $exception) {
            $caught = $exception;
        }

        self::assertSame($widening, $caught->getPrevious());
        self::assertSame(1, $tries);
    }

    /**
     * A delegated try made again inside a transaction the operation did not
     * open keeps the conflict the try before it failed with while its work
     * runs, and only then; a first try, a try in a fresh transaction, and no
     * operation at all keep none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATryMadeAgainInsideAnOpenTransactionKeepsItsConflict(): void
    {
        $conflict = DependencyChangedException::rows('roles');
        $seen     = [];

        $nested = OperationScope::run(self::delegated(), static function () use (&$seen, $conflict): bool {
            $seen[] = OperationScope::retriedInPlace();

            return \count($seen) < 2 ? throw $conflict : OperationScope::run(Operation::begin(), static fn (): bool => OperationScope::retriedInPlace() === null);
        });

        self::assertSame([null, $conflict], $seen);
        self::assertTrue($nested);
        self::assertNull(OperationScope::retriedInPlace());

        $this->useAnAuthorizationConnection();

        $fresh = [];

        OperationScope::run(self::delegated(), static function () use (&$fresh, $conflict): bool {
            $fresh[] = OperationScope::retriedInPlace();

            return \count($fresh) < 2 ? throw $conflict : true;
        });

        self::assertSame([null, null], $fresh);
    }

    /**
     * While a grant hook runs every operation is refused, and the guard is
     * lifted once the hook returns or throws.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function testEveryOperationIsRefusedWhileAGrantHookRuns(): void
    {
        $ran = 0;

        OperationScope::whileHookRuns(static function () use (&$ran): void {
            try {
                OperationScope::run(Operation::begin(), static fn (): bool => true);
            } catch (GrantHookRecursionException) {
                $ran++;
            }

            try {
                OperationScope::run(self::delegated(), static fn (): bool => true);
            } catch (GrantHookRecursionException) {
                $ran++;
            }
        });

        self::assertSame(2, $ran);
        self::assertTrue(OperationScope::run(Operation::begin(), static fn (): bool => true));

        $refused = static fn () => OperationScope::whileHookRuns(static fn (): never => throw new \RuntimeException('Refused.'));

        try {
            $refused();
        } catch (\RuntimeException) {
            // The guard must be lifted after a hook that throws.
        }

        self::assertTrue(OperationScope::run(Operation::begin(), static fn (): bool => true));
    }

    /**
     * An operation is nested only while it runs inside another's work.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOperationIsNestedOnlyInsideAnothersWork(): void
    {
        self::assertFalse(OperationScope::isNested());

        $nested = OperationScope::run(Operation::begin(), static fn (): array => [
            OperationScope::isNested(),
            OperationScope::run(Operation::begin(), static fn (): bool => OperationScope::isNested()),
            OperationScope::isNested(),
        ]);

        self::assertSame([false, true, false], $nested);
        self::assertFalse(OperationScope::isNested());
    }

    /**
     * A tree change reported while delegated operations run marks each one's
     * pins moved, so none validates; with none running, it does nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATreeChangeMarksEveryRunningDelegatedOperation(): void
    {
        OperationScope::treeChanged();

        config(['authorization.administration.retries' => 0]);

        $failures = \array_map(self::reasonOfAMove(...), [true, false]);

        self::assertSame([DecisionReason::ADMINISTRATION_CONFLICT, DecisionReason::ADMINISTRATION_CONFLICT], $failures);
    }

    /**
     * The pins of a delegated operation are returned to work that only ever
     * runs delegated; none running, or a trusted one, is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyADelegatedOperationHasPinsToReturn(): void
    {
        self::assertTrue(OperationScope::run(self::delegated(), static fn (): bool => OperationScope::delegatedPins() === OperationScope::pins()));

        $none    = static fn (): DependencyPins => OperationScope::delegatedPins();
        $trusted = static fn (): DependencyPins => OperationScope::run(Operation::begin(), $none);

        foreach ([$none, $trusted] as $call) {
            $refusal = null;

            try {
                $call();
            } catch (\LogicException $exception) {
                $refusal = $exception;
            }

            self::assertSame('No delegated operation is running.', $refusal?->getMessage());
        }
    }

    /**
     * Once every try has conflicted, the refusal is recorded and reported as
     * the refusal of the actor the operation was run for.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheConflictRefusalIsReportedForTheActorGiven(): void
    {
        config(['authorization.administration.retries' => 0]);

        $actor     = ActingContext::for(StubIdentity::query()->create(['id' => 'admin']));
        $operation = Operation::begin($actor, ['authorization:role.grant']);

        /** @var \ArrayObject<int, string|null> $failed */
        $failed = new \ArrayObject;

        Event::listen(AuthorizationFailed::class, static fn (AuthorizationFailed $event) => $failed->append($event->resource));

        try {
            OperationScope::run($operation, self::conflict(...), $actor);
        } catch (AuthorizationException) {
            // Asserted below.
        }

        self::assertSame(['authorization:operation:' . $operation->id], $failed->getArrayCopy());
    }

    /**
     * Run a delegated operation that reports a tree change, itself or from a
     * trusted call inside it, then validates its pins, and return the reason it
     * was refused with, or null.
     *
     * @param  bool  $isItself
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     *
     * @throws \Throwable
     */
    private static function reasonOfAMove(bool $isItself): ?DecisionReason
    {
        $report = static function (): void {
            OperationScope::treeChanged();
        };

        try {
            OperationScope::run(self::delegated(), static function () use ($isItself, $report): void {
                $outer = OperationScope::pins();

                $isItself ? $report() : OperationScope::run(Operation::begin(), $report);

                $outer?->validate();
            });
        } catch (AuthorizationException $refusal) {
            return $refusal->getReason();
        }

        return null;
    }

    /**
     * Throw the conflict of a grant that widens with no grant hook run for it.
     *
     * @return never
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException
     */
    private static function widening(): never
    {
        throw DependencyChangedException::widening();
    }

    /**
     * Throw the conflict of a tree that moved.
     *
     * @return never
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException
     */
    private static function conflict(): never
    {
        throw DependencyChangedException::tree();
    }

    /**
     * Return a new delegated operation, as an acting context begins one.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Operation
     */
    private static function delegated(): Operation
    {
        return new Operation((string) Str::uuid(), new Reference('user', '1'), CarbonImmutable::now('UTC'), false);
    }

    /**
     * Return an event for a new operation.
     *
     * @return \SineMacula\Laravel\Authorization\Events\SystemOverrideUsed
     */
    private static function event(): SystemOverrideUsed
    {
        return new SystemOverrideUsed(Operation::begin(), new Reference('role', '1'), 'admin', null, 'delete');
    }
}
