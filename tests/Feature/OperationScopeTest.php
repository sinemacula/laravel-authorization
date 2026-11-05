<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Events\SystemOverrideUsed;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\UsesAnAuthorizationConnection;
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
     * Return an event for a new operation.
     *
     * @return \SineMacula\Laravel\Authorization\Events\SystemOverrideUsed
     */
    private static function event(): SystemOverrideUsed
    {
        return new SystemOverrideUsed(Operation::begin(), new Reference('role', '1'), 'admin', null, 'delete');
    }
}
