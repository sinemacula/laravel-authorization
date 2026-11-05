<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;

/**
 * Runs a management service call as one operation, and dispatches the events of
 * every write once it commits.
 *
 * `run()` opens one transaction on the package's connection and makes the
 * operation current while the call's work runs inside it, so the model
 * observers and the system protection report the call's actor and operation id.
 * The operation stops being current before the transaction commits, so a
 * listener that writes is an operation of its own. A model write made outside a
 * call is an operation of its own too, with no actor, shared by every event
 * that one save or delete dispatches.
 *
 * `dispatch()` queues events on the package's connection, the connection every
 * row the package writes lives on, through its `afterCommit()`: they are
 * dispatched once the outermost transaction commits, once, and never when it
 * rolls back. A write made while that connection has no transaction open has
 * already committed, so its events are dispatched straight away, even while
 * another connection's transaction is open.
 *
 * @managed-static
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class OperationScope
{
    /** @var list<\SineMacula\Laravel\Authorization\Support\Operation> The operations whose work is running, innermost last. */
    private static array $operations = [];

    /** @var \WeakMap<\Illuminate\Database\Eloquent\Model, \SineMacula\Laravel\Authorization\Support\Operation>|null The operation of each model write made outside a call. */
    private static ?\WeakMap $writes = null;

    /**
     * Run the call's work as the given operation, in one transaction on the
     * package's connection.
     *
     * @template TResult
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \Closure(\SineMacula\Laravel\Authorization\Support\Operation): TResult  $work
     * @return TResult
     *
     * @throws \Throwable
     */
    public static function run(Operation $operation, \Closure $work): mixed
    {
        return AuthorizationConnection::connection()->transaction(static function () use ($operation, $work): mixed {
            self::$operations[] = $operation;

            try {
                return $work($operation);
            } finally {
                \array_pop(self::$operations);
            }
        });
    }

    /**
     * Return the operation whose work is running or, for a write made outside a
     * management service call, the operation of the record's write, begun with
     * no actor on first use.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $record
     * @return \SineMacula\Laravel\Authorization\Support\Operation
     */
    public static function current(Model $record): Operation
    {
        if (self::$operations !== []) {
            return self::$operations[\count(self::$operations) - 1];
        }

        $writes = self::$writes ??= new \WeakMap;

        return $writes[$record] ??= Operation::begin();
    }

    /**
     * Mark the start of a new write of the record, so a write made outside a
     * management service call does not share the operation of the last one.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $record
     * @return void
     */
    public static function beginWrite(Model $record): void
    {
        if (self::$writes === null) {
            return;
        }

        unset(self::$writes[$record]);
    }

    /**
     * Dispatch the events once the package connection's transaction commits, or
     * straight away when it has none open.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent  ...$events
     * @return void
     */
    public static function dispatch(AuthorizationEvent ...$events): void
    {
        $connection = AuthorizationConnection::connection();
        $send       = static function () use ($events): void {
            foreach ($events as $event) {
                Event::dispatch($event);
            }
        };

        if ($connection->transactionLevel() === 0) {
            $send();

            return;
        }

        $connection->afterCommit($send);
    }
}
