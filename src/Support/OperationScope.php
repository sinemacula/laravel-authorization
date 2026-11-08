<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\ConflictRetries;
use SineMacula\Laravel\Authorization\Administration\DependencyPins;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException;
use SineMacula\Laravel\Authorization\Exceptions\GrantHookRecursionException;

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
 * `dispatch()` also invalidates the resolution cache for what the events say
 * changed, twice. Inside the transaction, a failure of the cache store is
 * thrown, so the write rolls back rather than commit with entries that still
 * allow what it took away. Once it has committed, before any listener runs, the
 * versions are bumped again so an entry a concurrent check stored from the rows
 * before the commit never holds; a failure then is written to the log channel,
 * since the write cannot be undone. A write made with no transaction open has
 * already committed: it is invalidated the same way, and a failure of the first
 * bump is thrown.
 *
 * A delegated operation runs under the concurrency protocol (AUTHZ-11.1): each
 * try runs in a transaction of its own and holds `DependencyPins`, which lock
 * and pin what its decisions read and validate it before the write, and a try
 * that conflicts is rolled back and tried again, then refused as
 * `administration.conflict`, recorded and reported as the actor's refusal (see
 * `ConflictRetries`). The work starts inside the transaction before the service
 * reads or locks anything, and the protocol takes no lock until the service
 * first reads what the operation changes, so the grant hooks (AUTHZ-11.3), run
 * first in a grant's work (see `Hooks\WideningPhase`), run before every lock
 * the package takes for the call. A trusted operation runs with no pins and no
 * extra lock, once, unless its grant hooks were not run for a grant it is about
 * to write that now widens an identity's scope: that try conflicts, and is
 * rolled back and tried again the same way.
 *
 * While a grant hook runs (`whileHookRuns()`), `run()` refuses every operation
 * with `GrantHookRecursionException`, so a hook can call no management service:
 * a hook only vetoes. A grant made while another operation's work runs is
 * nested in it (`isNested()`), and may run after that operation took locks.
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

    /** @var list<\SineMacula\Laravel\Authorization\Administration\DependencyPins|null> The pins of each operation whose work is running, null for a trusted one, innermost last. */
    private static array $pins = [];

    /** @var \WeakMap<\Illuminate\Database\Eloquent\Model, \SineMacula\Laravel\Authorization\Support\Operation>|null The operation of each model write made outside a call. */
    private static ?\WeakMap $writes = null;

    /** @var int How many grant hooks are running, one inside another's call never, so at most one. */
    private static int $hooks = 0;

    /**
     * Run the call's work as the given operation, in one transaction on the
     * package's connection: once for a trusted operation, and, for a delegated
     * one, under the concurrency protocol, again in a fresh transaction for
     * each try that conflicts, up to `authorization.administration.retries`
     * times, then refused as `administration.conflict`, recorded and reported
     * as the refusal of the actor given, the acting context the operation was
     * begun with. A trusted operation is tried again only when a grant it is
     * about to write widens an identity's scope with no grant hook run for it.
     * While a grant hook runs, every operation is refused.
     *
     * @template TResult
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \Closure(\SineMacula\Laravel\Authorization\Support\Operation): TResult  $work
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return TResult
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GrantHookRecursionException
     * @throws \Throwable
     */
    public static function run(Operation $operation, \Closure $work, ?ActingContext $actor = null): mixed
    {
        if (self::$hooks > 0) {
            throw new GrantHookRecursionException;
        }

        if ($operation->isTrusted) {
            return self::trusted($operation, $work);
        }

        return ConflictRetries::run(static fn (): mixed => self::attempt($operation, $work, new DependencyPins($operation)), $actor, $operation);
    }

    /**
     * Run a grant hook, refusing every operation until it returns or throws.
     *
     * @param  \Closure(): void  $hook
     * @return void
     */
    public static function whileHookRuns(\Closure $hook): void
    {
        self::$hooks++;

        try {
            $hook();
        } finally {
            self::$hooks--;
        }
    }

    /**
     * Determine whether the operation whose work is running runs inside another
     * operation's work, which may already hold the package's locks.
     *
     * @return bool
     */
    public static function isNested(): bool
    {
        return \count(self::$operations) > 1;
    }

    /**
     * Return the pins of the operation whose work is running, or null when it
     * is trusted or none is running.
     *
     * @return \SineMacula\Laravel\Authorization\Administration\DependencyPins|null
     */
    public static function pins(): ?DependencyPins
    {
        return self::$pins === [] ? null : self::$pins[\count(self::$pins) - 1];
    }

    /**
     * Return the pins of the delegated operation whose work is running, for
     * work that only ever runs delegated, such as a guardrail change; none
     * running, or a trusted one, is a mistake, refused with `LogicException`.
     *
     * @return \SineMacula\Laravel\Authorization\Administration\DependencyPins
     *
     * @throws \LogicException
     */
    public static function delegatedPins(): DependencyPins
    {
        return self::pins() ?? throw new \LogicException('No delegated operation is running.');
    }

    /**
     * Mark every delegated operation whose work is running as having seen the
     * tenant tree move, so none writes on the chains its decisions read.
     *
     * @return void
     */
    public static function treeChanged(): void
    {
        foreach (self::$pins as $pins) {
            $pins?->treeChanged();
        }
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
     * Invalidate the resolution cache for the events and dispatch them once the
     * package connection's transaction commits, or straight away when it has
     * none open.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent  ...$events
     * @return void
     */
    public static function dispatch(AuthorizationEvent ...$events): void
    {
        $connection = AuthorizationConnection::connection();
        $cache      = ResolutionCache::instance();
        $keys       = $cache?->versionKeys($events) ?? [];

        $cache?->invalidate($keys);

        $send = static function () use ($cache, $keys, $events): void {
            $cache?->invalidateQuietly($keys);

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

    /**
     * Run the trusted operation's work once, and again, in a fresh transaction,
     * for each try a grant's hook phase finds a widening it did not cover, up
     * to `authorization.administration.retries` times, then refuse it as
     * `administration.conflict`. Nothing else a trusted operation throws, any
     * other dependency conflict included, is tried again.
     *
     * @template TResult
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \Closure(\SineMacula\Laravel\Authorization\Support\Operation): TResult  $work
     * @return TResult
     *
     * @throws \Throwable
     */
    private static function trusted(Operation $operation, \Closure $work): mixed
    {
        for ($left = ConflictRetries::retries();; $left--) {
            try {
                return self::attempt($operation, $work, null);
            } catch (DependencyChangedException $exception) {
                $refusal = match (true) {
                    !$exception->isWidening() => $exception,
                    $left > 0                 => null,
                    default                   => ConflictRetries::refusal(),
                };

                if ($refusal !== null) {
                    throw $refusal;
                }
            }
        }
    }

    /**
     * Run the work as the operation, with the pins of its try, in one
     * transaction on the package's connection, the operation current while it
     * runs.
     *
     * @template TResult
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \Closure(\SineMacula\Laravel\Authorization\Support\Operation): TResult  $work
     * @param  \SineMacula\Laravel\Authorization\Administration\DependencyPins|null  $pins
     * @return TResult
     *
     * @throws \Throwable
     */
    private static function attempt(Operation $operation, \Closure $work, ?DependencyPins $pins): mixed
    {
        return AuthorizationConnection::connection()->transaction(static function () use ($operation, $work, $pins): mixed {
            self::$operations[] = $operation;
            self::$pins[]       = $pins;

            try {
                return $work($operation);
            } finally {
                \array_pop(self::$operations);
                \array_pop(self::$pins);
            }
        });
    }
}
