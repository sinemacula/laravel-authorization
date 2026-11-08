<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionRolledBack;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;

/**
 * Simulates a concurrent write landing between a delegated decision and the
 * write it allows, whatever the database, so a test can reach the concurrency
 * protocol's version check on SQLite, which serialises writers, as on
 * PostgreSQL and MySQL.
 *
 * The change runs from a listener of the decision, inside the operation's try,
 * as a concurrent call's write would be seen by the reads that follow; when
 * that try is rolled back, it runs again outside it, inside the test's own
 * transaction, as though the concurrent call had committed, so the next try
 * decides on it. Asked to race every try, it runs inside each try instead, and
 * never outside, so every try conflicts. A race can land on a query instead of
 * a decision, so a write between a service's read and its lock, or between the
 * validation and the write, is simulated alike. The tries are those on the
 * package's connection, whether a test's transaction holds them or, on a
 * connection of its own, they open the outermost transaction there.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait RacesDelegatedCalls
{
    /**
     * Run the change once the first decision of the action of a try has been
     * made, as described above, and return how many decisions of the action
     * were made, counted as they are.
     *
     * @param  string  $action
     * @param  \Closure(): mixed  $change
     * @param  bool  $isEveryTry
     * @return \ArrayObject<int, bool>
     */
    protected static function raceWith(string $action, \Closure $change, bool $isEveryTry = false): \ArrayObject
    {
        /** @var \ArrayObject<int, bool> $decisions */
        $decisions = new \ArrayObject;

        /** @var \ArrayObject<string, bool|int> $state */
        $state = new \ArrayObject(['armed' => true, 'level' => 0, 'committed' => false]);

        Event::listen(DecisionEvaluated::class, static function (DecisionEvaluated $event) use ($action, $change, $decisions, $state): void {
            if ($event->action !== $action) {
                return;
            }

            $decisions->append($event->isAllowed());

            if ($state['armed'] !== true) {
                return;
            }

            $state['armed'] = false;
            $state['level'] = AuthorizationConnection::connection()->transactionLevel();

            $change();
        });

        self::replayOnRollback($change, $state, $isEveryTry);

        return $decisions;
    }

    /**
     * Run the change once the query matching the pattern, its identifiers
     * unquoted, has run the given number of times inside a try, as a write of a
     * concurrent call landing between that read and what follows it, then, when
     * the try is rolled back, again outside it, as `raceWith()` does; return
     * the SQL of the query it ran after.
     *
     * @param  string  $pattern
     * @param  \Closure(): mixed  $change
     * @param  int  $occurrence
     * @return \ArrayObject<int, string>
     */
    protected static function raceOnQuery(string $pattern, \Closure $change, int $occurrence = 1): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $raced */
        $raced = new \ArrayObject;

        /** @var \ArrayObject<string, bool|int> $state */
        $state = new \ArrayObject(['armed' => true, 'level' => 0, 'committed' => false, 'seen' => 0]);

        DB::listen(static function (QueryExecuted $query) use ($pattern, $change, $occurrence, $raced, $state): void {
            if ($state['armed'] !== true || \preg_match($pattern, \str_replace(['"', '`'], '', $query->sql)) !== 1) {
                return;
            }

            $state['seen'] = (int) $state['seen'] + 1;

            if ($state['seen'] < $occurrence) {
                return;
            }

            $state['armed'] = false;
            $state['level'] = AuthorizationConnection::connection()->transactionLevel();

            $raced->append($query->sql);

            $change();
        });

        self::replayOnRollback($change, $state, false);

        return $raced;
    }

    /**
     * Record the package's change events dispatched from now on, by class:
     * every package event but the decisions and the refusals.
     *
     * @return \ArrayObject<int, string>
     */
    protected static function recordChanges(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $changes */
        $changes = new \ArrayObject;

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
     * Run the change again outside the try it raced once that try is rolled
     * back, as though the concurrent call had committed, or, racing every try,
     * arm it for the next.
     *
     * @param  \Closure(): mixed  $change
     * @param  \ArrayObject<string, bool|int>  $state
     * @param  bool  $isEveryTry
     * @return void
     */
    private static function replayOnRollback(\Closure $change, \ArrayObject $state, bool $isEveryTry): void
    {
        Event::listen(TransactionRolledBack::class, static function (TransactionRolledBack $event) use ($change, $isEveryTry, $state): void {
            // Only the rollback of the try raced counts, on the package's
            // connection: not one inside the change itself, nor the test's own
            // once it ends. A try that opened the outermost transaction there
            // rolls back to none.
            $level   = $event->connection->transactionLevel();
            $isOther = $event->connectionName !== AuthorizationConnection::connection()->getName();

            if ($state['committed'] === true || $isOther || $level >= $state['level'] || ($level === 0 && $state['level'] > 1)) {
                return;
            }

            if ($isEveryTry) {
                $state['armed'] = true;

                return;
            }

            $state['committed'] = true;

            $change();
        });
    }
}
