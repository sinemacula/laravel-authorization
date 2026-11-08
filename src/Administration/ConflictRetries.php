<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use Illuminate\Container\Container;
use Illuminate\Contracts\Database\ConcurrencyErrorDetector;
use Illuminate\Database\DeadlockException;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException;
use SineMacula\Laravel\Authorization\Exceptions\TransactionConflictException;
use SineMacula\Laravel\Authorization\Support\Operation;

/**
 * Tries a delegated operation again when it conflicts with a concurrent write,
 * a bounded number of times (AUTHZ-11.1, the concurrency protocol).
 *
 * A try conflicts when something its decisions read changed before it wrote
 * (`DependencyChangedException`, see `DependencyPins`), or, when the operation
 * opened the outermost transaction on the package's connection, when the
 * database refused it as a concurrency error: a PostgreSQL serialisation
 * failure or deadlock, a MySQL deadlock or lock wait timeout, or a busy SQLite
 * database, as Laravel's concurrency error detector tells them, and Laravel's
 * `DeadlockException`, which it throws for one a nested transaction met. Each
 * try runs in its own transaction, rolled back before the next, so a try that
 * conflicts leaves nothing written and dispatches no change event, and the next
 * reads and decides everything again on what is stored then, from records it
 * reads afresh rather than models the rolled-back try changed.
 *
 * The operation is tried again at most `authorization.administration.retries`
 * times (2 by default, validated at boot), so it runs at most that many times
 * and once more; once every try has conflicted, it is refused as
 * `administration.conflict`, at the `administration` stage, with a trace step
 * naming it. The refusal is recorded and reported as any refusal is: the acting
 * subject's `DecisionEvaluated` and `AuthorizationFailed`, naming the operation
 * resource `authorization:operation:{id}` and the operation's first action,
 * then `AuthorizationException`.
 *
 * Inside a transaction the application opened, a concurrency error is never
 * tried again: MySQL rolls the whole transaction back on a deadlock and
 * PostgreSQL needs the whole transaction restarted, so only the application can
 * retry it, and it is thrown as `TransactionConflictException`, which Laravel's
 * `DB::transaction()` given attempts tries again. A conflict the pins find is
 * tried again there too, rolled back to the operation's savepoint, though a
 * snapshot older than the application's transaction stays as old, so on MySQL
 * it may conflict every time. Rolling back to a savepoint keeps the row locks
 * the try took on MySQL, so a grant's hook, which never runs under the
 * package's locks, is never called again there: a grant that widens with no
 * hook run for it is thrown as `TransactionConflictException` at once, and so
 * is a try made again there as soon as its grant would call its hook (see
 * `Hooks\WideningPhase`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConflictRetries
{
    /** @var int How many times a conflicting operation is tried again when none is configured. */
    public const int DEFAULT_RETRIES = 2;

    /**
     * Return how many times a conflicting operation is tried again:
     * `authorization.administration.retries`, or the default when it is not a
     * whole number of at least 0.
     *
     * @return int
     */
    public static function retries(): int
    {
        $retries = config('authorization.administration.retries', self::DEFAULT_RETRIES);

        return \is_int($retries) && $retries >= 0 ? $retries : self::DEFAULT_RETRIES;
    }

    /**
     * Run the try, and run it again while it conflicts and tries remain,
     * returning what the first try that does not conflict returns; once every
     * try has conflicted, refuse the operation, recorded and reported as the
     * acting subject's refusal when the actor and the operation are given. Each
     * try is handed the conflict the one before it failed with, null for the
     * first.
     *
     * @template TResult
     *
     * @param  \Closure(\Throwable|null): TResult  $try
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  \SineMacula\Laravel\Authorization\Support\Operation|null  $operation
     * @return TResult
     *
     * @throws \Throwable
     */
    public static function run(\Closure $try, ?ActingContext $actor = null, ?Operation $operation = null): mixed
    {
        $isOutermost = AuthorizationConnection::connection()->transactionLevel() === 0;
        $left        = self::retries();
        $conflict    = null;

        while (true) {
            try {
                return $try($conflict);
            } catch (\Throwable $exception) {
                self::assertRetryable($exception, $isOutermost, $left-- > 0, $actor, $operation);

                $conflict = $exception;
            }
        }
    }

    /**
     * Return the decision that refuses an operation that conflicted on every
     * try: a deny as `administration.conflict`, at the `administration` stage,
     * with a trace step naming it.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    public static function decision(): Decision
    {
        $step = new TraceEntry(DecisionStage::ADMINISTRATION, TraceOutcome::REFUSED, cap: DecisionReason::ADMINISTRATION_CONFLICT->value);

        return Decision::deny(DecisionReason::ADMINISTRATION_CONFLICT, DecisionStage::ADMINISTRATION, [], [$step]);
    }

    /**
     * Return the refusal of an operation that conflicted on every try, when no
     * actor is known to record it for: an `AuthorizationException` carrying the
     * decision.
     *
     * @return \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public static function refusal(): AuthorizationException
    {
        return ActingContext::refusal(self::decision());
    }

    /**
     * Determine whether the exception is a concurrency error the database
     * refused a transaction with: one Laravel's bound detector tells, or the
     * `DeadlockException` Laravel throws once it has told one inside a nested
     * transaction, whose own code and message no longer say so.
     *
     * @param  \Throwable  $exception
     * @return bool
     */
    public static function isConcurrencyError(\Throwable $exception): bool
    {
        $detector = Container::getInstance()->make(ConcurrencyErrorDetector::class);

        return $exception instanceof DeadlockException || $detector->causedByConcurrencyError($exception);
    }

    /**
     * Throw the exception unless the try conflicted and may run again; throw
     * the refusal, recorded and reported as the actor's when the actor and the
     * operation are given, when it conflicted with no tries left.
     *
     * @param  \Throwable  $exception
     * @param  bool  $isOutermost
     * @param  bool  $hasTriesLeft
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  \SineMacula\Laravel\Authorization\Support\Operation|null  $operation
     * @return void
     *
     * @throws \Throwable
     */
    private static function assertRetryable(\Throwable $exception, bool $isOutermost, bool $hasTriesLeft, ?ActingContext $actor, ?Operation $operation): void
    {
        if (!self::isRetryable($exception, $isOutermost)) {
            throw $exception;
        }

        if (!$hasTriesLeft) {
            throw $actor === null || $operation === null ? self::refusal() : $actor->reportRefusal($operation, self::decision());
        }
    }

    /**
     * Determine whether the try that threw the exception conflicted and may run
     * again; throw a concurrency error, or a grant that widens with no hook run
     * for it, met inside a transaction the application opened, as
     * `TransactionConflictException`, for the application to restart its
     * transaction.
     *
     * @param  \Throwable  $exception
     * @param  bool  $isOutermost
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\TransactionConflictException
     */
    private static function isRetryable(\Throwable $exception, bool $isOutermost): bool
    {
        $isConflict = $exception instanceof DependencyChangedException;
        $isRestart  = $isConflict ? $exception->isWidening() : self::isConcurrencyError($exception);

        if ($isRestart && !$isOutermost) {
            throw new TransactionConflictException($exception);
        }

        return $isConflict || $isRestart;
    }
}
