<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use Illuminate\Container\Container;
use Illuminate\Contracts\Database\ConcurrencyErrorDetector as ConcurrencyErrorDetectorContract;
use Illuminate\Database\ConcurrencyErrorDetector;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException;

/**
 * Tries a delegated operation again when it conflicts with a concurrent write,
 * a bounded number of times (AUTHZ-11.1, the concurrency protocol).
 *
 * A try conflicts when something its decisions read changed before it wrote
 * (`DependencyChangedException`, see `DependencyPins`), or, when the operation
 * opened the outermost transaction on the package's connection, when the
 * database refused it as a concurrency error: a PostgreSQL serialisation
 * failure or deadlock, a MySQL deadlock or lock wait timeout, or a busy SQLite
 * database, as Laravel's concurrency error detector tells them. Each try runs
 * in its own transaction, rolled back before the next, so a try that conflicts
 * leaves nothing written and dispatches no change event, and the next decides
 * everything again on what is stored then.
 *
 * The operation is tried again at most `authorization.administration.retries`
 * times (2 by default, validated at boot); once every try has conflicted, it is
 * refused with `AuthorizationException` as `administration.conflict`, at the
 * `administration` stage, with a trace step naming it.
 *
 * Inside a transaction the application opened, a concurrency error is thrown as
 * it is, never tried again: MySQL rolls the whole transaction back on a
 * deadlock and PostgreSQL needs the whole transaction restarted, so only the
 * application can retry it. A conflict the pins find is tried again there too,
 * rolled back to the operation's savepoint, though a snapshot older than the
 * application's transaction stays as old, so on MySQL it may conflict every
 * time.
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
     * returning what the first try that does not conflict returns.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $try
     * @return TResult
     *
     * @throws \Throwable
     */
    public static function run(\Closure $try): mixed
    {
        $isOutermost = AuthorizationConnection::connection()->transactionLevel() === 0;
        $left        = self::retries();

        while (true) {
            try {
                return $try();
            } catch (\Throwable $exception) {
                self::assertRetryable($exception, $isOutermost, $left-- > 0);
            }
        }
    }

    /**
     * Return the refusal of an operation that conflicted on every try: an
     * `AuthorizationException` as `administration.conflict`, with a trace step
     * naming it.
     *
     * @return \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public static function refusal(): AuthorizationException
    {
        $step = new TraceEntry(DecisionStage::ADMINISTRATION, TraceOutcome::REFUSED, cap: DecisionReason::ADMINISTRATION_CONFLICT->value);

        return ActingContext::refusal(Decision::deny(DecisionReason::ADMINISTRATION_CONFLICT, DecisionStage::ADMINISTRATION, [], [$step]));
    }

    /**
     * Determine whether the exception is a concurrency error the database
     * refused a transaction with.
     *
     * @param  \Throwable  $exception
     * @return bool
     */
    public static function isConcurrencyError(\Throwable $exception): bool
    {
        $container = Container::getInstance();
        $detector  = $container->bound(ConcurrencyErrorDetectorContract::class) ? $container->make(ConcurrencyErrorDetectorContract::class) : null;
        $detector  = $detector instanceof ConcurrencyErrorDetectorContract ? $detector : new ConcurrencyErrorDetector;

        return $detector->causedByConcurrencyError($exception);
    }

    /**
     * Throw the exception unless the try conflicted and may run again: throw
     * the refusal when it conflicted with no tries left.
     *
     * @param  \Throwable  $exception
     * @param  bool  $isOutermost
     * @param  bool  $hasTriesLeft
     * @return void
     *
     * @throws \Throwable
     */
    private static function assertRetryable(\Throwable $exception, bool $isOutermost, bool $hasTriesLeft): void
    {
        $isConflict = $exception instanceof DependencyChangedException || ($isOutermost && self::isConcurrencyError($exception));

        if (!$isConflict) {
            throw $exception;
        }

        if (!$hasTriesLeft) {
            throw self::refusal();
        }
    }
}
