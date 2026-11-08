<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

use Illuminate\Database\DeadlockException;

/**
 * Thrown when the database refuses a delegated administration call that runs
 * inside a transaction the application opened, as a concurrency error: a
 * deadlock, a serialisation failure or a lock wait timeout (AUTHZ-11.1, the
 * concurrency protocol).
 *
 * The database has rolled back, or needs to roll back, the whole transaction,
 * not just the call, so only the application can try it again: it should
 * restart its own transaction from the start. Its code is SQLSTATE `40001`, so
 * Laravel's concurrency error detector tells it, and `DB::transaction()` given
 * a number of attempts tries the transaction again by itself. The database's
 * own error is kept as the previous exception.
 *
 * Thrown too, inside such a transaction, by a grant, trusted or delegated, that
 * would otherwise call its grant hook again (AUTHZ-11.3): when a grant it is
 * about to write now widens an identity's scope with no hook run for it, or
 * when a try of it made again after a conflict would call the hook. The failed
 * try's row locks stay held until the application's transaction ends, and a
 * hook is never called under the package's locks, so the application restarts
 * its transaction instead. The conflict is kept as the previous exception.
 *
 * A call that opened the outermost transaction itself never throws this: it is
 * tried again, then refused as `administration.conflict`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class TransactionConflictException extends DeadlockException
{
    /** @var int The SQLSTATE of a serialisation failure, which Laravel's detector tells as a concurrency error. */
    public const int SERIALIZATION_FAILURE = 40001;

    /**
     * Create the exception of the database's concurrency error, or of the
     * call's conflict.
     *
     * @param  \Throwable  $previous
     */
    public function __construct(\Throwable $previous)
    {
        parent::__construct('An administration call conflicted with a concurrent transaction inside a transaction the application opened; '
            . "restart that transaction from the start. {$previous->getMessage()}", self::SERIALIZATION_FAILURE, $previous);
    }
}
