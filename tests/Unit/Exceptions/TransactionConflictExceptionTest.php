<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use Illuminate\Database\ConcurrencyErrorDetector;
use Illuminate\Database\DeadlockException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\TransactionConflictException;

/**
 * Unit tests for `TransactionConflictException`, the concurrency error of a
 * delegated call inside a transaction the application opened, for the
 * application to restart.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TransactionConflictException::class)]
final class TransactionConflictExceptionTest extends TestCase
{
    /**
     * The exception keeps the database's error, says to restart the
     * transaction, and is a deadlock whose code is a serialisation failure's,
     * so Laravel's detector tells it as a concurrency error.
     *
     * @return void
     */
    public function testItIsAConcurrencyErrorForTheApplicationToRestart(): void
    {
        $error     = new \RuntimeException('SQLSTATE[40P01]: deadlock detected');
        $exception = new TransactionConflictException($error);

        self::assertInstanceOf(DeadlockException::class, $exception);
        self::assertSame($error, $exception->getPrevious());
        self::assertSame(40001, $exception->getCode());
        self::assertSame(
            'A delegated administration call conflicted with a concurrent transaction inside a transaction the application opened; '
                . 'restart that transaction from the start. SQLSTATE[40P01]: deadlock detected',
            $exception->getMessage(),
        );
        self::assertTrue((new ConcurrencyErrorDetector)->causedByConcurrencyError(new TransactionConflictException(new \RuntimeException('lost'))));
    }
}
