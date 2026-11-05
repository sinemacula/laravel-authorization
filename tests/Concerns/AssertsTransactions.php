<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Assert;

/**
 * Asserts that a call runs every query it makes inside a transaction on the
 * package's connection.
 *
 * Meant for a test that has moved the package onto the `authorization`
 * connection, which the test's own wrapping transaction does not cover, so a
 * query the call makes outside its own transaction runs at level zero.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait AssertsTransactions
{
    /**
     * Run the call and assert that it made queries, each on the package's
     * connection inside a transaction, and return what the call returned.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $call
     * @return TResult
     */
    protected static function assertAllInATransaction(\Closure $call): mixed
    {
        /** @var \ArrayObject<int, array{string, int, string}> $levels */
        $levels = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($levels): void {
            $levels->append([$query->connectionName, $query->connection->transactionLevel(), $query->sql]);
        });

        $result = $call();
        $made   = $levels->getArrayCopy();

        Assert::assertNotSame([], $made, 'The call made no query.');

        foreach ($made as [$connection, $level, $sql]) {
            Assert::assertSame('authorization', $connection, $sql);
            Assert::assertGreaterThan(0, $level, $sql);
        }

        return $result;
    }
}
