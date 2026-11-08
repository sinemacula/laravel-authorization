<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Contracts\Database\ConcurrencyErrorDetector;
use Illuminate\Database\QueryException;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ConflictRetries;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException;
use Tests\Concerns\UsesAnAuthorizationConnection;
use Tests\TestCase;

/**
 * Feature tests for `ConflictRetries`, which try a delegated operation again
 * while it conflicts, up to `authorization.administration.retries` times, then
 * refuse it as `administration.conflict`; a database's concurrency error is
 * tried again only when the operation opened the outermost transaction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ConflictRetries::class)]
final class ConflictRetriesTest extends TestCase
{
    use UsesAnAuthorizationConnection;

    /**
     * The retries are those configured, 2 when none is, and the default for
     * anything but a whole number of at least 0.
     *
     * @return void
     */
    public function testTheRetriesAreThoseConfigured(): void
    {
        self::assertSame(2, ConflictRetries::DEFAULT_RETRIES);
        self::assertSame(2, ConflictRetries::retries());

        foreach ([[0, 0], [5, 5], [-1, 2], ['3', 2], [1.0, 2], [null, 2]] as [$configured, $retries]) {
            config(['authorization.administration.retries' => $configured]);

            self::assertSame($retries, ConflictRetries::retries(), \var_export($configured, true));
        }
    }

    /**
     * A try that does not conflict runs once, and its result is returned.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATryThatDoesNotConflictRunsOnce(): void
    {
        $tries = new \ArrayObject;

        self::assertSame('done', ConflictRetries::run(static function () use ($tries): string {
            $tries->append(true);

            return 'done';
        }));
        self::assertCount(1, $tries);
    }

    /**
     * A try that conflicts runs again until one does not, as many times as the
     * retries allow.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConflictIsTriedAgain(): void
    {
        $tries = new \ArrayObject;

        self::assertSame(3, ConflictRetries::run(static fn (): int => self::conflictUntil($tries, 3)));
        self::assertCount(3, $tries);
    }

    /**
     * A conflict on every try is refused once the retries run out, as
     * `administration.conflict` at the administration stage, its trace step
     * naming it; with none, the first conflict is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConflictOnEveryTryIsRefused(): void
    {
        foreach ([2 => 3, 0 => 1, 4 => 5] as $retries => $expected) {
            config(['authorization.administration.retries' => $retries]);

            $tries   = new \ArrayObject;
            $refusal = self::refusalOf(static fn (): int => self::conflictUntil($tries, \PHP_INT_MAX));

            self::assertCount($expected, $tries);
            self::assertSame(DecisionReason::ADMINISTRATION_CONFLICT, $refusal->getReason());
            self::assertSame(DecisionStage::ADMINISTRATION, $refusal->getDecision()?->stage);
            self::assertEquals([new TraceEntry(DecisionStage::ADMINISTRATION, TraceOutcome::REFUSED, cap: 'administration.conflict')], $refusal->getDecision()->trace);
        }
    }

    /**
     * Anything else a try throws is thrown at once, never tried again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnythingElseIsThrownAtOnce(): void
    {
        $tries = new \ArrayObject;

        try {
            ConflictRetries::run(static function () use ($tries): never {
                $tries->append(true);

                throw new \RuntimeException('broken');
            });
        } catch (\RuntimeException $exception) {
            self::assertSame('broken', $exception->getMessage());
        }

        self::assertCount(1, $tries);
    }

    /**
     * A database's concurrency error inside a transaction the application
     * opened is thrown as it is, never tried again: only the application can
     * restart its transaction.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConcurrencyErrorInsideAnOpenTransactionIsThrown(): void
    {
        $tries = new \ArrayObject;
        $error = self::serialisationFailure();

        try {
            ConflictRetries::run(static function () use ($tries, $error): never {
                $tries->append(true);

                throw $error;
            });
        } catch (QueryException $exception) {
            self::assertSame($error, $exception);
        }

        self::assertCount(1, $tries);
    }

    /**
     * When the operation opens the outermost transaction, a concurrency error
     * is tried again as a conflict is, and refused once the retries run out.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConcurrencyErrorOfTheOutermostTransactionIsTriedAgain(): void
    {
        $this->useAnAuthorizationConnection();

        $tries = new \ArrayObject;
        $error = self::serialisationFailure();

        self::assertSame('done', ConflictRetries::run(static function () use ($tries, $error): string {
            $tries->append(true);

            return $tries->count() < 2 ? throw $error : 'done';
        }));
        self::assertCount(2, $tries);

        $refusal = self::refusalOf(static fn (): never => throw $error);

        self::assertSame(DecisionReason::ADMINISTRATION_CONFLICT, $refusal->getReason());
    }

    /**
     * A concurrency error is told by Laravel's detector, or by the one the
     * application binds: a serialisation failure and a deadlock are, anything
     * else is not.
     *
     * @return void
     */
    public function testAConcurrencyErrorIsToldByTheDetector(): void
    {
        self::assertTrue(ConflictRetries::isConcurrencyError(self::serialisationFailure()));
        self::assertTrue(ConflictRetries::isConcurrencyError(new \RuntimeException('SQLSTATE[40P01]: deadlock detected')));
        self::assertFalse(ConflictRetries::isConcurrencyError(new \RuntimeException('broken')));

        $this->app?->instance(ConcurrencyErrorDetector::class, new class implements ConcurrencyErrorDetector {
            /**
             * Tell every exception a concurrency error.
             *
             * @param  \Throwable  $e
             * @return bool
             */
            #[\Override]
            public function causedByConcurrencyError(\Throwable $e): bool
            {
                return true;
            }
        });

        self::assertTrue(ConflictRetries::isConcurrencyError(new \RuntimeException('broken')));
    }

    /**
     * The refusal is an `AuthorizationException` as `administration.conflict`.
     *
     * @return void
     */
    public function testTheRefusal(): void
    {
        $refusal = ConflictRetries::refusal();

        self::assertSame(DecisionReason::ADMINISTRATION_CONFLICT, $refusal->getReason());
        self::assertFalse($refusal->getDecision()?->isAllowed());
        self::assertSame(403, $refusal->getCode());
    }

    /**
     * Conflict until the given try, counting each, and return the try that did
     * not conflict.
     *
     * @param  \ArrayObject<int, bool>  $tries
     * @param  int  $until
     * @return int
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException
     */
    private static function conflictUntil(\ArrayObject $tries, int $until): int
    {
        $tries->append(true);

        return $tries->count() < $until ? throw DependencyChangedException::tree() : $tries->count();
    }

    /**
     * Run the call and return the `AuthorizationException` it is refused with.
     *
     * @param  \Closure(): mixed  $call
     * @return \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     *
     * @throws \Throwable
     */
    private static function refusalOf(\Closure $call): AuthorizationException
    {
        try {
            ConflictRetries::run($call);
        } catch (AuthorizationException $refusal) {
            return $refusal;
        }

        self::fail('The call was not refused.');
    }

    /**
     * Return a PostgreSQL serialisation failure, as the database reports one.
     *
     * @return \Illuminate\Database\QueryException
     */
    private static function serialisationFailure(): QueryException
    {
        $pdo = new \PDOException('SQLSTATE[40001]: Serialization failure: could not serialize access due to concurrent update');

        // A PDOException's code is its SQLSTATE, a string.
        (new \ReflectionProperty(\Exception::class, 'code'))->setValue($pdo, '40001');

        return new QueryException('testing', 'update roles set name = ?', ['x'], $pdo);
    }
}
