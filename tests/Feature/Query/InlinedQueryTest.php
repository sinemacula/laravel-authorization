<?php

declare(strict_types = 1);

namespace Tests\Feature\Query;

use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Query\Contracts\Dialect;
use SineMacula\Laravel\Authorization\Query\Dialects\Dialects;
use SineMacula\Laravel\Authorization\Query\InlinedQuery;
use SineMacula\Laravel\Authorization\Query\RecordAttachments;
use SineMacula\Laravel\Authorization\Query\TenantMembership;
use Tests\TestCase;

/**
 * Feature tests for a nested query written with its values inlined as the
 * dialect writes a bound value, and for whether a nested read of the
 * authorization tables reads what `check()` reads.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(InlinedQuery::class)]
final class InlinedQueryTest extends TestCase
{
    /** @var list<string> The values stored, each a probe too: question marks, quotes, backslashes, case, padding and composed forms. */
    private const array VALUES = ['a?b', 'a??b', '??', 'a\'b', 'a\\', 'a\\\'b', '\\', 'abc', 'ABC', 'abc ', ' abc', "\u{e9}", "e\u{301}", '', '*'];

    /**
     * Each value inlined finds exactly the rows the value bound finds, under
     * the column's own collation, on every database: a question mark, a doubled
     * one, a quote and a backslash are never read as SQL.
     *
     * @return void
     */
    public function testAnInlinedValueFindsWhatTheBoundValueFinds(): void
    {
        $values = $this->values();

        foreach ([...$values, 'missing'] as $probe) {
            $query   = DB::table('inlined_values')->select('value')->where('value', $probe)->orderBy('id');
            $inlined = InlinedQuery::sqlOf($query, self::dialect());

            self::assertNotNull($inlined, \bin2hex($probe));
            self::assertStringNotContainsString('?', $inlined);
            self::assertSame($query->pluck('value')->all(), self::valuesOf($inlined), \bin2hex($probe));
        }
    }

    /**
     * An integer and a boolean are inlined as they are bound.
     *
     * @return void
     */
    public function testAnIntegerAndABooleanAreInlinedAsBound(): void
    {
        $this->values();

        $query   = DB::table('inlined_values')->select('value')->where('number', 3)->orWhere('number', -2)->orWhere('flag', true)->orderBy('id');
        $inlined = InlinedQuery::sqlOf($query, self::dialect());

        self::assertNotNull($inlined);
        self::assertSame($query->pluck('value')->all(), self::valuesOf($inlined));
    }

    /**
     * A query nested once inlined leaves the outer query's own bindings where
     * they were, however many backslashes and question marks it inlined.
     *
     * @return void
     */
    public function testTheOuterQueriesBindingsStayInPlace(): void
    {
        $this->values();

        $nested  = DB::table('inlined_values as inner_values')->selectRaw('1')->where('inner_values.value', 'a\\')->whereColumn('inner_values.id', 'inlined_values.id');
        $inlined = InlinedQuery::sqlOf($nested, self::dialect());

        self::assertNotNull($inlined);

        $kept = DB::table('inlined_values')->whereRaw('(EXISTS (' . $inlined . ') OR value = ?)', ['a?b'])->where('value', '<>', '??')->orderBy('id')->pluck('value')->all();

        self::assertSame(['a?b', 'a\\'], $kept);
    }

    /**
     * A question mark in the query's text that is no placeholder, and a value
     * no literal can stand for, are not written.
     *
     * @return void
     */
    public function testWhatCannotBeInlinedExactlyIsNotWritten(): void
    {
        $marked = DB::table('inlined_values')->selectRaw('\'?\' as mark')->where('value', 'a');

        self::assertNull(InlinedQuery::sqlOf($marked, self::dialect()));
        self::assertNull(InlinedQuery::sqlOf(DB::table('inlined_values')->where('value', 1.5), self::dialect()));

        $invalid = DB::table('inlined_values')->where('value', "\xff");

        self::assertSame(DB::connection()->getDriverName() === 'sqlite', InlinedQuery::sqlOf($invalid, self::dialect()) !== null);
    }

    /**
     * A query reads where `check()` reads the authorization tables when its
     * connection has no separate read connection, or is in a transaction; a
     * separate read connection outside one does not.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function testAReadOnTheWriteConnectionIsTold(): void
    {
        // A connection of its own, outside the transaction the test runs in.
        config()->set('database.connections.inlined_probe', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);

        /** @var \Illuminate\Database\Connection $connection */
        $connection = DB::connection('inlined_probe');

        self::assertSame(0, $connection->transactionLevel());
        self::assertTrue(InlinedQuery::isReadOnWrite($connection));

        $connection->setReadPdo($connection->getPdo());

        self::assertTrue(InlinedQuery::isReadOnWrite($connection));

        $connection->setReadPdo(static fn (): never => throw new \LogicException('The read connection was used.'));

        self::assertFalse(InlinedQuery::isReadOnWrite($connection));
        self::assertTrue($connection->transaction(static fn (Connection $connection): bool => InlinedQuery::isReadOnWrite($connection)));

        $connection->setReadPdo(null);

        self::assertTrue(InlinedQuery::isReadOnWrite($connection));
    }

    /**
     * A condition reads the authorization tables when it nests the attachments
     * or a subtree, by the alias each is read under.
     *
     * @return void
     */
    public function testAConditionReadingTheAuthorizationTablesIsTold(): void
    {
        self::assertTrue(InlinedQuery::readsAuthorizationTables('EXISTS (select 1 from "resource_policies" as "' . RecordAttachments::ALIAS . '")'));
        self::assertTrue(InlinedQuery::readsAuthorizationTables('EXISTS (SELECT 1 FROM (x) AS `' . TenantMembership::ALIAS . '`)'));
        self::assertFalse(InlinedQuery::readsAuthorizationTables('"scoped_posts"."id" = 5'));
    }

    /**
     * A query is running when its own select, cursor, existence, update or
     * deletion compiles it, and not when it is compiled to text or nested in
     * another query.
     *
     * @return void
     */
    public function testAQueryBeingRunIsTold(): void
    {
        $this->values();

        /** @var \ArrayObject<string, bool> $seen */
        $seen  = new \ArrayObject;
        $query = static fn (string $shape): Builder => DB::table('inlined_values')->beforeQuery(static function (Builder $query) use ($seen, $shape): void {
            $seen[$shape] = InlinedQuery::isRunning($query);
        });

        $query('select')->get();
        $query('cursor')->cursor()->all();
        $query('exists')->exists();
        $query('update')->where('id', 0)->update(['flag' => true]);
        $query('delete')->where('id', 0)->delete();
        $query('text')->toSql();
        DB::table('inlined_values')->whereExists($query('nested'))->get();

        self::assertSame(['select' => true, 'cursor' => true, 'exists' => true, 'update' => true, 'delete' => true, 'text' => false], $seen->getArrayCopy());
    }

    /**
     * Create the table of values, store each, and return them; a NUL byte is
     * stored too where the database can hold one.
     *
     * @return list<string>
     */
    private function values(): array
    {
        Schema::create('inlined_values', static function (Blueprint $schema): void {
            $schema->increments('id');
            $schema->string('value', 191)->nullable();
            $schema->integer('number')->nullable();
            $schema->boolean('flag')->default(false);
        });

        $values = DB::connection()->getDriverName() === 'pgsql' ? self::VALUES : [...self::VALUES, "a\0b", "\0"];

        foreach ($values as $index => $value) {
            DB::table('inlined_values')->insert(['value' => $value, 'number' => $index - 2, 'flag' => $index === 5]);
        }

        return $values;
    }

    /**
     * Return the values the SQL selects, in order.
     *
     * @param  string  $sql
     * @return list<mixed>
     */
    private static function valuesOf(string $sql): array
    {
        return \array_column(\array_map(static fn (mixed $row): array => (array) $row, DB::select($sql)), 'value');
    }

    /**
     * Return the dialect of the default connection.
     *
     * @return \SineMacula\Laravel\Authorization\Query\Contracts\Dialect
     */
    private static function dialect(): Dialect
    {
        $dialect = Dialects::for(DB::connection()->getDriverName());

        self::assertNotNull($dialect);

        return $dialect;
    }
}
