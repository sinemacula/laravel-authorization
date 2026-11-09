<?php

declare(strict_types = 1);

namespace Tests\Feature\Reviews\Support;

use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Database\ExactReferences;
use SineMacula\Laravel\Authorization\Reviews\Support\ReviewOrder;
use Tests\Concerns\CompilesQueries;
use Tests\TestCase;

/**
 * Feature tests for the one order of an access review: byte for byte on every
 * database, a null before any value, and the same in PHP; and the keys built
 * from parts.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ReviewOrder::class)]
final class ReviewOrderTest extends TestCase
{
    use CompilesQueries;

    /**
     * A database orders a column byte for byte, as `strcmp()` does, a null
     * first when the column may hold one, whatever its collation or locale.
     *
     * @return void
     */
    public function testADatabaseOrdersByteForByte(): void
    {
        Schema::create('review_order_values', static function (Blueprint $table): void {
            $table->increments('id');
            // The database's default collation, case-insensitive on MySQL and
            // locale-bound on PostgreSQL.
            $table->string('value', 191)->nullable();
        });

        $values = ['b', 'B', 'a ', 'a', "\u{e4}", "\u{1f600}", 'Z', '_', '%', '10', '9', ''];

        foreach ([...$values, null] as $value) {
            DB::table('review_order_values')->insert(['value' => $value]);
        }

        $sorted = $values;

        \usort($sorted, static fn (string $one, string $other): int => \strcmp($one, $other));

        $read = ReviewOrder::by(DB::table('review_order_values'), 'value', true)->pluck('value')->all();

        self::assertSame([null, ...$sorted], $read);

        $values = ReviewOrder::by(DB::table('review_order_values')->whereNotNull('value'), 'review_order_values.value')->pluck('value')->all();

        self::assertSame($sorted, $values);

        // A keyset compares as the order does: the values after one are those
        // sorted after it, and only its own bytes equal it.
        foreach ($sorted as $index => $value) {
            $after = ReviewOrder::by(ReviewOrder::compared(DB::table('review_order_values'), 'value', '>', $value), 'value')->pluck('value')->all();
            $equal = ReviewOrder::compared(DB::table('review_order_values'), 'value', '=', $value)->pluck('value')->all();

            self::assertSame(\array_slice($sorted, $index + 1), $after, "after '{$value}'");
            self::assertSame([$value], $equal, "equal to '{$value}'");
        }
    }

    /**
     * A comparison compiles, on each driver's grammar, to the driver's own
     * byte-for-byte expression against the value, cast to bytes on MySQL, and
     * any operator but `>` compares for equality.
     *
     * @return void
     */
    public function testAComparisonCompilesForEachDriver(): void
    {
        $bytes = [
            'sqlite'  => static fn (string $wrapped, string $operator): string => "{$wrapped} collate binary {$operator} ?",
            'pgsql'   => static fn (string $wrapped, string $operator): string => "cast({$wrapped} as text) collate \"C\" {$operator} ?",
            'mysql'   => static fn (string $wrapped, string $operator): string => "cast({$wrapped} as binary) {$operator} cast(? as binary)",
            'mariadb' => static fn (string $wrapped, string $operator): string => "cast({$wrapped} as binary) {$operator} cast(? as binary)",
        ];

        foreach (self::drivers() as $driver) {
            $wrapped = self::wrappedOn($driver, 'review_order_values.value');
            $table   = self::wrappedOn($driver, 'review_order_values');

            foreach (['>' => '>', '=' => '=', '<' => '='] as $operator => $compiled) {
                $query = ReviewOrder::compared(self::queryOn($driver, 'review_order_values'), 'review_order_values.value', $operator, 'a');

                self::assertSame("select * from {$table} where " . $bytes[$driver]($wrapped, $compiled), $query->toSql(), "{$driver} {$operator}");
                self::assertSame(['a'], $query->getBindings());
            }
        }
    }

    /**
     * The order compiles, on each driver's grammar, to the null tag when the
     * column may hold a null, then the driver's own byte-for-byte expression,
     * so what orders a column never rests on how one database sorts.
     *
     * @return void
     */
    public function testTheOrderCompilesForEachDriver(): void
    {
        $bytes = [
            'sqlite'  => static fn (string $wrapped): string => "{$wrapped} collate binary",
            'pgsql'   => static fn (string $wrapped): string => "cast({$wrapped} as text) collate \"C\"",
            'mysql'   => static fn (string $wrapped): string => "cast({$wrapped} as binary)",
            'mariadb' => static fn (string $wrapped): string => "cast({$wrapped} as binary)",
        ];

        foreach (self::drivers() as $driver) {
            $wrapped = self::wrappedOn($driver, 'review_order_values.value');
            $table   = self::wrappedOn($driver, 'review_order_values');

            self::assertSame(
                "select * from {$table} order by case when {$wrapped} is null then 0 else 1 end, " . $bytes[$driver]($wrapped),
                ReviewOrder::by(self::queryOn($driver, 'review_order_values'), 'review_order_values.value', true)->toSql(),
                $driver,
            );
            self::assertSame(
                "select * from {$table} order by " . $bytes[$driver]($wrapped),
                ReviewOrder::by(self::queryOn($driver, 'review_order_values'), 'review_order_values.value')->toSql(),
                $driver,
            );
        }
    }

    /**
     * A query whose connection is not a database connection orders, and
     * compares, by the column as it is, as a driver the order does not know
     * does.
     *
     * @return void
     */
    public function testAQueryWithoutADatabaseConnectionOrdersByTheColumn(): void
    {
        $sqlite = self::queryOn('sqlite', 'review_order_values');
        $query  = new Builder(self::createStub(ConnectionInterface::class), $sqlite->getGrammar(), $sqlite->getProcessor());

        self::assertSame('select * from "review_order_values" order by "value"', ReviewOrder::by($query->from('review_order_values'), 'value')->toSql());

        $compared = new Builder(self::createStub(ConnectionInterface::class), $sqlite->getGrammar(), $sqlite->getProcessor());

        self::assertSame('select * from "review_order_values" where "value" > ?', ReviewOrder::compared($compared->from('review_order_values'), 'value', '>', 'a')->toSql());
    }

    /**
     * Each driver orders through its own byte-for-byte expression, and one it
     * does not know by the column as it is.
     *
     * @return void
     */
    public function testAnUnknownDriverOrdersByTheColumn(): void
    {
        $method = new \ReflectionMethod(ReviewOrder::class, 'bytes');

        self::assertSame('"value"', $method->invoke(null, 'sqlsrv', 'value', '"value"'));
        self::assertSame('cast("value" as text) collate "C"', $method->invoke(null, 'pgsql', 'value', '"value"'));
        self::assertSame('cast(`value` as binary)', $method->invoke(null, 'mysql', 'value', '`value`'));
        self::assertSame('cast(`value` as binary)', $method->invoke(null, 'mariadb', 'value', '`value`'));
        self::assertSame('"value" collate binary', $method->invoke(null, 'sqlite', 'value', '"value"'));

        // A reference column is left as it is stored where it compares its
        // bytes already, and only collated where it is text; MariaDB's
        // reference columns keep their collation, so they are cast.
        self::assertSame('"tenant_id"', $method->invoke(null, 'sqlsrv', 'grants.tenant_id', '"tenant_id"'));
        self::assertSame('"tenant_id" collate "C"', $method->invoke(null, 'pgsql', 'grants.tenant_id', '"tenant_id"'));
        self::assertSame('`tenant_id`', $method->invoke(null, 'mysql', 'grants.tenant_id', '`tenant_id`'));
        self::assertSame('`tenant_id`', $method->invoke(null, 'mysql', 'tenant_id', '`tenant_id`'));
        self::assertSame('cast(`tenant_id` as binary)', $method->invoke(null, 'mariadb', 'tenant_id', '`tenant_id`'));
        self::assertSame('"tenant_id" collate binary', $method->invoke(null, 'sqlite', 'tenant_id', '"tenant_id"'));
        self::assertSame('cast(`tenant_ids` as binary)', $method->invoke(null, 'mysql', 'grants.tenant_ids', '`tenant_ids`'));
        self::assertSame('cast(`tenant_id.x` as binary)', $method->invoke(null, 'mysql', 'tenant_id.x', '`tenant_id.x`'));
    }

    /**
     * A reference column, which the package collates `utf8mb4_0900_bin` on
     * MySQL, is ordered and compared as it is stored there, and only collated
     * `C` on PostgreSQL, yet still byte for byte, as `strcmp()` orders it, on
     * every database: so an index on the column serves the order.
     *
     * @return void
     */
    public function testAReferenceColumnOrdersByteForByteAsItIsStored(): void
    {
        $exact = new ExactReferences(DB::connection());

        Schema::create('review_order_references', static function (Blueprint $table) use ($exact): void {
            $table->increments('id');
            $table->string('tenant_id', 191)->nullable();

            $exact->apply($table);
        });

        $values = ['b', 'B', 'a ', 'a', "\u{e4}", "\u{1f600}", 'Z', '_', '%', '10', '9', ''];

        foreach ($values as $value) {
            DB::table('review_order_references')->insert(['tenant_id' => $value]);
        }

        \usort($values, static fn (string $one, string $other): int => \strcmp($one, $other));

        self::assertSame($values, ReviewOrder::by(DB::table('review_order_references'), 'review_order_references.tenant_id')->pluck('tenant_id')->all());

        foreach ($values as $index => $value) {
            $after = ReviewOrder::by(ReviewOrder::compared(DB::table('review_order_references'), 'tenant_id', '>', $value), 'tenant_id')->pluck('tenant_id')->all();
            $equal = ReviewOrder::compared(DB::table('review_order_references'), 'tenant_id', '=', $value)->pluck('tenant_id')->all();

            self::assertSame(\array_slice($values, $index + 1), $after, "after '{$value}'");
            self::assertSame([$value], $equal, "equal to '{$value}'");
        }
    }

    /**
     * On PostgreSQL the leading columns of a keyset are bounded together, as a
     * row, through each column's byte-for-byte expression, so an index leading
     * with them seeks to the bound; on every other database, and with no
     * column, the query is left as it is.
     *
     * @return void
     */
    public function testLeadingColumnsAreBoundedAsARowOnPostgreSql(): void
    {
        $query = ReviewOrder::atLeast(self::queryOn('pgsql', 'grants'), ['grants.authorizable_type' => 'u', 'grants.role_id' => 'r']);

        self::assertSame('select * from "grants" where ("grants"."authorizable_type" collate "C", cast("grants"."role_id" as text) collate "C") >= (?, ?)', $query->toSql());
        self::assertSame(['u', 'r'], $query->getBindings());

        foreach (['sqlite', 'mysql', 'mariadb'] as $driver) {
            $bounded = ReviewOrder::atLeast(self::queryOn($driver, 'grants'), ['grants.authorizable_type' => 'u']);

            self::assertSame('select * from ' . self::wrappedOn($driver, 'grants'), $bounded->toSql(), $driver);
        }

        self::assertSame('select * from "grants"', ReviewOrder::atLeast(self::queryOn('pgsql', 'grants'), [])->toSql());

        // The bound keeps the rows at and after it, byte for byte, and no
        // other, on the database the tests run on, whose reference columns are
        // made as the package makes them.
        $exact = new ExactReferences(DB::connection());

        Schema::create('review_order_pairs', static function (Blueprint $table) use ($exact): void {
            $table->increments('id');
            $table->string('authorizable_type', 191);
            $table->string('authorizable_id', 191);

            $exact->apply($table);
        });

        foreach ([['a', 'b'], ['a', 'c'], ['b', 'a'], ['B', 'z']] as [$type, $id]) {
            DB::table('review_order_pairs')->insert(['authorizable_type' => $type, 'authorizable_id' => $id]);
        }

        $bounded = ReviewOrder::atLeast(DB::table('review_order_pairs'), ['review_order_pairs.authorizable_type' => 'a', 'review_order_pairs.authorizable_id' => 'c']);
        $kept    = ReviewOrder::by($bounded, 'review_order_pairs.authorizable_type')->pluck('authorizable_type')->all();

        self::assertSame(DB::connection()->getDriverName() === 'pgsql' ? ['a', 'b'] : ['B', 'a', 'a', 'b'], $kept);
    }

    /**
     * Two sort keys compare part by part: strings byte for byte, integers and
     * booleans by value, a null first, and a prefix before the longer key.
     *
     * @return void
     */
    public function testSortKeysComparePartByPart(): void
    {
        self::assertSame(-1, ReviewOrder::compare(['B'], ['a']));
        self::assertSame(1, ReviewOrder::compare(['b'], ['a']));
        self::assertSame(0, ReviewOrder::compare(['a', 1, true], ['a', 1, true]));
        self::assertSame(-1, ReviewOrder::compare([1, 'z'], [2, 'a']));
        self::assertSame(1, ReviewOrder::compare([10], [9]));
        self::assertSame(-1, ReviewOrder::compare([false], [true]));
        self::assertSame(-1, ReviewOrder::compare([null], [0]));
        self::assertSame(1, ReviewOrder::compare([0], [null]));
        self::assertSame(-1, ReviewOrder::compare(['a'], ['a', 'b']));
        self::assertSame(1, ReviewOrder::compare(['a', 'b'], ['a']));
        self::assertSame(0, ReviewOrder::compare([], []));
        self::assertSame(-1, ReviewOrder::compare(['10'], ['9']));
        self::assertSame(1, ReviewOrder::compare(["\u{e4}"], ['z']));
    }

    /**
     * A nullable value's sort key is tagged, a null first.
     *
     * @return void
     */
    public function testANullableValueIsTagged(): void
    {
        self::assertSame([0, ''], ReviewOrder::nullable(null));
        self::assertSame([1, ''], ReviewOrder::nullable(''));
        self::assertSame([1, 'a'], ReviewOrder::nullable('a'));
    }

    /**
     * A key is each part's length in bytes and its bytes, a null as `~`, so no
     * two lists of parts share one.
     *
     * @return void
     */
    public function testAKeyNamesItsPartsUnambiguously(): void
    {
        self::assertSame('1:a|~|0:|2:|b', ReviewOrder::key(['a', null, '', '|b']));
        self::assertSame("2:\u{e4}", ReviewOrder::key(["\u{e4}"]));
        self::assertSame('', ReviewOrder::key([]));
        self::assertNotSame(ReviewOrder::key(['a|1:b']), ReviewOrder::key(['a', 'b']));
        self::assertNotSame(ReviewOrder::key(['~']), ReviewOrder::key([null]));
    }
}
