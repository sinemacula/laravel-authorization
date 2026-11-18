<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Database\KeyAsText;
use Tests\Concerns\CompilesQueries;

/**
 * Unit tests for a definition key column read as text.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyAsText::class)]
final class KeyAsTextTest extends TestCase
{
    use CompilesQueries;

    /**
     * The column is wrapped by the grammar and read as text on PostgreSQL and
     * MySQL.
     *
     * @return void
     */
    public function testTheColumnIsReadAsTextOnPostgresAndMySql(): void
    {
        $compiled = [];

        foreach (self::drivers() as $driver) {
            $compiled[$driver] = (new KeyAsText('roles.id'))->getValue(self::queryOn($driver, 'roles')->getGrammar());
        }

        self::assertSame([
            'sqlite'  => '"roles"."id"',
            'pgsql'   => 'cast("roles"."id" as text)',
            'mysql'   => 'concat(`roles`.`id`, \'\')',
            'mariadb' => 'concat(`roles`.`id`, \'\')',
        ], $compiled);
    }

    /**
     * The expression compiles as a column on either side of a column
     * comparison.
     *
     * @return void
     */
    public function testItComparesAsAColumn(): void
    {
        $query = self::queryOn('pgsql', 'grants')->whereColumn(new KeyAsText('roles.id'), 'grants.grant_id');

        self::assertSame('select * from "grants" where cast("roles"."id" as text) = "grants"."grant_id"', $query->toSql());
    }
}
