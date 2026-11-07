<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query\Dialects;

use Illuminate\Database\Connection;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authorization\Query\Contracts\Dialect;
use SineMacula\Laravel\Authorization\Query\Enums\ColumnKind;
use SineMacula\Laravel\Authorization\Query\QueryAuthorizer;

/**
 * The SQL `whereAuthorized()` writes on PostgreSQL.
 *
 * A value is compared through the UTF-8 bytes of its text, `convert_to(CAST(x
 * AS TEXT), 'UTF8')`, which for an integer are its decimal digits and for a
 * uuid its canonical lower-case form, as PHP reads them, and for text the bytes
 * PHP reads, whatever the column's collation. PostgreSQL text never holds a NUL
 * byte. The server and the client encodings must both be UTF8, so the bytes
 * compared are the bytes PHP reads. PHP reads every column of these kinds as a
 * string or an integer.
 *
 * The plain comparison an index serves compares a text column with the value
 * decoded from its hex, under the column's collation, under which equal bytes
 * are equal; an integer column with its digits; and a uuid column with its
 * canonical text. A value that is not UTF-8 or holds a NUL byte, which no text
 * holds, or that no integer or uuid reads as, is compared with nothing, since
 * PostgreSQL would raise an error rather than find no row.
 *
 * It also tells whether a key column can be compared with a value at all, which
 * the resolver of a declared model's tenant asks before looking a record up,
 * since an error would abort the transaction around it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PostgresDialect implements Dialect
{
    /** @var array<string, \SineMacula\Laravel\Authorization\Query\Enums\ColumnKind> The kind of each type the scope compares. */
    private const array KINDS = [
        'int2'    => ColumnKind::INTEGER,
        'int4'    => ColumnKind::INTEGER,
        'int8'    => ColumnKind::INTEGER,
        'varchar' => ColumnKind::STRING,
        'text'    => ColumnKind::STRING,
        'uuid'    => ColumnKind::UUID,
    ];

    /** @var array<string, int> The largest value of each integer type. */
    private const array INTEGER_MAX = [
        'int2' => 32767,
        'int4' => 2147483647,
        'int8' => \PHP_INT_MAX,
    ];

    /**
     * Return the kind of a column by its type: `int2`, `int4` and `int8` are
     * integers, `varchar` and `text` strings, `uuid` a uuid; `bpchar`, whose
     * padding PHP reads, is none.
     *
     * @param  array<string, mixed>  $column
     * @return \SineMacula\Laravel\Authorization\Query\Enums\ColumnKind|null
     */
    #[\Override]
    public function kindOf(array $column): ?ColumnKind
    {
        $type = \is_string($column['type_name'] ?? null) ? \strtolower($column['type_name']) : '';

        return self::KINDS[$type] ?? null;
    }

    /**
     * Determine whether the server and the client encodings are both UTF8.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return bool
     */
    #[\Override]
    public function isUtf8(Connection $connection): bool
    {
        $server = (array) $connection->selectOne('SHOW server_encoding');
        $client = (array) $connection->selectOne('SHOW client_encoding');

        return \strtoupper((string) \reset($server)) === 'UTF8' && \strtoupper((string) \reset($client)) === 'UTF8'; // @phpstan-ignore cast.string, cast.string
    }

    /**
     * Return the condition a row's key meets when it identifies a record.
     *
     * @param  string  $key
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\ColumnKind  $kind
     * @param  bool  $isIntegerCast
     * @return string
     */
    #[\Override]
    public function keyGuard(string $key, ColumnKind $kind, bool $isIntegerCast): string
    {
        return $kind === ColumnKind::STRING && !$isIntegerCast
            ? "({$key} IS NOT NULL AND octet_length({$key}) > 0)"
            : "{$key} IS NOT NULL";
    }

    /**
     * Return the byte length of a row's key, which only a string's leaves
     * unbounded.
     *
     * @param  string  $key
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\ColumnKind  $kind
     * @param  bool  $isIntegerCast
     * @return string|null
     */
    #[\Override]
    public function keyLength(string $key, ColumnKind $kind, bool $isIntegerCast): ?string
    {
        return $kind === ColumnKind::STRING && !$isIntegerCast ? "octet_length({$key})" : null;
    }

    /**
     * Determine whether a key column of the type the schema builder describes
     * can be compared with the value without PostgreSQL raising an error: an
     * integer column with the digits of a value its type holds, a uuid column
     * with a uuid, and any other with UTF-8 text.
     *
     * @param  array<string, mixed>  $column
     * @param  string  $value
     * @return bool
     */
    public function isComparableKey(array $column, string $value): bool
    {
        $type      = \is_string($column['type_name'] ?? null) ? \strtolower($column['type_name']) : '';
        $max       = self::INTEGER_MAX[$type] ?? null;
        $isInteger = \preg_match('/\A-?\d{1,18}\z/', $value) === 1 && (int) $value >= -($max ?? 0) - 1 && (int) $value <= ($max ?? 0);

        return match (true) {
            $max !== null    => $isInteger,
            $type === 'uuid' => Str::isUuid($value),
            default          => \mb_check_encoding($value, 'UTF-8'),
        };
    }

    /**
     * Return the condition every row's tenant column meets, since PHP reads
     * each kind the scope compares as a string, an integer or null.
     *
     * @param  string  $column
     * @return string
     */
    #[\Override]
    public function readable(string $column): string
    {
        return QueryAuthorizer::EVERY_ROW;
    }

    /**
     * Return the condition a row's column meets when the UTF-8 bytes of its
     * text are exactly the value's.
     *
     * @param  string  $column
     * @param  string  $value
     * @return string
     */
    #[\Override]
    public function equalsBytes(string $column, string $value): string
    {
        return "convert_to(CAST({$column} AS TEXT), 'UTF8') = decode('" . \bin2hex($value) . '\', \'hex\')';
    }

    /**
     * Return a condition comparing the bare column with the value: a text
     * column with the value decoded, when it is UTF-8 with no NUL byte; an
     * integer column with its digits, when it is an integer's decimal text, as
     * PHP reads one; a uuid column with the value, when it is a uuid's
     * canonical lower-case text, as PHP reads one.
     *
     * @param  string  $column
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\ColumnKind  $kind
     * @param  string  $value
     * @return string
     */
    #[\Override]
    public function equalsIndexed(string $column, ColumnKind $kind, string $value): string
    {
        $isText = \mb_check_encoding($value, 'UTF-8') && !\str_contains($value, "\0");
        $isUuid = \preg_match('/\A[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\z/', $value) === 1;

        return match (true) {
            $kind === ColumnKind::STRING  && $isText                          => "{$column} = convert_from(decode('" . \bin2hex($value) . '\', \'hex\'), \'UTF8\')',
            $kind === ColumnKind::INTEGER && (string) (int) $value === $value => "{$column} = {$value}",
            $kind === ColumnKind::UUID    && $isUuid                          => "{$column} = '{$value}'",
            default                                                           => QueryAuthorizer::NO_ROW,
        };
    }
}
