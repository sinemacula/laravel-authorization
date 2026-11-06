<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query\Dialects;

use Illuminate\Database\Connection;
use SineMacula\Laravel\Authorization\Query\Contracts\Dialect;
use SineMacula\Laravel\Authorization\Query\Enums\ColumnKind;

/**
 * The SQL `whereAuthorized()` writes on PostgreSQL.
 *
 * A value is compared through the UTF-8 bytes of its text, `convert_to(CAST(x
 * AS TEXT), 'UTF8')`, which for an integer are its decimal digits and for a
 * uuid its canonical lower-case form, as PHP reads them, and for text the bytes
 * PHP reads, whatever the column's collation. PostgreSQL text never holds a NUL
 * byte. The server and the client encodings must both be UTF8, so the bytes
 * compared are the bytes PHP reads.
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
}
