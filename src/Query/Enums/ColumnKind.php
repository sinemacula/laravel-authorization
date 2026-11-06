<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query\Enums;

/**
 * The kinds of column `whereAuthorized()` can compare exactly with what PHP
 * reads from them: an integer, which PHP reads as an integer or its decimal
 * digits; a string of UTF-8 text, read as its bytes; and, on PostgreSQL, a
 * uuid, read as its canonical lower-case text.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum ColumnKind: string
{
    /** An integer column. */
    case INTEGER = 'integer';

    /** A column of UTF-8 text. */
    case STRING = 'string';

    /** A PostgreSQL uuid column. */
    case UUID = 'uuid';
}
