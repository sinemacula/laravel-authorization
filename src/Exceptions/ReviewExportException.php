<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when an access review's export cannot be written: the stream it is
 * written to takes none of what is left of a line (see
 * `Reviews\Support\JsonLinesExport`). The export stops there, with no footer,
 * so a reader of what was written can tell it is incomplete.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ReviewExportException extends \RuntimeException
{
    /**
     * Refuse a stream that takes none of a line.
     *
     * @return self
     */
    public static function unwritable(): self
    {
        return new self('The access review export could not be written.');
    }
}
