<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\ReviewExportException;

/**
 * Unit tests for the failure of an access review's export.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReviewExportException::class)]
final class ReviewExportExceptionTest extends TestCase
{
    /**
     * A stream that takes none of a line fails the export as a runtime failure,
     * naming nothing of what was being written.
     *
     * @return void
     */
    public function testAnUnwritableStreamFailsTheExport(): void
    {
        $exception = ReviewExportException::unwritable();

        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertSame('The access review export could not be written.', $exception->getMessage());
        self::assertNull($exception->getPrevious());
    }
}
