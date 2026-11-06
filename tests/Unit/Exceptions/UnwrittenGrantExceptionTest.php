<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\UnwrittenGrantException;

/**
 * Unit tests for `UnwrittenGrantException`, raised when a boundary or a
 * resource policy attachment could not be written.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UnwrittenGrantException::class)]
final class UnwrittenGrantExceptionTest extends TestCase
{
    /**
     * The message names what was not written and that the call may be retried,
     * and what was not written is exposed.
     *
     * @return void
     */
    public function testNamesWhatWasNotWritten(): void
    {
        $exception = new UnwrittenGrantException('boundary of user:user-1');

        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertSame('The boundary of user:user-1 was not written: no row was stored or found once the write was tried again; retry the call.', $exception->getMessage());
        self::assertSame('boundary of user:user-1', $exception->getGrant());
    }
}
