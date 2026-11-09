<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\InvalidReviewCursorException;

/**
 * Unit tests for the refusal of a review cursor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InvalidReviewCursorException::class)]
final class InvalidReviewCursorExceptionTest extends TestCase
{
    /**
     * A cursor is refused as an invalid argument with the one message, which
     * says nothing of why.
     *
     * @return void
     */
    public function testACursorIsRefusedWithTheOneMessage(): void
    {
        $exception = InvalidReviewCursorException::refused();

        self::assertInstanceOf(\InvalidArgumentException::class, $exception);
        self::assertSame('The access review cursor is not valid for this review.', $exception->getMessage());
        self::assertSame(0, $exception->getCode());
        self::assertNull($exception->getPrevious());
    }
}
