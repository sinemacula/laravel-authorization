<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use Illuminate\Foundation\Auth\User;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\UnsavedRecordException;

/**
 * Unit tests for `UnsavedRecordException`, the programming error raised when a
 * record service is handed a model of its kind that has not been saved.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UnsavedRecordException::class)]
final class UnsavedRecordExceptionTest extends TestCase
{
    /**
     * The message names the service's kind and the unsaved model's class, and
     * the kind is exposed.
     *
     * @return void
     */
    public function testNamesTheKindAndTheUnsavedModel(): void
    {
        $exception = new UnsavedRecordException('policy', new User);

        self::assertInstanceOf(\InvalidArgumentException::class, $exception);
        self::assertSame('The policy service takes a saved policy, not an unsaved ' . User::class . '.', $exception->getMessage());
        self::assertSame('policy', $exception->getKind());
    }
}
