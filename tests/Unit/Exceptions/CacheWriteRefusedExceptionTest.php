<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\CacheWriteRefusedException;

/**
 * Unit tests for `CacheWriteRefusedException`, a write the resolution cache
 * store refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CacheWriteRefusedException::class)]
final class CacheWriteRefusedExceptionTest extends TestCase
{
    /**
     * The exception is a runtime exception that says the store refused a write.
     *
     * @return void
     */
    public function testItSaysTheStoreRefusedAWrite(): void
    {
        $exception = new CacheWriteRefusedException;

        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertSame('The resolution cache store refused a write.', $exception->getMessage());
    }
}
