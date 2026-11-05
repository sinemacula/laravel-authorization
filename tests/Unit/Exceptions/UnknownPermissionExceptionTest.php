<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;

/**
 * Unit tests for `UnknownPermissionException`, the programming error raised
 * when the calling code names a permission that does not exist.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UnknownPermissionException::class)]
final class UnknownPermissionExceptionTest extends TestCase
{
    /**
     * The exception is a runtime error that names the permission and exposes
     * it.
     *
     * @return void
     */
    public function testNamesThePermission(): void
    {
        $exception = new UnknownPermissionException('posts:create');

        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertSame('posts:create', $exception->getPermission());
        self::assertSame('Unknown permission \'posts:create\'.', $exception->getMessage());
    }

    /**
     * The exception carries no HTTP-like status code.
     *
     * @return void
     */
    public function testCarriesNoStatusLikeCode(): void
    {
        self::assertSame(0, (new UnknownPermissionException('posts:create'))->getCode());
    }
}
