<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;

/**
 * Unit tests for `UnknownRoleException`, the programming error raised when the
 * calling code names a role that does not exist.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UnknownRoleException::class)]
final class UnknownRoleExceptionTest extends TestCase
{
    /**
     * The exception is a runtime error that names the role and exposes it.
     *
     * @return void
     */
    public function testNamesTheRole(): void
    {
        $exception = new UnknownRoleException('admin');

        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertSame('admin', $exception->getRole());
        self::assertSame('Unknown role \'admin\'.', $exception->getMessage());
    }

    /**
     * The exception carries no HTTP-like status code.
     *
     * @return void
     */
    public function testCarriesNoStatusLikeCode(): void
    {
        self::assertSame(0, (new UnknownRoleException('admin'))->getCode());
    }
}
