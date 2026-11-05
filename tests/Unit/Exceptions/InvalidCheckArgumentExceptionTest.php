<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException;

/**
 * Unit tests for `InvalidCheckArgumentException`, which refuses an argument a
 * route middleware or a Blade directive cannot honour.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InvalidCheckArgumentException::class)]
final class InvalidCheckArgumentExceptionTest extends TestCase
{
    /**
     * The exception is a programming error, not a denial.
     *
     * @return void
     */
    public function testIsAnInvalidArgument(): void
    {
        self::assertInstanceOf(\InvalidArgumentException::class, InvalidCheckArgumentException::unknownGuard('api'));
        self::assertSame(0, InvalidCheckArgumentException::unknownGuard('api')->getCode());
    }

    /**
     * An unknown guard is named, with how a role check reads its arguments.
     *
     * @return void
     */
    public function testUnknownGuardNamesTheGuard(): void
    {
        self::assertSame(
            '\'editor\' is not an authentication guard. A role check takes the roles, separated by \'|\', then an optional guard.',
            InvalidCheckArgumentException::unknownGuard('editor')->getMessage(),
        );
    }

    /**
     * An unsupported guard names the check and the guard.
     *
     * @return void
     */
    public function testUnsupportedGuardNamesTheCheckAndTheGuard(): void
    {
        self::assertSame(
            'A permission check takes no guard: it is decided on the full authorization decision, which no guard changes. Remove the guard \'web\'.',
            InvalidCheckArgumentException::unsupportedGuard('permission', 'web')->getMessage(),
        );
    }

    /**
     * Too many arguments names the middleware and the count given.
     *
     * @return void
     */
    public function testTooManyArgumentsNamesTheMiddlewareAndTheCount(): void
    {
        self::assertSame(
            'App\Middleware takes at most two arguments, 3 given. Separate several names with \'|\', not \',\'.',
            InvalidCheckArgumentException::tooManyArguments('App\Middleware', 3)->getMessage(),
        );
    }
}
