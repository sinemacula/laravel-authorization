<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException;

/**
 * Unit tests for `InvalidCheckArgumentException`, which refuses an argument a
 * route middleware, a Blade directive or a check over several actions cannot
 * honour.
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

    /**
     * An ambiguous guard names the guard and how to write it unambiguously.
     *
     * @return void
     */
    public function testAmbiguousGuardNamesTheGuardAndItsPrefixedForm(): void
    {
        self::assertSame(
            '\'admin\' is both an authentication guard and a role. Separate several roles with \'|\', or write the guard as \'guard=admin\'.',
            InvalidCheckArgumentException::ambiguousGuard('admin')->getMessage(),
        );
    }

    /**
     * Too many directive arguments names the directive and the count given.
     *
     * @return void
     */
    public function testTooManyDirectiveArgumentsNamesTheDirectiveAndTheCount(): void
    {
        self::assertSame(
            '@role takes at most two arguments, 3 given. Separate several names with \'|\', not \',\'.',
            InvalidCheckArgumentException::tooManyDirectiveArguments('role', 3)->getMessage(),
        );
    }

    /**
     * A list naming nothing names the middleware.
     *
     * @return void
     */
    public function testNoNamesNamesTheMiddleware(): void
    {
        self::assertSame(
            'App\Middleware names nothing to check. List one or more names, separated by \'|\'.',
            InvalidCheckArgumentException::noNames('App\Middleware')->getMessage(),
        );
    }

    /**
     * A check over several actions given none names the method.
     *
     * @return void
     */
    public function testNoActionsNamesTheMethod(): void
    {
        self::assertSame('all() takes at least one action to decide, none given.', InvalidCheckArgumentException::noActions('all')->getMessage());
    }

    /**
     * A bulk check given something other than a check names its key.
     *
     * @return void
     */
    public function testNotACheckNamesTheKey(): void
    {
        $message = 'checkMany() takes a CheckInput for each check to decide; the check at key ';

        self::assertSame($message . '\'posts\' is not one.', InvalidCheckArgumentException::notACheck('posts')->getMessage());
        self::assertSame($message . '\'3\' is not one.', InvalidCheckArgumentException::notACheck(3)->getMessage());
    }
}
