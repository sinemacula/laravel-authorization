<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\InvalidRoleExclusionException;

/**
 * Unit tests for the refusal of a role paired with itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InvalidRoleExclusionException::class)]
final class InvalidRoleExclusionExceptionTest extends TestCase
{
    /**
     * The refusal names the role and says why, as an invalid argument.
     *
     * @return void
     */
    public function testNamesTheRole(): void
    {
        $exception = new InvalidRoleExclusionException('clerk');

        self::assertInstanceOf(\InvalidArgumentException::class, $exception);
        self::assertSame('clerk', $exception->getRole());
        self::assertSame('Role \'clerk\' cannot be mutually exclusive with itself: a pair names two roles.', $exception->getMessage());
    }
}
