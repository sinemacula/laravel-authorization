<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\GranteeGuardMismatchException;

/**
 * Unit tests for the refusal of a grant to a grantee of another guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GranteeGuardMismatchException::class)]
final class GranteeGuardMismatchExceptionTest extends TestCase
{
    /**
     * A grantee guard mismatch names the record and both guards.
     *
     * @return void
     */
    public function testAGranteeGuardMismatchNamesBothGuards(): void
    {
        $exception = new GranteeGuardMismatchException('permission', 'posts:edit', 'web', 'api');

        self::assertSame('Guard mismatch: permission \'posts:edit\' (guard \'web\') cannot be granted to a grantee of guard \'api\'.', $exception->getMessage());
        self::assertSame('permission', $exception->getKind());
        self::assertSame('posts:edit', $exception->getName());
        self::assertSame('web', $exception->getGuard());
        self::assertSame('api', $exception->getGranteeGuard());
    }
}
