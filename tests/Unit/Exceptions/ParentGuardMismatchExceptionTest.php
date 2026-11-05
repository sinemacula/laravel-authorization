<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\ParentGuardMismatchException;

/**
 * Unit tests for the refusal of a parent role of another guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ParentGuardMismatchException::class)]
final class ParentGuardMismatchExceptionTest extends TestCase
{
    /**
     * A parent guard mismatch names both roles and both guards.
     *
     * @return void
     */
    public function testAParentGuardMismatchNamesBothGuards(): void
    {
        $exception = new ParentGuardMismatchException('editor', 'admin', 'web', 'api');

        self::assertSame(
            'Guard mismatch: role \'editor\' (guard \'web\') cannot sit under parent role \'admin\' (guard \'api\').'
                . ' Scope one side to null for a guard-agnostic link, or match the guards.',
            $exception->getMessage(),
        );
        self::assertSame('editor', $exception->getRoleName());
        self::assertSame('admin', $exception->getParentName());
        self::assertSame('web', $exception->getRoleGuard());
        self::assertSame('api', $exception->getParentGuard());
    }
}
