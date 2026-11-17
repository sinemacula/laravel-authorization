<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\UndeclaredPermissionException;

/**
 * Unit tests for the refusal of a permission name nothing declares.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UndeclaredPermissionException::class)]
final class UndeclaredPermissionExceptionTest extends TestCase
{
    /**
     * The message names the permission and where to declare it, and the
     * accessor returns the name.
     *
     * @return void
     */
    public function testNamesThePermissionAndWhereToDeclareIt(): void
    {
        $exception = new UndeclaredPermissionException('posts:invented');

        self::assertSame('Permission \'posts:invented\' matches no declared permission; declare it in permission_enums or permission_providers.', $exception->getMessage());
        self::assertSame(422, $exception->getCode());
        self::assertSame('posts:invented', $exception->getPermission());
    }
}
