<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionAttributeException;

/**
 * Unit tests for `InvalidPermissionAttributeException`.
 *
 * The exception is raised by the permission enum walker when a `#[Permission]`
 * attribute carries an invalid configuration. The constructor formats a stable
 * message and exposes the enum class, case name, and validation reason through
 * typed accessors consumed by the sync command's error renderer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(InvalidPermissionAttributeException::class)]
final class InvalidPermissionAttributeExceptionTest extends TestCase
{
    /**
     * The constructor formats a stable message that names the enum class and
     * case, and exposes each constructor argument through a dedicated accessor.
     *
     * @return void
     */
    public function testConstructsMessageAndExposesAccessors(): void
    {
        $exception = new InvalidPermissionAttributeException(
            enumClass: \stdClass::class,
            caseName: 'POSTS_BROKEN',
            reason: 'guards must not be empty',
        );

        self::assertSame(\stdClass::class, $exception->getEnumClass());
        self::assertSame('POSTS_BROKEN', $exception->getCaseName());
        self::assertSame('guards must not be empty', $exception->getReason());
        self::assertStringContainsString(\stdClass::class, $exception->getMessage());
        self::assertStringContainsString('POSTS_BROKEN', $exception->getMessage());
        self::assertStringContainsString('guards must not be empty', $exception->getMessage());
    }
}
