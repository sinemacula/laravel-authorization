<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException;

/**
 * Unit tests for `InvalidPermissionCatalogueException`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InvalidPermissionCatalogueException::class)]
final class InvalidPermissionCatalogueExceptionTest extends TestCase
{
    /**
     * The message names the declaration at fault and the reason, both of which
     * the accessors return.
     *
     * @return void
     */
    public function testCarriesTheSourceAndTheReason(): void
    {
        $exception = new InvalidPermissionCatalogueException('App\Enums\Permission::EDIT', 'the guard list is empty.');

        self::assertSame('Invalid permission declared by App\Enums\Permission::EDIT: the guard list is empty.', $exception->getMessage());
        self::assertSame('App\Enums\Permission::EDIT', $exception->getSource());
        self::assertSame('the guard list is empty.', $exception->getReason());
        self::assertSame(500, $exception->getCode());
    }
}
