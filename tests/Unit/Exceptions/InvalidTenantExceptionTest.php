<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;

/**
 * Unit tests for `InvalidTenantException`, thrown at the tenant-scope boundary
 * for a tenant of an unaccepted shape or one without a key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InvalidTenantException::class)]
final class InvalidTenantExceptionTest extends TestCase
{
    /**
     * The constructor names the accepted shapes and the refused class.
     *
     * @return void
     */
    public function testConstructorNamesTheAcceptedShapes(): void
    {
        $exception = new InvalidTenantException(new \stdClass);

        self::assertSame(
            'Tenant must be an Eloquent Model or implement ' . AuthorizableTenant::class . '. Got stdClass.',
            $exception->getMessage(),
        );
    }

    /**
     * `withoutKey()` names the keyless tenant's class.
     *
     * @return void
     */
    public function testWithoutKeyNamesTheKeylessTenant(): void
    {
        $exception = InvalidTenantException::withoutKey(new \stdClass);

        self::assertSame(
            'Tenant stdClass has no key, so it cannot be matched to the rows it owns.',
            $exception->getMessage(),
        );
    }
}
