<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Database\MigrationCollisionException;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;

/**
 * Unit tests for the package's typed exceptions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(InvalidPolicyDocumentException::class)]
#[CoversClass(MigrationCollisionException::class)]
final class ExceptionsTest extends TestCase
{
    /**
     * InvalidPolicyDocumentException exposes the policy name.
     *
     * @return void
     */
    public function testInvalidPolicyDocumentException(): void
    {
        $exception = new InvalidPolicyDocumentException('example', 'bad shape');

        self::assertSame(400, $exception->getCode());
        self::assertSame('example', $exception->getPolicyName());
    }

    /**
     * MigrationCollisionException exposes the table name.
     *
     * @return void
     */
    public function testMigrationCollisionException(): void
    {
        $exception = new MigrationCollisionException('roles');

        self::assertSame('roles', $exception->getTable());
    }
}
