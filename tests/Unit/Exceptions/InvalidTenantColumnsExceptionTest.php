<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;

/**
 * Unit tests for the refusal of a row naming half a tenant: one tenant column
 * without the other, refused when the row is saved, or when a row stored that
 * way is granted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InvalidTenantColumnsException::class)]
final class InvalidTenantColumnsExceptionTest extends TestCase
{
    /**
     * The refusal names what was refused, saving by default, the kind of row
     * and the column it lacks, and states the invariant.
     *
     * @return void
     */
    public function testTheRefusalNamesTheActionTheKindAndTheMissingColumn(): void
    {
        $invariant = ' with inconsistent tenant columns — \'tenant_type\' is required when the other tenant column is set. '
            . 'Both columns must be null (global row) or both must be non-null (tenant-owned row).';

        self::assertSame('Cannot save role' . $invariant, (new InvalidTenantColumnsException('role', 'tenant_type'))->getMessage());
        self::assertSame('Cannot grant policy' . $invariant, (new InvalidTenantColumnsException('policy', 'tenant_type', 'grant'))->getMessage());
        self::assertInstanceOf(\LogicException::class, new InvalidTenantColumnsException('permission', 'tenant_id'));
    }
}
