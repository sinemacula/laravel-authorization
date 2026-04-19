<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Support\PermissionMetadataReader;
use Tests\Unit\Support\Stubs\FixturePermission;

/**
 * Unit tests for the permission metadata reader.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PermissionMetadataReader::class)]
final class PermissionMetadataReaderTest extends TestCase
{
    /**
     * A case with no `#[Permission]` attribute yields a default
     * (all-null) instance.
     *
     * @return void
     */
    public function testReturnsDefaultInstanceWhenAttributeIsAbsent(): void
    {
        $case   = new \ReflectionEnumUnitCase(FixturePermission::class, 'DELETE_APPLICATIONS');
        $reader = new PermissionMetadataReader;

        $meta = $reader->read($case);

        self::assertInstanceOf(PermissionMeta::class, $meta);
        self::assertNull($meta->description);
        self::assertNull($meta->category);
        self::assertNull($meta->guards);
    }

    /**
     * A case with a populated `#[Permission]` attribute yields the
     * attribute instance verbatim.
     *
     * @return void
     */
    public function testReturnsPopulatedAttributeInstanceWhenPresent(): void
    {
        $case   = new \ReflectionEnumUnitCase(FixturePermission::class, 'VIEW_APPLICATIONS');
        $reader = new PermissionMetadataReader;

        $meta = $reader->read($case);

        self::assertInstanceOf(PermissionMeta::class, $meta);
        self::assertSame('View applications', $meta->description);
        self::assertSame('Applications', $meta->category);
        self::assertSame(['web', 'api'], $meta->guards);
    }
}
