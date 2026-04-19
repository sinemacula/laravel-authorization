<?php

declare(strict_types = 1);

namespace Tests\Unit\Attributes;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Attributes\Permission;

/**
 * Unit tests for the per-case permission metadata attribute.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(Permission::class)]
final class PermissionTest extends TestCase
{
    /**
     * All fields default to null when no arguments are supplied.
     *
     * @return void
     */
    public function testDefaultConstructionLeavesEveryFieldNull(): void
    {
        $attribute = new Permission;

        self::assertNull($attribute->description);
        self::assertNull($attribute->category);
        self::assertNull($attribute->guards);
    }

    /**
     * Description is exposed verbatim via the readonly public property.
     *
     * @return void
     */
    public function testDescriptionIsExposedAsReadonlyProperty(): void
    {
        $attribute = new Permission(description: 'View applications');

        self::assertSame('View applications', $attribute->description);
        self::assertNull($attribute->category);
        self::assertNull($attribute->guards);
    }

    /**
     * Category is exposed verbatim via the readonly public property.
     *
     * @return void
     */
    public function testCategoryIsExposedAsReadonlyProperty(): void
    {
        $attribute = new Permission(category: 'Applications');

        self::assertSame('Applications', $attribute->category);
        self::assertNull($attribute->description);
        self::assertNull($attribute->guards);
    }

    /**
     * Guards is exposed verbatim via the readonly public property.
     *
     * @return void
     */
    public function testGuardsIsExposedAsReadonlyProperty(): void
    {
        $attribute = new Permission(guards: ['web', 'api']);

        self::assertSame(['web', 'api'], $attribute->guards);
        self::assertNull($attribute->description);
        self::assertNull($attribute->category);
    }

    /**
     * Every field populated simultaneously is stored verbatim.
     *
     * @return void
     */
    public function testAllFieldsPopulatedAreStoredVerbatim(): void
    {
        $attribute = new Permission(
            description: 'View applications',
            category: 'Applications',
            guards: ['web', 'api'],
        );

        self::assertSame('View applications', $attribute->description);
        self::assertSame('Applications', $attribute->category);
        self::assertSame(['web', 'api'], $attribute->guards);
    }

    /**
     * The attribute targets class constants (enum cases are class constants
     * in PHP's reflection model).
     *
     * @return void
     */
    public function testAttributeTargetsClassConstants(): void
    {
        $reflection = new \ReflectionClass(Permission::class);
        $attributes = $reflection->getAttributes(\Attribute::class);

        self::assertCount(1, $attributes);

        $attribute = $attributes[0]->newInstance();

        self::assertSame(\Attribute::TARGET_CLASS_CONSTANT, $attribute->flags);
    }
}
