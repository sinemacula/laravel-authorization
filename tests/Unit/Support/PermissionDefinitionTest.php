<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;

/**
 * Unit tests for `PermissionDefinition`, one permission the application
 * declares in code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PermissionDefinition::class)]
final class PermissionDefinitionTest extends TestCase
{
    /**
     * A definition given only a name is guard-agnostic, with no description or
     * category.
     *
     * @return void
     */
    public function testDefaultsToGuardAgnosticWithoutMetadata(): void
    {
        $definition = new PermissionDefinition('posts:create');

        self::assertSame('posts:create', $definition->name);
        self::assertNull($definition->description);
        self::assertNull($definition->category);
        self::assertNull($definition->guard);
    }

    /**
     * The key joins the name and the guard with a NUL byte, so no name and
     * guard pair can produce another pair's key.
     *
     * @return void
     */
    public function testKeyJoinsTheNameAndTheGuard(): void
    {
        self::assertSame("posts:create\0web", (new PermissionDefinition(name: 'posts:create', guard: 'web'))->key());
        self::assertSame("posts:create\0", (new PermissionDefinition('posts:create'))->key());
        self::assertNotSame(PermissionDefinition::keyOf('posts:createweb', null), PermissionDefinition::keyOf('posts:create', 'web'));
    }

    /**
     * A null guard and an empty one give the same key.
     *
     * @return void
     */
    public function testNullAndEmptyGuardsShareAKey(): void
    {
        self::assertSame(PermissionDefinition::keyOf('posts:create', null), PermissionDefinition::keyOf('posts:create', ''));
    }

    /**
     * The definition has the given metadata only when both the description and
     * the category are the ones it declares.
     *
     * @return void
     */
    public function testHasMetadataComparesTheDescriptionAndTheCategory(): void
    {
        $definition = new PermissionDefinition(name: 'posts:create', description: 'Create posts', category: 'Posts');

        self::assertTrue($definition->hasMetadata('Create posts', 'Posts'));
        self::assertFalse($definition->hasMetadata('Write posts', 'Posts'));
        self::assertFalse($definition->hasMetadata('Create posts', 'Content'));
        self::assertFalse($definition->hasMetadata(null, null));
        self::assertTrue((new PermissionDefinition('posts:create'))->hasMetadata(null, null));
    }
}
