<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Models\Permission;
use Tests\TestCase;

/**
 * Feature coverage for the nullable `category` column on permissions.
 *
 * Verifies that a permission created with a category value persists
 * and reloads correctly, and that the column remains nullable.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Permission::class)]
final class PermissionCategoryTest extends TestCase
{
    /**
     * A permission created with a category persists the value.
     *
     * @return void
     */
    public function testPermissionCategoryPersists(): void
    {
        $permission = Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'posts:create',
            'guard_name' => 'web',
            'category'   => 'Content Management',
        ]);

        $reloaded = Permission::query()->whereKey($permission->getKey())->first();

        self::assertNotNull($reloaded);
        self::assertSame('Content Management', $reloaded->category);
    }

    /**
     * A permission created without a category defaults to null.
     *
     * @return void
     */
    public function testPermissionCategoryDefaultsToNull(): void
    {
        $permission = Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'posts:delete',
            'guard_name' => 'web',
        ]);

        $reloaded = Permission::query()->whereKey($permission->getKey())->first();

        self::assertNotNull($reloaded);
        self::assertNull($reloaded->category);
    }
}
