<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Scopes\ExcludesDeprecatedScope;
use Tests\TestCase;

/**
 * Feature coverage for the `ExcludesDeprecatedScope` global scope on
 * `Permission`.
 *
 * The default query surface hides deprecated rows; both the `withDeprecated()`
 * helper and the raw `withoutGlobalScope()` escape hatch surface them again
 * without affecting any other scope applied to the model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ExcludesDeprecatedScope::class)]
#[CoversClass(Permission::class)]
final class ExcludesDeprecatedScopeTest extends TestCase
{
    /**
     * The default query surface omits any row with a non-null `deprecated_at`.
     *
     * @return void
     */
    public function testDefaultQueryExcludesDeprecatedRows(): void
    {
        Permission::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'scope:live',
            'guard' => 'web',
        ]);
        Permission::create([
            'id'            => (string) Str::uuid(),
            'name'          => 'scope:retired',
            'guard'         => 'web',
            'deprecated_at' => now(),
        ]);

        $names = Permission::query()->pluck('name')->all();

        self::assertContains('scope:live', $names);
        self::assertNotContains('scope:retired', $names);
    }

    /**
     * `Permission::withDeprecated()` surfaces deprecated rows alongside live
     * ones.
     *
     * @return void
     */
    public function testWithDeprecatedHelperIncludesDeprecatedRows(): void
    {
        Permission::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'scope:live',
            'guard' => 'web',
        ]);
        Permission::create([
            'id'            => (string) Str::uuid(),
            'name'          => 'scope:retired',
            'guard'         => 'web',
            'deprecated_at' => now(),
        ]);

        $names = Permission::withDeprecated()->pluck('name')->all();

        self::assertContains('scope:live', $names);
        self::assertContains('scope:retired', $names);
    }

    /**
     * Calling `withoutGlobalScope` directly with the scope class produces the
     * same escape hatch as `withDeprecated()`.
     *
     * @return void
     */
    public function testWithoutGlobalScopeBypassesTheExclusion(): void
    {
        Permission::create([
            'id'            => (string) Str::uuid(),
            'name'          => 'scope:retired',
            'guard'         => 'web',
            'deprecated_at' => now(),
        ]);

        $names = Permission::query()
            ->withoutGlobalScope(ExcludesDeprecatedScope::class)
            ->pluck('name')
            ->all();

        self::assertContains('scope:retired', $names);
    }
}
