<?php

declare(strict_types = 1);

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\TestCase;

/**
 * Feature tests for the string casts on the shipped models.
 *
 * A driver may hand back a scalar column as an integer or a float; the fillable
 * string columns read back as strings whatever the driver returns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Role::class)]
#[CoversClass(Permission::class)]
#[CoversClass(Policy::class)]
final class ModelStringCastsTest extends TestCase
{
    /**
     * Every fillable string column on the shipped models.
     *
     * @return iterable<string, array{class-string<\Illuminate\Database\Eloquent\Model>, string}>
     */
    public static function stringColumns(): iterable
    {
        $columns = [
            Role::class       => ['name', 'guard_name', 'description', 'parent_id', 'tenant_type', 'tenant_id'],
            Permission::class => ['name', 'guard_name', 'description', 'category', 'tenant_type', 'tenant_id'],
            Policy::class     => ['name', 'description'],
        ];

        foreach ($columns as $class => $attributes) {
            foreach ($attributes as $attribute) {
                yield class_basename($class) . '.' . $attribute => [$class, $attribute];
            }
        }
    }

    /**
     * A stored non-string value in a fillable string column reads back as a
     * string.
     *
     * @param  class-string<\Illuminate\Database\Eloquent\Model>  $class
     * @param  string  $attribute
     * @return void
     */
    #[DataProvider('stringColumns')]
    public function testStringColumnReadsBackAsString(string $class, string $attribute): void
    {
        /** @var \Illuminate\Database\Eloquent\Model $model */
        $model = new $class;

        $model->setRawAttributes([$attribute => 123]);

        self::assertSame('123', $model->getAttribute($attribute));
    }

    /**
     * A null stored in a fillable string column stays null.
     *
     * @param  class-string<\Illuminate\Database\Eloquent\Model>  $class
     * @param  string  $attribute
     * @return void
     */
    #[DataProvider('stringColumns')]
    public function testNullStringColumnStaysNull(string $class, string $attribute): void
    {
        /** @var \Illuminate\Database\Eloquent\Model $model */
        $model = new $class;

        $model->setRawAttributes([$attribute => null]);

        self::assertNull($model->getAttribute($attribute));
    }
}
