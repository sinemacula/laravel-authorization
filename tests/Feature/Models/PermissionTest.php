<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Models\Permission;

/**
 * Feature tests for the string casts on the shipped `Permission` model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Permission::class)]
final class PermissionTest extends StringCastsTestCase
{
    /**
     * Create an instance of the model under test.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    #[\Override]
    protected static function newModel(): Model
    {
        return new Permission;
    }

    /**
     * Return the model's fillable string columns.
     *
     * @return list<string>
     */
    #[\Override]
    protected static function stringColumns(): array
    {
        return ['name', 'guard_name', 'description', 'category', 'tenant_type', 'tenant_id'];
    }
}
