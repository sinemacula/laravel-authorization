<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

/**
 * Eloquent model for role rows.
 *
 * Roles are named buckets of permissions shared across authorizable
 * identities. The `guard_name` column is nullable: a null value
 * marks the role as guard-agnostic (applies to every guard), a
 * concrete string scopes the role to a single guard.
 *
 * @property string $id
 * @property string $name
 * @property string|null $guard_name
 * @property string|null $description
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class Role extends Model
{
    use HasUuids;

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'name',
        'guard_name',
        'description',
    ];

    /**
     * Create a new Eloquent model instance.
     *
     * @param  array<string, mixed>  $attributes
     */
    public function __construct(array $attributes = [])
    {
        parent::__construct($attributes);

        /** @var string $table */
        $table       = config('authorization.tables.roles', 'roles');
        $this->table = $table;
    }

    /**
     * Permissions attached to this role.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany<\SineMacula\Laravel\Authorization\Models\Permission, $this>
     */
    public function permissions(): BelongsToMany
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> $permissionModel */
        $permissionModel = config('authorization.models.permission', Permission::class);

        /** @var string $pivot */
        $pivot = config('authorization.tables.role_permissions', 'role_permissions');

        return $this->belongsToMany(
            related: $permissionModel,
            table: $pivot,
            foreignPivotKey: 'role_id',
            relatedPivotKey: 'permission_id',
        );
    }
}
