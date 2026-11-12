<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Models\BreakGlassActivation;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Stores break-glass activations as a test needs them, through the model, since
 * nothing in the package creates one yet: an emergency role carrying an action,
 * and an activation of it for a grantee, platform-wide and live for half an
 * hour unless the columns say otherwise, with a note no output may show.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ActivatesBreakGlass
{
    /** @var string The note every activation carries, which nothing may show. */
    protected const string NOTE = 'Paged at 3am by the on-call lead';

    /**
     * Store an activation of the role for the grantee through the model,
     * platform-wide, live for half an hour, with the columns given in place.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  array<string, mixed>  $columns
     * @return \SineMacula\Laravel\Authorization\Models\BreakGlassActivation
     */
    protected static function activate(Model $grantee, Role $role, array $columns = []): BreakGlassActivation
    {
        return BreakGlassActivation::query()->create([
            'role_id' => $role->getKey(),
            ...self::granteeColumns($grantee),
            'justification' => 'incident',
            'note'          => self::NOTE,
            'activated_at'  => Carbon::now(),
            'expires_at'    => Carbon::now()->addMinutes(30),
            ...$columns,
        ]);
    }

    /**
     * Return the emergency role of the name, carrying the action, creating each
     * the first time.
     *
     * @param  string  $action
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    protected static function emergencyRole(string $action = 'posts:create', string $name = 'responder'): Role
    {
        $role = Role::query()->firstOrCreate(['name' => $name]);

        $role->givePermission(Permission::query()->firstOrCreate(['name' => $action]));

        return $role;
    }

    /**
     * Return the grantee's columns of a grant row.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $grantee
     * @return array{authorizable_type: string, authorizable_id: string}
     */
    protected static function granteeColumns(Model $grantee): array
    {
        return ['authorizable_type' => $grantee->getMorphClass(), 'authorizable_id' => Reference::of($grantee)->id];
    }
}
