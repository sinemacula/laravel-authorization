<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Database\BreakGlassActivations;
use SineMacula\Laravel\Authorization\Models\BreakGlassActivation;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Stores break-glass activations as a test needs them, through the model: an
 * emergency role carrying an action, and an activation of it for a grantee,
 * platform-wide and live for half an hour unless the columns say otherwise,
 * with a note no output may show. Break-glass is switched on before each test,
 * as it is off by default.
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
     * Switch break-glass on before the test.
     *
     * @return void
     */
    protected function setUpActivatesBreakGlass(): void
    {
        self::switchBreakGlass(true);
    }

    /**
     * Switch break-glass on or off with the settings given, as the next request
     * or job would read it, `responder` listed with the global maximum and
     * `incident` the one code unless the settings say otherwise.
     *
     * @param  bool  $isEnabled
     * @param  array<string, mixed>  $settings
     * @return void
     */
    protected static function switchBreakGlass(bool $isEnabled, array $settings = []): void
    {
        config()->set('authorization.break_glass', ['enabled' => $isEnabled, 'roles' => ['responder' => []], 'justifications' => ['incident'], ...$settings]);

        app()->forgetInstance(BreakGlassActivations::class);
        app()->forgetInstance(ResolutionCache::class);
    }

    /**
     * Store an activation of the role for the grantee through the model,
     * platform-wide, live for half an hour, with the columns given in place.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  array<string, mixed>  $columns
     * @return \SineMacula\Laravel\Authorization\Models\BreakGlassActivation
     */
    protected static function activate(Model|Reference $grantee, Role $role, array $columns = []): BreakGlassActivation
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
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return array{authorizable_type: string, authorizable_id: string}
     */
    protected static function granteeColumns(Model|Reference $grantee): array
    {
        return ['authorizable_type' => $grantee->getMorphClass(), 'authorizable_id' => Reference::of($grantee)->id];
    }
}
