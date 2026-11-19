<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Config\ModelClasses;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Database\BreakGlassActivations;
use SineMacula\Laravel\Authorization\Events\Grantee\BreakGlassRevoked;
use SineMacula\Laravel\Authorization\Events\Grantee\BreakGlassSurrendered;
use SineMacula\Laravel\Authorization\Models\BreakGlassActivation;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Ends break-glass activations for the break-glass and grant services: the
 * revocation each is decided as, and the end itself, written through the model
 * so the observer bumps the grantee's versions, and reported once the operation
 * commits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ActivationEnds
{
    /**
     * Return the grantee's activations not ended and not yet expired, locked,
     * in key order, whether break-glass is enabled or not, since one grants
     * again once it is.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return list<\SineMacula\Laravel\Authorization\Models\BreakGlassActivation>
     */
    public static function unexpiredOf(Reference $grantee): array
    {
        $query = BreakGlassActivation::query()
            ->useWritePdo()
            ->where('authorizable_type', $grantee->type)
            ->where('authorizable_id', $grantee->id)
            ->orderBy('id')
            ->lockForUpdate();

        BreakGlassActivations::unexpired($query->getQuery(), TableNames::get('break_glass'));

        return \array_values($query->get()->all());
    }

    /**
     * Return the revocation of the activation, decided under the break-glass
     * revoke right in the activation's scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\BreakGlassActivation  $activation
     * @return \SineMacula\Laravel\Authorization\Administration\OperationResource
     */
    public static function revocation(BreakGlassActivation $activation): OperationResource
    {
        return OperationResource::breakGlass(PackagePermissions::BREAK_GLASS_REVOKE, self::granteeOf($activation), self::roleOf($activation), self::scopeOf($activation));
    }

    /**
     * End the activation for the reason, by the operation's actor, unless it
     * has ended or expired already, report the end, and return how many were
     * ended.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\BreakGlassActivation  $activation
     * @param  'revoked'|'surrendered'  $reason
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @return int
     */
    public static function end(BreakGlassActivation $activation, string $reason, Operation $operation): int
    {
        $now = Carbon::now('UTC')->startOfSecond();
        $by  = $operation->actor;

        if ($activation->ended_at !== null || $activation->expires_at->lessThanOrEqualTo($now)) {
            return 0;
        }

        $activation->forceFill(['ended_at' => $now, 'ended_by_type' => $by?->type, 'ended_by_id' => $by?->id, 'end_reason' => $reason])->save();

        $role  = self::roleOf($activation);
        $event = [$operation, self::granteeOf($activation), Reference::of($role), $role->name, self::scopeOf($activation), $activation->id, $now->toImmutable()];

        OperationScope::dispatch($reason === 'surrendered' ? new BreakGlassSurrendered(...$event) : new BreakGlassRevoked(...$event));

        return 1;
    }

    /**
     * Return the activation's role as stored.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\BreakGlassActivation  $activation
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private static function roleOf(BreakGlassActivation $activation): Role
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $class */
        $class = ModelClasses::get('role');

        return $class::query()->withoutGlobalScopes()->useWritePdo()->whereKey($activation->role_id)->firstOrFail();
    }

    /**
     * Return the activation's grantee.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\BreakGlassActivation  $activation
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    private static function granteeOf(BreakGlassActivation $activation): Reference
    {
        return new Reference($activation->authorizable_type, $activation->authorizable_id);
    }

    /**
     * Return the scope the activation holds in.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\BreakGlassActivation  $activation
     * @return \SineMacula\Laravel\Authorization\Support\GrantScope
     */
    private static function scopeOf(BreakGlassActivation $activation): GrantScope
    {
        return new GrantScope(Reference::tenantOf($activation), $activation->application, $activation->include_subtree);
    }
}
