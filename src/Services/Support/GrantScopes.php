<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Where the grant service writes a grant (AUTHZ-5.1, AUTHZ-5.2, D15): in the
 * tenant that owns the target, else the tenant a call names, else
 * platform-wide; a target one tenant owns is never granted anywhere else.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class GrantScopes
{
    /**
     * Return the reference to the tenant a call names, or null for none.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    public static function named(Model|Reference|null $tenant): ?Reference
    {
        if (!$tenant instanceof Model) {
            return $tenant;
        }

        [$type, $id] = TenantScope::extractTenantPair($tenant);

        return new Reference($type, $id);
    }

    /**
     * Return the scope a grant of the target holds in: the tenant that owns it,
     * else the tenant named, else null for platform-wide. A target one tenant
     * owns cannot be granted in another.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model  $target
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $named
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException
     */
    public static function of(GrantTarget $kind, Model $target, ?Reference $named): ?Reference
    {
        $scope = $named ?? Reference::tenantOf($target);

        self::assertGrantableIn($kind, $target, $scope);

        return $scope;
    }

    /**
     * Return the tenant that owns every target of a sync, or null for the
     * platform when any target is the platform's, their owners differ, or there
     * is none.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  string|null  $guard
     * @param  array<int, mixed>  $targets
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    public static function commonOwner(GrantTarget $kind, ?string $guard, array $targets): ?Reference
    {
        $owners = \array_map(static fn (mixed $target): ?Reference => Reference::tenantOf($kind->resolve($target, $guard)), $targets);
        $first  = $owners[0] ?? null;

        foreach ($owners as $owner) {
            if (!self::isSameTenant($owner, $first)) {
                return null;
            }
        }

        return $first;
    }

    /**
     * Refuse a target one tenant owns in any scope but that tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model  $target
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $scope
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException
     */
    public static function assertGrantableIn(GrantTarget $kind, Model $target, ?Reference $scope): void
    {
        $owner = Reference::tenantOf($target);

        if ($owner === null || self::isSameTenant($owner, $scope)) {
            return;
        }

        /** @var string $name */
        $name = $target->getAttribute('name');

        throw new GrantScopeMismatchException($kind->value, $name, $owner, $scope);
    }

    /**
     * Determine whether two scopes are the same: the same tenant, or both the
     * platform.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $left
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $right
     * @return bool
     */
    private static function isSameTenant(?Reference $left, ?Reference $right): bool
    {
        return $left?->type === $right?->type && $left?->id === $right?->id;
    }
}
