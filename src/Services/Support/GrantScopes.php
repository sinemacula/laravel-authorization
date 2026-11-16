<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\RecordOwner;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;

/**
 * Where the grant service writes a grant: in the tenant a call names, else the
 * tenant that owns the target, else platform-wide; a target one tenant owns is
 * granted only in that tenant or a tenant below it.
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
     * Return the scope a call names: the tenant it names (a model taken as its
     * reference), whether a grant reaches the tenants below it, and the
     * application, each before the target's owner settles the tenant.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @param  string|null  $application
     * @return \SineMacula\Laravel\Authorization\Support\GrantScope
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    public static function ofCall(Model|Reference|null $tenant, bool $includeSubtree, ?string $application): GrantScope
    {
        return new GrantScope(self::named($tenant), $application, $includeSubtree);
    }

    /**
     * Return the scope a grant is written in: its tenant, whether it also holds
     * in the tenants below it, and its application. A platform-wide grant
     * counts in every tenant, so it always reaches below.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @param  string|null  $application
     * @return \SineMacula\Laravel\Authorization\Support\GrantScope
     */
    public static function written(?Reference $tenant, bool $includeSubtree, ?string $application): GrantScope
    {
        return new GrantScope($tenant, $application, $includeSubtree || $tenant === null);
    }

    /**
     * Return the scope each key listed is written in, keyed by key, refusing a
     * key listed with both reaches with `InvalidArgumentException`.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  list<array{string, \SineMacula\Laravel\Authorization\Support\GrantScope}>  $listed
     * @return array<string, \SineMacula\Laravel\Authorization\Support\GrantScope>
     *
     * @throws \InvalidArgumentException
     */
    public static function byKey(GrantTarget $kind, array $listed): array
    {
        $scopes = [];

        foreach ($listed as [$key, $scope]) {
            if (($scopes[$key] ?? $scope)->includeSubtree !== $scope->includeSubtree) {
                throw new \InvalidArgumentException("The {$kind->value} [{$key}] is listed with both reaches.");
            }

            $scopes[$key] = $scope;
        }

        return $scopes;
    }

    /**
     * Return the scope a grant of the target holds in: the tenant named, else
     * the tenant that owns it, else null for platform-wide. A target one tenant
     * owns cannot be granted outside that tenant and the tenants below it, and
     * one naming half a tenant nowhere (see `assertGrantableIn()`).
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model  $target
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $named
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException
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
     * Refuse a target one tenant owns in any scope but that tenant and the
     * tenants below it, and a target naming half a tenant, which the package
     * never writes, in every scope: it is neither the platform's nor any
     * tenant's, so it is never granted as though the platform owned it.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model  $target
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $scope
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException
     */
    public static function assertGrantableIn(GrantTarget $kind, Model $target, ?Reference $scope): void
    {
        RecordOwner::assertWhole($target, $kind->value, 'grant');

        $owner = Reference::tenantOf($target);

        if ($owner === null || TenantChain::isWithin($scope, $owner)) {
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
