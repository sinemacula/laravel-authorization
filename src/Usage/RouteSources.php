<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Usage;

use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use SineMacula\Laravel\Authorization\Database\BreakGlassActivations;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
use SineMacula\Laravel\Authorization\Reviews\Support\Definitions;
use SineMacula\Laravel\Authorization\Support\InheritedPermissions;
use SineMacula\Laravel\Authorization\Support\InheritedPolicies;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The grant routes behind what a grantee's resolution finds, while grant usage
 * is tracked (N100): for each permission, by its name, and each policy, by its
 * key, every live route that gives it, redundant ones included.
 *
 * - A direct grant, or a policy attached to the grantee, is one route.
 * - A role held gives a route for each permission or policy a role of its chain
 *   carries, through the chain up to that role, and, beside it, the route of
 *   the role granted and, when the carrier is an ancestor, the route by which
 *   the ancestor is held, so the role grant and the ancestor it comes through
 *   count as used with what they carried.
 *
 * Everything is read from the rows the resolution itself reads (see
 * `GrantResolver`), in the scope in place, so the routes follow the same live
 * and scope rules as the names, and cost no query of their own. The routes are
 * those an access review lists for the same grants, by the same key (see
 * `GrantUsageKey`), kept as a route map (see `RouteMap`): each grant and each
 * route once, a role's grant and the ancestor it comes through referenced by
 * everything the role carries rather than copied into each.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RouteSources
{
    /** @var list<string> The grant columns that say where a grant was made. */
    public const array SCOPE = ['tenant_type', 'tenant_id', 'application'];

    /**
     * Return the relation reading the columns that say where each grant was
     * made, beside those it reads already.
     *
     * @template TRelation of \Illuminate\Database\Eloquent\Relations\MorphToMany
     *
     * @param  TRelation  $relation
     * @return TRelation
     */
    public static function scoped(MorphToMany $relation): MorphToMany
    {
        $relation->withPivot(self::SCOPE);

        return $relation;
    }

    /**
     * Return the routes behind each permission the grantee holds, by its name:
     * its direct grants, and the routes through the roles it holds.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $grantee
     * @param  \Illuminate\Database\Eloquent\Collection<int, covariant \Illuminate\Database\Eloquent\Model>  $granted
     * @param  \Illuminate\Database\Eloquent\Collection<int, covariant \Illuminate\Database\Eloquent\Model>  $held
     * @param  array<string, list<string>>  $chains
     * @param  \SineMacula\Laravel\Authorization\Support\InheritedPermissions  $inherited
     * @return \SineMacula\Laravel\Authorization\Usage\RouteMap
     */
    public static function permissions(Model $grantee, EloquentCollection $granted, EloquentCollection $held, array $chains, InheritedPermissions $inherited): RouteMap
    {
        $reference = Reference::of($grantee);
        $type      = Definitions::morph(GrantTarget::PERMISSION);
        $map       = new RouteMapBuilder;

        foreach ($granted as $permission) {
            $grant = StoredGrant::throughPivot(GrantTarget::PERMISSION, $permission, $reference);
            $name  = $permission->getAttribute('name');

            $map->give(\is_scalar($name) ? (string) $name : '', $map->route(GrantRoute::to(SourceKind::PERMISSION_GRANT, new Reference($type, $grant->grantId), [], $grant)));
        }

        $carried = [];

        foreach ($inherited->byRole ?? [] as $role => $permissions) {
            foreach ($permissions as $permission) {
                $carried[$role][] = [$permission['name'], $permission['id']];
            }
        }

        self::throughRoles($map, $reference, $held, $chains, $carried, SourceKind::ROLE_PERMISSION, $type);

        return $map->build();
    }

    /**
     * Return the routes behind each policy attached to the grantee, by its key:
     * its own attachments, and the routes through the roles it holds; or null
     * when the roles' hierarchy moved while it was read, so where a policy came
     * through a role cannot be said.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $grantee
     * @param  array<int, array<string, mixed>>  $own
     * @param  \Illuminate\Database\Eloquent\Collection<int, covariant \Illuminate\Database\Eloquent\Model>|null  $held
     * @param  \SineMacula\Laravel\Authorization\Support\InheritedPolicies  $inherited
     * @return \SineMacula\Laravel\Authorization\Usage\RouteMap|null
     */
    public static function policies(Model $grantee, array $own, ?EloquentCollection $held, InheritedPolicies $inherited): ?RouteMap
    {
        if ($held !== null && $inherited->chains === null) {
            return null;
        }

        $reference = Reference::of($grantee);
        $type      = Definitions::morph(GrantTarget::POLICY);
        $map       = new RouteMapBuilder;

        foreach ($own as $row) {
            $key   = \is_scalar($row['policy_id'] ?? null) ? (string) $row['policy_id'] : '';
            $grant = StoredGrant::of(GrantTarget::POLICY, $key, $reference, $row);

            $map->give($key, $map->route(GrantRoute::to(SourceKind::POLICY_ATTACHMENT, new Reference($type, $key), [], $grant)));
        }

        $carried = \array_map(static fn (array $policies): array => \array_map(static fn (string $policy): array => [$policy, $policy], $policies), $inherited->byRole);

        self::throughRoles($map, $reference, $held ?? new EloquentCollection, $inherited->chains ?? [], $carried, SourceKind::ROLE_POLICY, $type);

        return $map->build();
    }

    /**
     * Keep the routes through each role held, by what each carries: for each
     * role of its chain and each thing that role carries, the route through the
     * chain up to it, the route of the role granted and, for an ancestor, the
     * route by which the ancestor is held, the last two kept once each however
     * much the role carries. A role held through a break-glass activation is no
     * stored grant, so no route starts from it, and a use of it never counts as
     * a use of a role grant.
     *
     * @param  \SineMacula\Laravel\Authorization\Usage\RouteMapBuilder  $map
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \Illuminate\Database\Eloquent\Collection<int, covariant \Illuminate\Database\Eloquent\Model>  $held
     * @param  array<string, list<string>>  $chains
     * @param  array<array-key, list<array{string, string}>>  $carried
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind  $kind
     * @param  string  $type
     * @return void
     */
    private static function throughRoles(RouteMapBuilder $map, Reference $grantee, EloquentCollection $held, array $chains, array $carried, SourceKind $kind, string $type): void
    {
        $role = Definitions::morph(GrantTarget::ROLE);

        foreach ($held->filter(static fn (Model $model): bool => BreakGlassActivations::activationOf($model) === null) as $model) {
            $grant   = StoredGrant::throughPivot(GrantTarget::ROLE, $model, $grantee);
            $chain   = $chains[$grant->grantId] ?? [];
            $granted = null;

            foreach ($chain as $depth => $carrier) {
                $path    = \array_slice($chain, 0, $depth + 1);
                $reached = null;

                foreach ($carried[$carrier] ?? [] as [$name, $id]) {
                    $granted ??= $map->route(GrantRoute::to(SourceKind::ROLE_GRANT, new Reference($role, $grant->grantId), [$grant->grantId], $grant));
                    $reached ??= $depth === 0 ? $granted : $map->route(GrantRoute::to(SourceKind::ROLE_INHERITED, new Reference($role, $carrier), $path, $grant));

                    $map->give($name, $map->route(GrantRoute::to($kind, new Reference($type, $id), $path, $grant)), $granted, $reached);
                }
            }
        }
    }
}
