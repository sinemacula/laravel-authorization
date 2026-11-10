<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Support\AuthorizationLog;
use SineMacula\Laravel\Authorization\Support\GrantExpiry;
use SineMacula\Laravel\Authorization\Support\InheritedPolicies;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\PolicyDocument;
use SineMacula\Laravel\Authorization\Support\RoleGraph;
use SineMacula\Laravel\Authorization\Support\RolePolicies;
use SineMacula\Laravel\Authorization\Usage\RouteSources;

/**
 * Resolves what an identity's grants come to: the names of its roles, the keys
 * of the roles it reaches, the names of its permissions, and its policies.
 *
 * Every read is on the write connection, so a read replica that has not caught
 * up never serves a grant already revoked. Each resolution pins the version of
 * a role or policy before it reads that record, so the resolution cache never
 * stores a value under versions newer than the data it was built from (the
 * cache pins the grantee before the resolution starts). A resolution whose role
 * hierarchy moved while it ran is returned but marked unstable, and is not
 * stored.
 *
 * Each kind takes a fixed number of queries: two for roles, three for the keys
 * of the roles reached, two for policies, and five for permissions however many
 * roles the identity holds and however deep they sit. Policies take four more,
 * however many roles and however deep, only when a role holds a policy in the
 * current scope.
 *
 * While grant usage is tracked (see `ResolutionPins::isRouting()`), the
 * permissions and the policies are resolved with the routes of the stored
 * grants behind each (see `Usage\RouteSources`), read from the same rows in the
 * same queries, each also reading where its grants were made and when; a
 * resolution whose hierarchy moved while it ran says none.
 *
 * @phpstan-type PolicyGrants \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Policy, covariant \Illuminate\Database\Eloquent\Model, *>
 * @phpstan-type RoleGrants \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Role, covariant \Illuminate\Database\Eloquent\Model, *>
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class GrantResolver
{
    /**
     * Resolve the names of the roles granted through the relation.
     *
     * @param  RoleGrants  $grants
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionPins  $pins
     * @return \SineMacula\Laravel\Authorization\Cache\Resolution<string>
     */
    public static function roles(MorphToMany $grants, ResolutionPins $pins): Resolution
    {
        $held = self::held($grants);
        $keys = \array_keys($held->getDictionary());

        $pins->roles($keys);

        /** @var array<string, string> $names */
        $names = $keys === [] ? [] : $grants->getRelated()->newQuery()->useWritePdo()->whereKey($keys)->pluck('name', 'id')->all();

        return new Resolution(self::inOrder($keys, $names), self::expiresIn(null, $held));
    }

    /**
     * Resolve the keys of the roles granted through the relation, with the keys
     * of the roles above them when the hierarchy is enabled: the roles a
     * resource policy's role selector names the grantee by.
     *
     * Every role reached is pinned before the roles are read again, as the
     * permissions are, so a move in the hierarchy while the resolution runs is
     * seen; the roles are then read afresh, and the resolution is marked
     * unstable, so it is kept for the request or job alone and never stored.
     *
     * @param  RoleGrants  $grants
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionPins  $pins
     * @return \SineMacula\Laravel\Authorization\Cache\Resolution<string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public static function roleKeys(MorphToMany $grants, ResolutionPins $pins): Resolution
    {
        $held  = self::held($grants);
        $keys  = \array_keys($held->getDictionary());
        $reach = RoleGraph::reach($keys);

        $pins->roles(\array_keys($reach));

        $within = RoleGraph::keysWithin($reach, $keys);

        return new Resolution(\array_values(\array_unique($within ?? RoleGraph::keysHeldBy(self::rolesAfresh($grants, $keys)))), self::expiresIn(null, $held), $within !== null);
    }

    /**
     * Resolve the names of the permissions granted directly and through the
     * roles, with each role's ancestors' when the hierarchy is enabled.
     *
     * @param  \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Permission, covariant \Illuminate\Database\Eloquent\Model, *>  $direct
     * @param  RoleGrants  $roles
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionPins  $pins
     * @return \SineMacula\Laravel\Authorization\Cache\Resolution<string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public static function permissions(MorphToMany $direct, MorphToMany $roles, ResolutionPins $pins): Resolution
    {
        $granted = self::heldOf($direct, $pins);
        $held    = self::heldOf($roles, $pins);
        $keys    = \array_keys($held->getDictionary());
        $reach   = RoleGraph::reach($keys);

        $pins->roles(\array_keys($reach));

        $chains = $pins->isRouting() ? RoleGraph::chainsWithin($reach, $keys) : null;
        $within = match (true) {
            !$pins->isRouting() => RoleGraph::permissionsWithin($reach, $keys),
            $chains === null    => null,
            default             => RoleGraph::carriedWithin($chains),
        };

        $inherited = $within ?? RoleGraph::permissionsHeldBy(self::rolesAfresh($roles, $keys));

        /** @var list<string> $names */
        $names = $granted->pluck('name')->all();

        return new Resolution(
            \array_values(\array_unique([...$names, ...$inherited->names])),
            self::expiresIn($inherited->expiresIn, $granted, $held),
            $within !== null,
            $chains === null ? null : RouteSources::permissions($direct->getParent(), $granted, $held, $chains, $inherited),
        );
    }

    /**
     * Resolve the policies attached through the relation and, given the
     * relation onto the grantee's roles, those attached to its roles and to the
     * roles above them, hydrated for evaluation, each once.
     *
     * A role's policy applies only where the grant of the role and the
     * attachment of the policy both hold (see `RolePolicies`). The grantee's
     * own attachments are read in one query that also asks whether any role
     * holds a policy in the current scope, so the roles are read only when one
     * might apply. The evaluator orders the policies, by name, then stored key,
     * then document, wherever they came from.
     *
     * A policy whose document cannot be read is written to the log channel and
     * its exception thrown, so it denies every check for its holder rather than
     * being skipped.
     *
     * @param  PolicyGrants  $grants
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionPins  $pins
     * @param  RoleGrants|null  $roles
     * @return \SineMacula\Laravel\Authorization\Cache\Resolution<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public static function policies(MorphToMany $grants, ResolutionPins $pins, ?MorphToMany $roles = null): Resolution
    {
        if ($roles !== null) {
            $pins->rolePolicies();
        }

        [$own, $throughRoles] = self::attached($grants, $roles, $pins->isRouting());

        $held      = $roles !== null && $throughRoles ? self::heldOf($roles, $pins) : null;
        $inherited = $roles !== null && $held !== null ? RolePolicies::heldThrough($held, $roles, $pins) : new InheritedPolicies;

        // Flipping the keys and back lists each policy once, in the order it
        // was first reached.
        $keys = \array_keys(\array_flip([...\array_column($own, 'policy_id'), ...$inherited->keys]));

        $pins->policies($keys);

        /** @var array<string, \SineMacula\Laravel\Authorization\Models\Policy> $fresh */
        $fresh    = $keys === [] ? [] : $grants->getRelated()->newQuery()->useWritePdo()->whereKey($keys)->get()->getDictionary();
        $policies = [];

        foreach (self::inOrder($keys, $fresh) as $policy) {
            $policies[] = self::hydrate($policy);
        }

        $routes = $pins->isRouting() ? RouteSources::policies($grants->getParent(), $own, $held, $inherited) : null;

        return new Resolution($policies, GrantExpiry::nearest($inherited->expiresIn, \array_column($own, 'expires_at')), $inherited->stable, $routes);
    }

    /**
     * Hydrate one policy for evaluation, writing a document that cannot be read
     * to the log channel before its exception is thrown. The resource policy
     * resolver hydrates through here too.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    public static function hydrate(Policy $policy): \SineMacula\Laravel\Authorization\Evaluation\Policy
    {
        try {
            return PolicyDocument::hydrate($policy);
        } catch (InvalidPolicyDocumentException $exception) {
            AuthorizationLog::warning(
                "Authorization: malformed policy '{$policy->id}' denies every check for its holder: " . $exception->getMessage(),
                [
                    'policy_id'   => $policy->id,
                    'policy_name' => $policy->name,
                    'reason'      => $exception->getMessage(),
                ],
            );

            throw $exception;
        }
    }

    /**
     * Return the held roles read afresh, with their hierarchy as it is now, for
     * a resolution whose hierarchy moved while it ran.
     *
     * @param  RoleGrants  $roles
     * @param  list<string>  $keys
     * @return list<\SineMacula\Laravel\Authorization\Models\Role>
     */
    private static function rolesAfresh(MorphToMany $roles, array $keys): array
    {
        /** @var list<\SineMacula\Laravel\Authorization\Models\Role> */
        return $roles->getRelated()->newQuery()->useWritePdo()->whereKey($keys)->get()->all();
    }

    /**
     * Read the grantee's own attachments of policies, each with its expiry, on
     * the write connection, and, given the relation onto its roles, whether any
     * role holds a policy in the current scope, in the same query. An
     * attachment of an inline policy that belongs to another grantee is left
     * out. While grant usage is tracked, each is read with where it was made
     * and its creation too.
     *
     * @param  PolicyGrants  $grants
     * @param  RoleGrants|null  $roles
     * @param  bool  $isRouting
     * @return array{0: array<int, array{policy_id: string, authorizable_type: string, expires_at: string|null}>, 1: bool}
     */
    private static function attached(MorphToMany $grants, ?MorphToMany $roles, bool $isRouting = false): array
    {
        $columns = $isRouting ? ['policy_id', 'authorizable_type', 'expires_at', ...RouteSources::SCOPE, 'created_at'] : ['policy_id', 'authorizable_type', 'expires_at'];
        $query   = InlinePolicies::attachedToTheirGrantee((clone $grants->getQuery())->toBase(), $grants->getTable())
            ->select(\array_map($grants->qualifyPivotColumn(...), $columns));

        if ($roles !== null) {
            $query->unionAll(RolePolicies::probe($roles, $columns));
        }

        /** @var list<array{policy_id: string, authorizable_type: string, expires_at: string|null}> $rows */
        $rows = $query->useWritePdo()->get()->map(static fn (object $row): array => (array) $row)->all();
        $role = $roles?->getRelated()->getMorphClass();
        $own  = \array_filter($rows, static fn (array $row): bool => $row['authorizable_type'] !== $role);

        return [$own, \count($own) !== \count($rows)];
    }

    /**
     * Read the grants of the relation, with their expiry, on the write
     * connection.
     *
     * @template TGranted of \Illuminate\Database\Eloquent\Model
     *
     * @param  \Illuminate\Database\Eloquent\Relations\MorphToMany<TGranted, *, *>  $grants
     * @return \Illuminate\Database\Eloquent\Collection<int, TGranted>
     */
    private static function held(MorphToMany $grants): EloquentCollection
    {
        $grants->getQuery()->useWritePdo();

        return $grants->get();
    }

    /**
     * Read the grants of the relation as `held()` reads them, with where each
     * was made when the resolution keeps the routes behind what it finds.
     *
     * @template TGranted of \Illuminate\Database\Eloquent\Model
     *
     * @param  \Illuminate\Database\Eloquent\Relations\MorphToMany<TGranted, covariant \Illuminate\Database\Eloquent\Model, *>  $grants
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionPins  $pins
     * @return \Illuminate\Database\Eloquent\Collection<int, TGranted>
     */
    private static function heldOf(MorphToMany $grants, ResolutionPins $pins): EloquentCollection
    {
        return self::held($pins->isRouting() ? RouteSources::scoped($grants) : $grants);
    }

    /**
     * Return the values for the keys that have one, in the order of the keys,
     * so a resolution lists records in the order they were granted and leaves
     * out any deleted, or hidden by the tenant scope, since.
     *
     * @template TValue
     *
     * @param  list<string>  $keys
     * @param  array<string, TValue>  $values
     * @return list<TValue>
     */
    private static function inOrder(array $keys, array $values): array
    {
        $ordered = [];

        foreach ($keys as $key) {
            if (!\array_key_exists($key, $values)) {
                continue;
            }

            $ordered[] = $values[$key];
        }

        return $ordered;
    }

    /**
     * Return the seconds until the nearest of the grants expires, starting from
     * an expiry already known, or null when none of them expires.
     *
     * @param  int|null  $nearest
     * @param  \Illuminate\Database\Eloquent\Collection<int, covariant \Illuminate\Database\Eloquent\Model>  ...$grants
     * @return int|null
     */
    private static function expiresIn(?int $nearest, EloquentCollection ...$grants): ?int
    {
        $now = Carbon::now()->getTimestamp();

        foreach ($grants as $models) {
            foreach ($models as $model) {
                $expiresAt = UtcDateTime::toUtc(self::pivot($model)->getAttribute('expires_at'));

                if ($expiresAt === null) {
                    continue;
                }

                $nearest = \min($nearest ?? \PHP_INT_MAX, $expiresAt->getTimestamp() - $now);
            }
        }

        return $nearest;
    }

    /**
     * Return the grant row a related model was read through.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return \Illuminate\Database\Eloquent\Model
     */
    private static function pivot(Model $model): Model
    {
        /** @var \Illuminate\Database\Eloquent\Model */
        return $model->getRelation('pivot');
    }
}
