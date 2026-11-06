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
use SineMacula\Laravel\Authorization\Support\InheritedPermissions;
use SineMacula\Laravel\Authorization\Support\PolicyDocument;
use SineMacula\Laravel\Authorization\Support\RoleGraph;

/**
 * Resolves what an identity's grants come to: the names of its roles, the names
 * of its permissions, and its policies.
 *
 * Every read is on the write connection, so a read replica that has not caught
 * up never serves a grant already revoked. Each resolution pins the version of
 * a role or policy before it reads that record, so the resolution cache never
 * stores a value under versions newer than the data it was built from (the
 * cache pins the grantee before the resolution starts). A resolution whose role
 * hierarchy moved while it ran is returned but marked unstable, and is not
 * stored.
 *
 * Each kind takes a fixed number of queries: two for roles, two for policies,
 * and five for permissions however many roles the identity holds and however
 * deep they sit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class GrantResolver
{
    /**
     * Resolve the names of the roles granted through the relation.
     *
     * @param  \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Role, \Illuminate\Database\Eloquent\Model>  $grants
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
     * Resolve the names of the permissions granted directly and through the
     * roles, with each role's ancestors' when the hierarchy is enabled.
     *
     * @param  \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Permission, \Illuminate\Database\Eloquent\Model>  $direct
     * @param  \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Role, \Illuminate\Database\Eloquent\Model>  $roles
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionPins  $pins
     * @return \SineMacula\Laravel\Authorization\Cache\Resolution<string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public static function permissions(MorphToMany $direct, MorphToMany $roles, ResolutionPins $pins): Resolution
    {
        $granted = self::held($direct);
        $held    = self::held($roles);
        $keys    = \array_keys($held->getDictionary());
        $reach   = RoleGraph::reach($keys);

        $pins->roles(\array_keys($reach));

        $within    = RoleGraph::permissionsWithin($reach, $keys);
        $inherited = $within ?? self::inheritedAfresh($roles, $keys);

        /** @var list<string> $names */
        $names = $granted->pluck('name')->all();

        return new Resolution(
            \array_values(\array_unique([...$names, ...$inherited->names])),
            self::expiresIn($inherited->expiresIn, $granted, $held),
            $within !== null,
        );
    }

    /**
     * Resolve the policies attached through the relation, hydrated for
     * evaluation.
     *
     * A policy whose document cannot be read is written to the log channel and
     * its exception thrown, so it denies every check for its holder rather than
     * being skipped.
     *
     * @param  \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Policy, \Illuminate\Database\Eloquent\Model>  $grants
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionPins  $pins
     * @return \SineMacula\Laravel\Authorization\Cache\Resolution<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    public static function policies(MorphToMany $grants, ResolutionPins $pins): Resolution
    {
        $held = self::held($grants);
        $keys = \array_keys($held->getDictionary());

        $pins->policies($keys);

        /** @var array<string, \SineMacula\Laravel\Authorization\Models\Policy> $fresh */
        $fresh    = $keys === [] ? [] : $grants->getRelated()->newQuery()->useWritePdo()->whereKey($keys)->get()->getDictionary();
        $policies = [];

        foreach (self::inOrder($keys, $fresh) as $policy) {
            $policies[] = self::hydrate($policy);
        }

        return new Resolution($policies, self::expiresIn(null, $held));
    }

    /**
     * Return the permissions the held roles hold, reading the roles and their
     * hierarchy afresh, for a resolution whose hierarchy moved while it ran.
     *
     * @param  \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Role, \Illuminate\Database\Eloquent\Model>  $roles
     * @param  list<string>  $keys
     * @return \SineMacula\Laravel\Authorization\Support\InheritedPermissions
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private static function inheritedAfresh(MorphToMany $roles, array $keys): InheritedPermissions
    {
        /** @var list<\SineMacula\Laravel\Authorization\Models\Role> $fresh */
        $fresh = $roles->getRelated()->newQuery()->useWritePdo()->whereKey($keys)->get()->all();

        return RoleGraph::permissionsHeldBy($fresh);
    }

    /**
     * Read the grants of the relation, with their expiry, on the write
     * connection.
     *
     * @param  \Illuminate\Database\Eloquent\Relations\MorphToMany<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>  $grants
     * @return \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model>
     */
    private static function held(MorphToMany $grants): EloquentCollection
    {
        /** @var \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model> */
        return $grants->useWritePdo()->get(); // @phpstan-ignore method.notFound
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
     * Hydrate one policy for evaluation, writing a document that cannot be read
     * to the log channel before its exception is thrown.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    private static function hydrate(Policy $policy): \SineMacula\Laravel\Authorization\Evaluation\Policy
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
     * Return the seconds until the nearest of the grants expires, starting from
     * an expiry already known, or null when none of them expires.
     *
     * @param  int|null  $nearest
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model>  ...$grants
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
