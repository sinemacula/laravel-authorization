<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Concerns\HasPermissions;
use SineMacula\Laravel\Authorization\Concerns\HasPolicies;
use SineMacula\Laravel\Authorization\Contracts\SupportsPermissions;
use SineMacula\Laravel\Authorization\Contracts\SupportsPolicies;
use SineMacula\Laravel\Authorization\Database\BreakGlassActivations;
use SineMacula\Laravel\Authorization\Evaluation\Enums\GrantSource;
use SineMacula\Laravel\Authorization\Evaluation\EvidenceRecorder;
use SineMacula\Laravel\Authorization\Evaluation\GrantProvenance;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\HeldPermissions;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\RoleGraph;
use SineMacula\Laravel\Authorization\Support\RolePolicies;
use SineMacula\Laravel\Authorization\Support\SubjectGrants;
use SineMacula\Laravel\Authorization\Support\TenantColumns;

/**
 * Resolves, for an explained check (N89), what a grantee's grants come to
 * together with where each came from: the permissions it holds and the policies
 * attached to it, each with the grant row that gave it, the roles it came
 * through, the role held and then each ancestor up to the role that carries it,
 * and the tenant and application the grant was made in.
 *
 * The check decides from what an everyday check decides from: the grantee's
 * resolution in the resolution cache when the cache holds it. Where each grant
 * came from is read afresh, from the rows `GrantResolver` reads, in the scope
 * in place and on the write connection, in no more queries than a resolution of
 * the names takes; on a cold cache the check decides from those same rows, as a
 * resolution would, and nothing is kept in the cache. A grant is told apart
 * only by what decided: the permission held is named by its grants among the
 * rows read, and each policy by its attachments, so a grant the cache still
 * holds that the rows no longer give, a stale entry say, is recorded as
 * `unavailable`, never guessed.
 *
 * A role held through a break-glass activation is named as such, with the
 * activation's key, never its note (see `GrantSource::BREAK_GLASS_PERMISSION`
 * and `BREAK_GLASS_POLICY`).
 *
 * Only a grantee whose grants the package's own traits resolve can say where a
 * grant came from: one whose `getPermissions()` or `getPolicies()` is its own,
 * or a policy store, is asked as an everyday check asks it, and each of its
 * grants recorded as `unavailable`.
 *
 * @phpstan-import-type PolicyGrants from \SineMacula\Laravel\Authorization\Resolvers\GrantResolver
 * @phpstan-import-type RoleGrants from \SineMacula\Laravel\Authorization\Resolvers\GrantResolver
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class GrantProvenanceResolver
{
    /** @var list<string> The grant row columns that say where a grant was made. */
    private const array SCOPE = ['tenant_type', 'tenant_id', 'application'];

    /**
     * Return the permission the subject, or its identity when it grants to the
     * subject, holds that matches the action, as
     * `SubjectGrants::permissionFor()` answers it, with where each grant of it
     * came from; no permission while either is inactive.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $action
     * @return array{string|null, list<\SineMacula\Laravel\Authorization\Evaluation\GrantProvenance>}
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public static function permissionFor(Subject $subject, string $action): array
    {
        if (SubjectGrants::isInactive($subject)) {
            return [null, []];
        }

        foreach ([[$subject->subject, false], [SubjectGrants::grantingIdentity($subject), true]] as [$grantee, $isIdentity]) {
            [$held, $grants] = $grantee instanceof SupportsPermissions ? self::heldBy($grantee, $action, $isIdentity) : [null, []];

            if ($held !== null) {
                return [$held, $grants];
            }
        }

        return [null, []];
    }

    /**
     * Return the policies attached to the grantee, as its `getPolicies()`
     * resolves them, noting where each came from with the recorder.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\SupportsPolicies  $grantee
     * @param  \SineMacula\Laravel\Authorization\Evaluation\EvidenceRecorder  $recorder
     * @param  bool  $isIdentity
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public static function policiesOf(SupportsPolicies $grantee, EvidenceRecorder $recorder, bool $isIdentity = false): array
    {
        if (!$grantee instanceof Model || !self::isResolvedByPackage($grantee, 'getPolicies', HasPolicies::class)) {
            $policies = $grantee->getPolicies();

            $recorder->notePolicies($policies, null, $grantee, $isIdentity);

            return $policies;
        }

        [$policies, $provenance] = self::attachedPolicies($grantee, $isIdentity);

        $recorder->notePolicies($policies, $provenance, $grantee, $isIdentity);

        return $policies;
    }

    /**
     * Return the policies attached to the subject's identity when that is
     * another model, as `SubjectGrants::identityPolicies()` gives them, noting
     * where each came from with the recorder when the identity grants to the
     * subject. An identity of the other kind gives its deny statements alone,
     * which never allow a check, so none of its policies is noted, and they are
     * resolved as an everyday check resolves them.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \SineMacula\Laravel\Authorization\Evaluation\EvidenceRecorder  $recorder
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public static function identityPolicies(Subject $subject, EvidenceRecorder $recorder): array
    {
        $identity = $subject->identity === $subject->subject ? null : $subject->identity;

        if (!$identity instanceof SupportsPolicies) {
            return [];
        }

        return SubjectGrants::grantingIdentity($subject) === null
            ? SubjectGrants::denialsOf($identity->getPolicies())
            : self::policiesOf($identity, $recorder, true);
    }

    /**
     * Return the permission the grantee holds that matches the action, as an
     * everyday check finds it, with where each grant of it came from among the
     * rows read afresh, or `unavailable` when they give none; for a grantee the
     * package does not resolve, the one its `getPermissions()` gives, its
     * provenance unavailable.
     *
     * The rows are read once: on a cold cache the names come from them, and on
     * a warm one they are read only once a permission is found held.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\SupportsPermissions  $grantee
     * @param  string  $action
     * @param  bool  $isIdentity
     * @return array{string|null, list<\SineMacula\Laravel\Authorization\Evaluation\GrantProvenance>}
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private static function heldBy(SupportsPermissions $grantee, string $action, bool $isIdentity): array
    {
        if (!$grantee instanceof Model || !self::isResolvedByPackage($grantee, 'getPermissions', HasPermissions::class)) {
            $held = HeldPermissions::match($grantee->getPermissions(), $action);

            return [$held, $held === null ? [] : [GrantProvenance::unavailable($held, self::referenceTo($grantee), $isIdentity)]];
        }

        $sources = null;
        $resolve = static function () use ($grantee, $isIdentity, &$sources): Resolution {
            $sources = self::permissionSources($grantee, $isIdentity);

            return self::unkept(\array_map(\strval(...), \array_keys($sources)), self::activationsOf($sources));
        };

        $held = HeldPermissions::match(ResolutionCache::instance()?->rememberPermissions($grantee, $resolve) ?? $resolve()->value, $action);

        if ($held !== null) {
            $sources ??= self::permissionSources($grantee, $isIdentity);
        }

        return [$held, $held === null ? [] : $sources[$held] ?? [GrantProvenance::unavailable($held, self::referenceTo($grantee), $isIdentity)]];
    }

    /**
     * Return the names of the permissions the grantee holds, as
     * `GrantResolver::permissions()` resolves them, through the grantee's own
     * `roles()` as the trait reads them, each with where every grant of it came
     * from: a direct grant, or a role held, through each ancestor up to the
     * role that carries it.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $grantee
     * @param  bool  $isIdentity
     * @return array<string, list<\SineMacula\Laravel\Authorization\Evaluation\GrantProvenance>>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private static function permissionSources(Model $grantee, bool $isIdentity): array
    {
        $reference = self::referenceTo($grantee);
        $sources   = [];

        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Permission> $direct */
        $direct = self::held($grantee->permissions()); // @phpstan-ignore method.notFound

        foreach ($direct as $permission) {
            $sources[$permission->name][] = self::provenance(GrantSource::PERMISSION, $permission->name, $reference, $isIdentity, [], $permission);
        }

        /** @var list<\SineMacula\Laravel\Authorization\Models\Role> $roles */
        $roles   = self::held($grantee->roles())->all(); // @phpstan-ignore method.notFound
        $paths   = RoleGraph::pathsOf($roles);
        $carried = RoleGraph::permissionsByRole(self::keysOf($paths));

        foreach ($roles as $role) {
            $through = [];

            foreach ($paths[$role->id] ?? [] as $step) {
                $through[] = $step->name;

                foreach ($carried[$step->id] ?? [] as $name) {
                    $sources[$name][] = self::provenance(GrantSource::ROLE_PERMISSION, $name, $reference, $isIdentity, $through, $role);
                }
            }
        }

        return $sources;
    }

    /**
     * Return the policies attached to the grantee, as an everyday check
     * resolves them, with where each came from among the attachments read
     * afresh, by its key. On a cold cache the policies are hydrated from those
     * attachments, as `GrantResolver::policies()` reads them, and on a warm one
     * the attachments are read only when the grantee has a policy.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $grantee
     * @param  bool  $isIdentity
     * @return array{list<\SineMacula\Laravel\Authorization\Evaluation\Policy>, array<string, list<\SineMacula\Laravel\Authorization\Evaluation\GrantProvenance>>}
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private static function attachedPolicies(Model $grantee, bool $isIdentity): array
    {
        /** @var \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Policy, \Illuminate\Database\Eloquent\Model> $grants */
        $grants     = $grantee->policies(); // @phpstan-ignore method.notFound
        $provenance = null;
        $resolve    = static function () use ($grantee, $grants, $isIdentity, &$provenance): Resolution {
            $whole      = [];
            $provenance = self::policyProvenance($grantee, $grants, $isIdentity, $whole);

            return self::unkept(self::hydrated($grants, \array_map(\strval(...), \array_keys($provenance)), $whole), self::activationsOf($provenance));
        };

        $policies = ResolutionCache::instance()?->rememberPolicies($grantee, $resolve) ?? $resolve()->value;

        return [$policies, $policies === [] ? [] : $provenance ?? self::policyProvenance($grantee, $grants, $isIdentity)];
    }

    /**
     * Return where each policy attached to the grantee came from, by its key,
     * from the attachments `GrantResolver::policies()` reads: an attachment to
     * the grantee, or to a role held, through each ancestor up to the role it
     * is attached to. The roles are read only when the query that reads the
     * grantee's own attachments finds a role holding a policy in the current
     * scope. The attachments whose denies alone count in every scope are read
     * too (see `GrantResolver::deniedEverywhere()`), and the key of each policy
     * reached through one whose allows count is kept in the given array. An
     * attachment naming half a tenant, whose denies alone count, is never where
     * an allow came from, so it adds its policy's key with no provenance, and
     * is never reported as the platform's.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $grantee
     * @param  PolicyGrants  $grants
     * @param  bool  $isIdentity
     * @param  array<string, bool>  $whole
     * @return array<string, list<\SineMacula\Laravel\Authorization\Evaluation\GrantProvenance>>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private static function policyProvenance(Model $grantee, MorphToMany $grants, bool $isIdentity, array &$whole = []): array
    {
        $roles     = RolePolicies::heldBy($grantee);
        $reference = self::referenceTo($grantee);
        $columns   = ['policy_id', 'authorizable_type', ...self::SCOPE];
        $query     = InlinePolicies::attachedToTheirGrantee((clone $grants->getQuery())->toBase(), $grants->getTable())
            ->select(\array_map($grants->qualifyPivotColumn(...), $columns))
            ->unionAll(GrantResolver::deniedEverywhere($grants, $columns));

        if ($roles !== null) {
            $query->unionAll(RolePolicies::probe($roles, $columns));
        }

        /** @var list<array{policy_id: string, authorizable_type: string, tenant_type: string|null, tenant_id: string|null, application: string|null}> $rows */
        $rows       = $query->useWritePdo()->get()->map(static fn (object $row): array => (array) $row)->all();
        $type       = $roles?->getRelated()->getMorphClass();
        $provenance = [];

        foreach ($rows as $row) {
            if ($row['authorizable_type'] === $type) {
                continue;
            }

            $isWhole                  = !TenantColumns::isHalf($row['tenant_type'], $row['tenant_id']);
            $whole[$row['policy_id']] = ($whole[$row['policy_id']] ?? false) || $isWhole;
            $provenance[$row['policy_id']] ??= [];

            // A row naming half a tenant only denies, so it is never where an
            // allow came from, nor reported as the platform's.
            if (!$isWhole) {
                continue;
            }

            $provenance[$row['policy_id']][] = self::rowProvenance($row, $reference, $isIdentity);
        }

        return $roles !== null && self::hasRoleRow($rows, $type) ? self::rolePolicies($roles, $reference, $isIdentity, $provenance, $whole) : $provenance;
    }

    /**
     * Determine whether the rows the grantee's attachments were read with hold
     * the probe's row, which says a role holds a policy in the current scope.
     *
     * @param  list<array{policy_id: string, authorizable_type: string, tenant_type: string|null, tenant_id: string|null, application: string|null}>  $rows
     * @param  string|null  $type
     * @return bool
     */
    private static function hasRoleRow(array $rows, ?string $type): bool
    {
        foreach ($rows as $row) {
            if ($row['authorizable_type'] === $type) {
                return true;
            }
        }

        return false;
    }

    /**
     * Add, to where each policy came from, the policies attached to the roles
     * the grantee holds and to their ancestors, each through the path from the
     * role held to the role it is attached to.
     *
     * @param  RoleGrants  $roles
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $reference
     * @param  bool  $isIdentity
     * @param  array<string, list<\SineMacula\Laravel\Authorization\Evaluation\GrantProvenance>>  $provenance
     * @param  array<string, bool>  $whole
     * @return array<string, list<\SineMacula\Laravel\Authorization\Evaluation\GrantProvenance>>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private static function rolePolicies(MorphToMany $roles, ?Reference $reference, bool $isIdentity, array $provenance, array &$whole): array
    {
        /** @var list<\SineMacula\Laravel\Authorization\Models\Role> $held */
        $held     = self::held($roles)->all();
        $paths    = RoleGraph::pathsOf($held);
        $attached = [];

        foreach (RolePolicies::attachedTo($roles->getRelated()->getMorphClass(), self::keysOf($paths)) as $row) {
            $whole[$row['policy_id']] = ($whole[$row['policy_id']] ?? false) || $row['is_whole'];
            $provenance[$row['policy_id']] ??= [];

            // An attachment naming half a tenant only denies, so no route
            // through it is where an allow came from.
            if (!$row['is_whole']) {
                continue;
            }

            $attached[$row['role_id']][] = $row['policy_id'];
        }

        foreach ($held as $role) {
            $through = [];

            foreach ($paths[$role->id] ?? [] as $step) {
                $through[] = $step->name;

                foreach ($attached[$step->id] ?? [] as $policy) {
                    $provenance[$policy][] = self::provenance(GrantSource::ROLE_POLICY, $policy, $reference, $isIdentity, $through, $role);
                }
            }
        }

        return $provenance;
    }

    /**
     * Return the policies with the given keys, hydrated for evaluation, each
     * once, in the order of the keys, with its denies alone unless it was
     * reached through an attachment whose allows count and names no half tenant
     * itself, as `GrantResolver::policies()` hydrates them; a policy whose
     * document cannot be read throws, as `GrantResolver::hydrate()` does.
     *
     * @param  PolicyGrants  $grants
     * @param  list<string>  $keys
     * @param  array<string, bool>  $whole
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    private static function hydrated(MorphToMany $grants, array $keys, array $whole): array
    {
        if ($keys === []) {
            return [];
        }

        /** @var array<string, \SineMacula\Laravel\Authorization\Models\Policy> $fresh */
        $fresh    = $grants->getRelated()->newQuery()->useWritePdo()->whereKey($keys)->get()->getDictionary();
        $policies = [];

        foreach ($keys as $key) {
            if (!isset($fresh[$key])) {
                continue;
            }

            $policy     = GrantResolver::hydrate($fresh[$key]);
            $policies[] = ($whole[$key] ?? false) && !TenantColumns::isDenyOnly(null, null, $fresh[$key]) ? $policy : $policy->denies();
        }

        return $policies;
    }

    /**
     * Return the provenance of a grant read from the row of the grantee's own
     * attachment of a policy.
     *
     * @param  array{policy_id: string, authorizable_type: string, tenant_type: string|null, tenant_id: string|null, application: string|null}  $row
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $reference
     * @param  bool  $isIdentity
     * @return \SineMacula\Laravel\Authorization\Evaluation\GrantProvenance
     */
    private static function rowProvenance(array $row, ?Reference $reference, bool $isIdentity): GrantProvenance
    {
        $tenant = $row['tenant_type'] !== null && $row['tenant_id'] !== null ? new Reference($row['tenant_type'], $row['tenant_id']) : null;

        return new GrantProvenance(GrantSource::POLICY, $row['policy_id'], $reference, $isIdentity, [], true, $tenant, $row['application']);
    }

    /**
     * Return the provenance of a grant read through a related model, with the
     * tenant and application of the grant row it was read through, and, for a
     * role read through a break-glass activation, the route named as one with
     * the activation's key.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\GrantSource  $source
     * @param  string  $grant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $grantee
     * @param  bool  $isIdentity
     * @param  list<string>  $roles
     * @param  \Illuminate\Database\Eloquent\Model  $granted
     * @return \SineMacula\Laravel\Authorization\Evaluation\GrantProvenance
     */
    private static function provenance(GrantSource $source, string $grant, ?Reference $grantee, bool $isIdentity, array $roles, Model $granted): GrantProvenance
    {
        /** @var \Illuminate\Database\Eloquent\Model $pivot */
        $pivot       = $granted->getRelation('pivot');
        $application = $pivot->getAttribute('application');
        $activation  = BreakGlassActivations::activationOf($granted);
        $route       = match (true) {
            $activation === null                     => $source,
            $source     === GrantSource::ROLE_POLICY => GrantSource::BREAK_GLASS_POLICY,
            default                                  => GrantSource::BREAK_GLASS_PERMISSION,
        };

        return new GrantProvenance($route, $grant, $grantee, $isIdentity, $roles, true, Reference::tenantOf($pivot), \is_string($application) ? $application : null, $activation);
    }

    /**
     * Return the grants of the relation, with where each was made, read on the
     * write connection.
     *
     * @param  \Illuminate\Database\Eloquent\Relations\MorphToMany<covariant \Illuminate\Database\Eloquent\Model, *, *>  $grants
     * @return \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model>
     */
    private static function held(MorphToMany $grants): EloquentCollection
    {
        /** @var \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model> */
        return $grants->withPivot(self::SCOPE)->useWritePdo()->get(); // @phpstan-ignore method.notFound
    }

    /**
     * Return the key of every role on the paths, each once.
     *
     * @param  array<string, list<\SineMacula\Laravel\Authorization\Models\Role>>  $paths
     * @return list<string>
     */
    private static function keysOf(array $paths): array
    {
        $keys = [];

        foreach ($paths as $path) {
            foreach ($path as $role) {
                $keys[$role->id] = $role->id;
            }
        }

        return \array_values($keys);
    }

    /**
     * Determine whether the package's trait resolves the grantee's grants of
     * the kind: the grantee uses it, and the method resolving them is the
     * trait's own, not one the model overrides.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $grantee
     * @param  string  $method
     * @param  class-string  $trait
     * @return bool
     */
    private static function isResolvedByPackage(Model $grantee, string $method, string $trait): bool
    {
        if (!\in_array($trait, \class_uses_recursive($grantee), true)) {
            return false;
        }

        return (new \ReflectionMethod($grantee, $method))->getFileName() === (new \ReflectionClass($trait))->getFileName();
    }

    /**
     * Return what an explained check read on a cold cache as a resolution the
     * cache keeps nowhere: unstable, so the store is never written, and lapsing
     * at once, so the memo never serves it, since the check read the rows for
     * where each grant came from rather than as a resolution reads them. The
     * activations behind each grant are kept with it, so the check names them.
     *
     * @template TValue
     *
     * @param  list<TValue>  $value
     * @param  array<string, list<string>>  $activations
     * @return \SineMacula\Laravel\Authorization\Cache\Resolution<TValue>
     */
    private static function unkept(array $value, array $activations): Resolution
    {
        return new Resolution($value, 0, false, null, $activations);
    }

    /**
     * Return the keys of the break-glass activations behind each grant, by its
     * name or key, from where each came from.
     *
     * @param  array<array-key, list<\SineMacula\Laravel\Authorization\Evaluation\GrantProvenance>>  $sources
     * @return array<string, list<string>>
     */
    private static function activationsOf(array $sources): array
    {
        $activations = [];

        foreach ($sources as $grant => $routes) {
            $activations[(string) $grant] = \array_values(\array_filter(\array_map(static fn (GrantProvenance $route): ?string => $route->activation, $routes), \is_string(...)));
        }

        return $activations;
    }

    /**
     * Return the reference to a grantee that is a saved model, or null.
     *
     * @param  object  $grantee
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    private static function referenceTo(object $grantee): ?Reference
    {
        return $grantee instanceof Model && $grantee->exists ? Reference::of($grantee) : null;
    }
}
