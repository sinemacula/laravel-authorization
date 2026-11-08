<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use SineMacula\Laravel\Authorization\Concerns\HasPermissions;
use SineMacula\Laravel\Authorization\Concerns\HasPolicies;
use SineMacula\Laravel\Authorization\Contracts\SupportsPermissions;
use SineMacula\Laravel\Authorization\Contracts\SupportsPolicies;
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

/**
 * Resolves, for an explained check (N89), what a grantee's grants come to
 * together with where each came from: the permissions it holds and the policies
 * attached to it, each with the grant row that gave it, the roles it came
 * through, the role held and then each ancestor up to the role that carries it,
 * and the tenant and application the grant was made in.
 *
 * It reads what `GrantResolver` reads, in the scope in place and on the write
 * connection, in no more queries than a resolution of the names takes, from the
 * same rows, so the permissions and policies are the ones an everyday check
 * resolves, and the check's verdict the same; it is never cached, since an
 * everyday check never asks for it. Only a grantee whose grants the package's
 * own traits resolve can say where a grant came from: one whose
 * `getPermissions()` or `getPolicies()` is its own, or a policy store, is asked
 * as an everyday check asks it, and each of its grants recorded as
 * `unavailable`, never guessed.
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
     * where each came from with the recorder.
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

        $policies = self::policiesOf($identity, $recorder, true);

        return SubjectGrants::grantingIdentity($subject) === null ? SubjectGrants::denialsOf($policies) : $policies;
    }

    /**
     * Return the permission the grantee holds that matches the action, with
     * where each grant of it came from, or, for a grantee the package does not
     * resolve, the one its `getPermissions()` gives, its provenance
     * unavailable.
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

        $sources = self::permissionSources($grantee, $isIdentity);
        $held    = HeldPermissions::match(\array_map(\strval(...), \array_keys($sources)), $action);

        return [$held, $held === null ? [] : $sources[$held]];
    }

    /**
     * Return the names of the permissions the grantee holds, as
     * `GrantResolver::permissions()` resolves them, each with where every grant
     * of it came from: a direct grant, or a role held, through each ancestor up
     * to the role that carries it.
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

        $held = RolePolicies::heldBy($grantee);

        /** @var list<\SineMacula\Laravel\Authorization\Models\Role> $roles */
        $roles   = $held === null ? [] : self::held($held)->all();
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
     * Return the policies attached to the grantee, as
     * `GrantResolver::policies()` resolves them, hydrated, with where each came
     * from, by its key: an attachment to the grantee, or to a role held,
     * through each ancestor up to the role it is attached to. The roles are
     * read only when the query that reads the grantee's own attachments finds a
     * role holding a policy in the current scope.
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
        $grants    = $grantee->policies(); // @phpstan-ignore method.notFound
        $roles     = RolePolicies::heldBy($grantee);
        $reference = self::referenceTo($grantee);
        $columns   = ['policy_id', 'authorizable_type', ...self::SCOPE];
        $query     = InlinePolicies::attachedToTheirGrantee((clone $grants->getQuery())->toBase(), $grants->getTable())
            ->select(\array_map($grants->qualifyPivotColumn(...), $columns));

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

            $provenance[$row['policy_id']][] = self::rowProvenance($row, $reference, $isIdentity);
        }

        if ($roles !== null && self::hasRoleRow($rows, $type)) {
            $provenance = self::rolePolicies($roles, $reference, $isIdentity, $provenance);
        }

        return [self::hydrated($grants, \array_map(\strval(...), \array_keys($provenance))), $provenance];
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
     * @param  \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Role, \Illuminate\Database\Eloquent\Model>  $roles
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $reference
     * @param  bool  $isIdentity
     * @param  array<string, list<\SineMacula\Laravel\Authorization\Evaluation\GrantProvenance>>  $provenance
     * @return array<string, list<\SineMacula\Laravel\Authorization\Evaluation\GrantProvenance>>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private static function rolePolicies(MorphToMany $roles, ?Reference $reference, bool $isIdentity, array $provenance): array
    {
        /** @var list<\SineMacula\Laravel\Authorization\Models\Role> $held */
        $held     = self::held($roles)->all();
        $paths    = RoleGraph::pathsOf($held);
        $attached = [];

        foreach (RolePolicies::attachedTo($roles->getRelated()->getMorphClass(), self::keysOf($paths)) as $row) {
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
     * once, in the order of the keys; a policy whose document cannot be read
     * throws, as `GrantResolver::hydrate()` does.
     *
     * @param  \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Policy, \Illuminate\Database\Eloquent\Model>  $grants
     * @param  list<string>  $keys
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    private static function hydrated(MorphToMany $grants, array $keys): array
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

            $policies[] = GrantResolver::hydrate($fresh[$key]);
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
     * tenant and application of the grant row it was read through.
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

        return new GrantProvenance($source, $grant, $grantee, $isIdentity, $roles, true, Reference::tenantOf($pivot), \is_string($application) ? $application : null);
    }

    /**
     * Return the grants of the relation, with where each was made, read on the
     * write connection.
     *
     * @param  \Illuminate\Database\Eloquent\Relations\MorphToMany<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>  $grants
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
