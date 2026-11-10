<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;
use SineMacula\Laravel\Authorization\Diagnostics\PackageState;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGranteeException;
use SineMacula\Laravel\Authorization\Hooks\ProposedGrant;
use SineMacula\Laravel\Authorization\Hooks\WideningPhase;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\Support\GrantChanges;
use SineMacula\Laravel\Authorization\Services\Support\GrantScopes;
use SineMacula\Laravel\Authorization\Services\Support\StoredRecords;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\RoleParity;

/**
 * Grants, revokes and syncs roles, permissions and policies to a grantee.
 *
 * Every call runs in one transaction on the package's connection, and reads the
 * role, permission and policy classes `authorization.models` configures. A role
 * or permission named by a string is looked up under the grantee's guard (its
 * `getAuthorizationGuard()`, when it declares one), else the package default.
 *
 * Every grant holds in a scope (AUTHZ-5.1): a role, permission or policy one
 * tenant owns is granted in that tenant, or a tenant below it that a call
 * names, and naming any other is refused with `GrantScopeMismatchException`;
 * one the platform owns is granted in the tenant a call names as `$tenant`,
 * else platform-wide. A name is looked up among the rows visible in the tenant
 * named, else in the current tenant. A revocation follows the same rule, and a
 * sync replaces the grants in one scope: the tenant named, else the tenant that
 * owns every target, else the platform. A grant holds in the application the
 * call names as `$application`, else in every application (AUTHZ-5.6, D24); a
 * revocation and a sync stay in it the same way.
 *
 * A grant in a tenant also holds in the tenants below it in the tenant tree
 * (AUTHZ-5.3), unless the call passes `$includeSubtree` false to limit it to
 * that tenant; a platform-wide grant counts everywhere whatever it is given.
 * Granting what the grantee holds, with the same expiry and another reach,
 * changes the reach and is reported as `REACH_CHANGED` with the granted event
 * (D21); a sync writes its reach only to what it grants or re-arms.
 *
 * Grants are idempotent: granting what the grantee holds, with the same expiry,
 * changes nothing and is reported as unchanged, and a concurrent duplicate
 * never surfaces a unique-constraint violation. Re-granting a grant that has
 * expired re-arms it with the new expiry, and a different expiry on a live
 * grant is reported as a change.
 *
 * The identity events (`RoleAssigned`, `PermissionGranted`, `PolicyAttached`,
 * their revoked and detached counterparts, and the expiry-changed events) are
 * dispatched once the write commits, on the package's connection, and only for
 * a write that changed something; a write that rolls back, alone or with an
 * enclosing transaction, dispatches nothing. A changed expiry dispatches the
 * granted event as well as the expiry-changed one.
 *
 * Each method takes the acting context making the call as `$actor`: null for
 * trusted system work, such as seeders, migrations and console commands (N75).
 * A call with an acting context is delegated administration (AUTHZ-11.1): each
 * change it makes is decided as the actor, through `check()`, on the change's
 * operation resource, inside the call's transaction before anything is written,
 * and the first refused throws the decision's `AuthorizationException`, leaving
 * nothing written and dispatching no change event. The actor's authority and
 * then the grantee's rows are locked before the call reads them (see
 * `Administration\DependencyPins`), so what is decided is what is written:
 * `revokeAll()` revokes exactly the rows it decided, never one granted
 * meanwhile, and a sync never writes back a row it decided as held that is gone
 * by the write; either is tried again instead. A grant is decided under
 * `authorization:role.grant`, `authorization:permission.grant` or
 * `authorization:policy.attach`, a regrant, a changed expiry and a changed
 * reach included, and a revocation under `authorization:role.revoke`,
 * `authorization:permission.revoke` or `authorization:policy.detach`, each in
 * the scope it is written in. A sync decides a grant of each listed row the
 * grantee does not hold live in its scope and a revocation of each it drops; a
 * row it holds live decides nothing. A revocation by name decides each held row
 * of that name; one by model decides that row whether it is held or not.
 * `revokeAll()` decides the revocation of every row and the removal of every
 * permission boundary (`authorization:boundary.remove`) the grantee has. There
 * is no blanket action. Each change is decided in the tenant of the row it
 * changes, so an actor whose authority for the action reaches that tenant, from
 * a parent over its subtree or from the platform, changes it from its own
 * context, and `revokeAll()` clears a grantee's rows across every tenant the
 * actor administers. Every change to an identity or a principal is then weighed
 * by the administration stage (see `OperationConstraints`): the actor must be
 * strictly senior to the grantee anywhere the change reaches
 * (`administration.rank`); one that may widen authority must be allowed across
 * its whole reach (`administration.scope`) and, made to the actor itself, also
 * allowed `authorization:administration.self` (`administration.self`). A change
 * that can only narrow (revoking a permission, a role no deny is attached to,
 * detaching an allow-only policy, or a grant that only shortens one held, see
 * `Narrowing`) is then allowed; a direct grant of a permission, a sync's
 * additions included, is allowed when the actor provably holds it across its
 * reach and lifetime, or may grant it explicitly (see `Possession`), and is
 * otherwise refused as `administration.not_grantable` or
 * `administration.unprovable`; a role grant hands out the role's whole
 * authority, every permission and policy it and its ancestors carry, and every
 * allow of a resource policy that names it or an ancestor, each by its own
 * route (see `RoleAuthority`), its rank counting as the grantee's; a policy
 * attachment, to an identity, a principal or a role, needs the policy route,
 * containment or `authorization:policy.grantable` on the policy's digest (see
 * `PolicyRoute`); a change to a role's policies is made only from the tenant
 * that owns the role, and weighed against every holder of the role (see
 * `DefinitionConstraints`); any other change that may widen authority, such as
 * detaching a denying policy, is refused as `administration.unprovable`. A
 * delegated call weighs each role, permission or policy it is handed as a model
 * on its row as stored (see `StoredRecords`), so a model with unsaved changes,
 * or one read before another write, is never judged on what its row does not
 * hold. Every event the call dispatches carries the operation, with the actor,
 * its mode and the actions, and every grant row it writes records the actor in
 * `granted_by_type` and `granted_by_id`; the actor is never read from the
 * authenticated user. A grantee that is not a saved model with a key, or a
 * reference with a type and a key, throws `InvalidGranteeException` before
 * anything is read. A role or permission name that answers no row throws
 * `UnknownRoleException` or `UnknownPermissionException`; a target that is not
 * a saved model of the kind granted, such as a policy sync handed another
 * model, throws `InvalidGrantTargetException`.
 *
 * Before a grant, a sync's additions and re-arms, an extension or a wider reach
 * that widens an identity's scope is written, trusted or delegated, the bound
 * grant hook is called with every widening grant of the call, before the
 * package takes any lock for it (AUTHZ-11.3, see `Hooks\WideningPhase`): it may
 * refuse by throwing, which rolls the call back, and the call is tried again
 * when a grant it writes widens with no hook run for it, as read again under
 * the lock once every decision is made, or, inside a transaction the
 * application opened, thrown as `TransactionConflictException`. A widening
 * grant made inside another management call's work is refused with
 * `NestedGrantException`, and one whose identity cannot be resolved with
 * `UnresolvableRecipientException`.
 *
 * A grantee is an identity or a role: a policy attached to a role applies to
 * whoever holds the role, within both grants' scopes, and to whoever holds a
 * role below it (AUTHZ-7.2). An inline policy is attached only to the grantee
 * it belongs to; attaching or syncing it to any other throws
 * `InlinePolicyAttachmentException` before anything is written (AUTHZ-6.9). A
 * policy whose statements name `principals` is refused for any grantee with
 * `ResourcePolicyException` (see `PolicyPrincipals`).
 *
 * Every operation refuses while the package is not healthy (see
 * `PackageState`), before it reads or writes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class GrantService
{
    use HasContainerInstance;

    /**
     * Grant a role to the grantee, until the given expiry or forever.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @param  string|null  $application
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    public function grantRole(
        Model|Reference $grantee,
        Role|string $role,
        ?\DateTimeInterface $expiresAt = null,
        ?ActingContext $actor = null,
        Model|Reference|null $tenant = null,
        bool $includeSubtree = true,
        ?string $application = null,
    ): GrantOutcome {
        PackageState::guardCurrent();

        return $this->grant(GrantTarget::ROLE, $grantee, $role, $expiresAt, $actor, self::named($tenant, $includeSubtree, $application));
    }

    /**
     * Revoke a role from the grantee, and return how many roles were revoked:
     * none when the grantee held none.
     *
     * A name revokes every held role of that name under the grantee's guard, or
     * guard-agnostic, whichever tenant or the platform owns it.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string|null  $application
     * @return int
     *
     * @throws \Throwable
     */
    public function revokeRole(Model|Reference $grantee, Role|string $role, ?ActingContext $actor = null, Model|Reference|null $tenant = null, ?string $application = null): int
    {
        PackageState::guardCurrent();

        return $this->revoke(GrantTarget::ROLE, $grantee, $role, $actor, $tenant, $application);
    }

    /**
     * Replace the grantee's roles with the given ones.
     *
     * A name keeps every held role of that name, and only when the grantee
     * holds none is the role the lookup ranks first granted. A role the sync
     * grants, or re-arms because it had expired, carries the given expiry; a
     * live role is left as it is.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Role|string>  $roles
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @param  string|null  $application
     * @return \SineMacula\Laravel\Authorization\Services\SyncResult
     *
     * @throws \Throwable
     */
    public function syncRoles(
        Model|Reference $grantee,
        array $roles,
        ?\DateTimeInterface $expiresAt = null,
        ?ActingContext $actor = null,
        Model|Reference|null $tenant = null,
        bool $includeSubtree = true,
        ?string $application = null,
    ): SyncResult {
        PackageState::guardCurrent();

        return $this->sync(GrantTarget::ROLE, $grantee, $roles, $expiresAt, $actor, self::named($tenant, $includeSubtree, $application));
    }

    /**
     * Grant a permission directly to the grantee, until the given expiry or
     * forever.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @param  string|null  $application
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    public function grantPermission(
        Model|Reference $grantee,
        Permission|string $permission,
        ?\DateTimeInterface $expiresAt = null,
        ?ActingContext $actor = null,
        Model|Reference|null $tenant = null,
        bool $includeSubtree = true,
        ?string $application = null,
    ): GrantOutcome {
        PackageState::guardCurrent();

        return $this->grant(GrantTarget::PERMISSION, $grantee, $permission, $expiresAt, $actor, self::named($tenant, $includeSubtree, $application));
    }

    /**
     * Revoke a direct permission from the grantee, and return how many
     * permissions were revoked: none when the grantee held none.
     *
     * A name revokes every held permission of that name under the grantee's
     * guard, or guard-agnostic, whichever tenant or the platform owns it.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string|null  $application
     * @return int
     *
     * @throws \Throwable
     */
    public function revokePermission(
        Model|Reference $grantee,
        Permission|string $permission,
        ?ActingContext $actor = null,
        Model|Reference|null $tenant = null,
        ?string $application = null,
    ): int {
        PackageState::guardCurrent();

        return $this->revoke(GrantTarget::PERMISSION, $grantee, $permission, $actor, $tenant, $application);
    }

    /**
     * Replace the grantee's direct permissions with the given ones, as
     * `syncRoles()` replaces its roles.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Permission|string>  $permissions
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @param  string|null  $application
     * @return \SineMacula\Laravel\Authorization\Services\SyncResult
     *
     * @throws \Throwable
     */
    public function syncPermissions(
        Model|Reference $grantee,
        array $permissions,
        ?\DateTimeInterface $expiresAt = null,
        ?ActingContext $actor = null,
        Model|Reference|null $tenant = null,
        bool $includeSubtree = true,
        ?string $application = null,
    ): SyncResult {
        PackageState::guardCurrent();

        return $this->sync(GrantTarget::PERMISSION, $grantee, $permissions, $expiresAt, $actor, self::named($tenant, $includeSubtree, $application));
    }

    /**
     * Attach a policy to the grantee, an identity or a role, until the given
     * expiry or forever. An inline policy is attached only to the grantee it
     * belongs to.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @param  string|null  $application
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    public function attachPolicy(
        Model|Reference $grantee,
        Policy $policy,
        ?\DateTimeInterface $expiresAt = null,
        ?ActingContext $actor = null,
        Model|Reference|null $tenant = null,
        bool $includeSubtree = true,
        ?string $application = null,
    ): GrantOutcome {
        PackageState::guardCurrent();

        return $this->grant(GrantTarget::POLICY, $grantee, $policy, $expiresAt, $actor, self::named($tenant, $includeSubtree, $application));
    }

    /**
     * Detach a policy from the grantee, and return how many were detached: none
     * when it was not attached.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string|null  $application
     * @return int
     *
     * @throws \Throwable
     */
    public function detachPolicy(Model|Reference $grantee, Policy $policy, ?ActingContext $actor = null, Model|Reference|null $tenant = null, ?string $application = null): int
    {
        PackageState::guardCurrent();

        return $this->revoke(GrantTarget::POLICY, $grantee, $policy, $actor, $tenant, $application);
    }

    /**
     * Replace the grantee's attached policies with the given ones, as
     * `syncRoles()` replaces its roles. Each entry must be a saved policy.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Policy>  $policies
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @param  string|null  $application
     * @return \SineMacula\Laravel\Authorization\Services\SyncResult
     *
     * @throws \Throwable
     */
    public function syncPolicies(
        Model|Reference $grantee,
        array $policies,
        ?\DateTimeInterface $expiresAt = null,
        ?ActingContext $actor = null,
        Model|Reference|null $tenant = null,
        bool $includeSubtree = true,
        ?string $application = null,
    ): SyncResult {
        PackageState::guardCurrent();

        return $this->sync(GrantTarget::POLICY, $grantee, $policies, $expiresAt, $actor, self::named($tenant, $includeSubtree, $application));
    }

    /**
     * Revoke every role, permission and policy the grantee holds, and remove
     * its permission boundaries, in one transaction and as one operation, each
     * decided for an acting context before any is written, dispatching a
     * revoked, detached or removed event for each, and return how many there
     * were. The `HasAuthorization` trait calls this once a grantee is deleted,
     * `RoleObserver` once a role is deleted, and the grant pruner for a grantee
     * that no longer exists. For an acting context and a grantee that holds
     * nothing, each of the call's actions is decided unchanged at platform
     * scope, so an actor that may not take them is refused either way.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return int
     *
     * @throws \Throwable
     */
    public function revokeAll(Model|Reference $grantee, ?ActingContext $actor = null): int
    {
        PackageState::guardCurrent();

        $reference = self::grantee($grantee);
        $actions   = [PackagePermissions::ROLE_REVOKE, PackagePermissions::PERMISSION_REVOKE, PackagePermissions::POLICY_DETACH, PackagePermissions::BOUNDARY_REMOVE];
        $operation = Operation::begin($actor, $actions);

        $revoked = OperationScope::run($operation, static function (Operation $operation) use ($actor, $reference): int {
            if ($actor === null) {
                $events = GrantChanges::revokeEverywhere($reference, $operation);
            } else {
                // The grantee's rows are locked before they are read, so what
                // is revoked is exactly what was decided, never a row granted
                // meanwhile in a tenant the actor does not administer.
                OperationScope::pins()?->lockGrantees($reference);

                $unchanged = static fn (string $action): OperationResource => OperationResource::unchanged($action, $reference, null, GrantScope::platform());
                $changes   = GrantChanges::everything($reference);

                $actor->authorizeChanges($operation, $changes, ...\array_map($unchanged, $operation->actions));

                $events = GrantChanges::revokeDecided($reference, $operation, $changes);
            }

            OperationScope::dispatch(...$events);

            return \count($events);
        }, $actor);

        foreach (GrantTarget::cases() as $kind) {
            self::forgetRelation($kind, $grantee);
        }

        return $revoked;
    }

    /**
     * Grant one row of the given kind in one transaction, in the scope its
     * owner fixes or the tenant named, else platform-wide.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  mixed  $target
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $named
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    private function grant(GrantTarget $kind, Model|Reference $grantee, mixed $target, ?\DateTimeInterface $expiresAt, ?ActingContext $actor, GrantScope $named): GrantOutcome
    {
        $reference = self::grantee($grantee);
        $begun     = Operation::begin($actor, [$kind->grantAction()]);

        /** @var \SineMacula\Laravel\Authorization\Enums\GrantOutcome $outcome */
        $outcome = OperationScope::run($begun, static function (Operation $operation) use ($actor, $kind, $grantee, $reference, $named, $target, $expiresAt, $begun): GrantOutcome {
            $resolve = static function () use ($kind, $grantee, $named, $target, $actor): array {
                $model = $kind->resolve($target, GrantChanges::guard($grantee), $named->tenant);
                $model = \is_string($target) ? $model : self::stored($kind, $model, $actor);

                return [$model, self::scope(GrantScopes::of($kind, $model, $named->tenant), $named->includeSubtree, $named->application)];
            };

            // A grant that widens the identity's scope runs its hooks first,
            // before the package takes any lock for the call (AUTHZ-11.3),
            // handed the operation as begun, with its client.
            $hooks = WideningPhase::before($begun, $grantee, static function () use ($kind, $resolve, $expiresAt): array {
                [$model, $scope] = $resolve();

                return [ProposedGrant::of($kind, $model, $scope, $expiresAt)];
            });

            // The grantee's rows are locked before they are read, so a grant
            // weighed as only shortening one held is weighed on the row as it
            // stays until the write.
            OperationScope::pins()?->lockGrantees($reference);

            [$model, $scope] = $resolve();

            RoleParity::assertGrantable($kind->value, $model, GrantChanges::guard($grantee));
            InlinePolicies::assertAttachable($model, $reference);

            $actor?->authorizeIn($operation, OperationResource::grant($kind->grantAction(), $reference, $model, $scope, $expiresAt));

            $hooks->assertCovers(static fn (): array => [ProposedGrant::of($kind, $model, $scope, $expiresAt)]);

            $change = GrantChanges::table($kind, $reference, $operation->actor, $scope)->grant(GrantChanges::key($model), $expiresAt);

            OperationScope::dispatch(...$kind->changeEvents($operation, $reference, $model, $scope, $change, $expiresAt));

            return $change->outcome;
        }, $actor);

        self::forgetRelation($kind, $grantee);

        return $outcome;
    }

    /**
     * Revoke rows of the given kind in one transaction, each in the scope its
     * owner fixes or the tenant named, else platform-wide.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  mixed  $target
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string|null  $application
     * @return int
     *
     * @throws \Throwable
     */
    private function revoke(GrantTarget $kind, Model|Reference $grantee, mixed $target, ?ActingContext $actor, Model|Reference|null $tenant, ?string $application): int
    {
        $reference = self::grantee($grantee);
        $named     = GrantScopes::named($tenant);
        $operation = Operation::begin($actor, [$kind->revokeAction()]);

        $revoked = OperationScope::run($operation, static function (Operation $operation) use ($actor, $kind, $grantee, $reference, $named, $target, $application): int {
            OperationScope::pins()?->lockGrantees($reference);

            $candidates = \is_string($target) ? $kind->named($target, GrantChanges::guard($grantee), $named) : [self::stored($kind, $kind->assertTarget($target), $actor)];
            $rows       = GrantChanges::revocations($kind, $reference, $operation->actor, $candidates, new GrantScope($named, $application));
            $events     = [];

            $action = $kind->revokeAction();

            $actor?->authorizeIn($operation, ...\array_map(static fn (array $row): OperationResource => OperationResource::revoke($action, $reference, $row[0], $row[4]), $rows));

            foreach ($rows as [$model, $table, $key, $reach, $scope]) {
                if ($reach === null) {
                    continue;
                }

                $table->revoke([$key]);

                $events[] = $kind->revokedEvent($operation, $reference, $model, $scope);
            }

            OperationScope::dispatch(...$events);

            return \count($events);
        }, $actor);

        self::forgetRelation($kind, $grantee);

        return $revoked;
    }

    /**
     * Replace the grantee's rows of the given kind in one scope, in one
     * transaction: the tenant named, else the tenant that owns every target,
     * else the platform.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<int, mixed>  $targets
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $named
     * @return \SineMacula\Laravel\Authorization\Services\SyncResult
     *
     * @throws \Throwable
     */
    private function sync(GrantTarget $kind, Model|Reference $grantee, array $targets, ?\DateTimeInterface $expiresAt, ?ActingContext $actor, GrantScope $named): SyncResult
    {
        $reference = self::grantee($grantee);
        $begun     = Operation::begin($actor, [$kind->grantAction(), $kind->revokeAction()]);

        /** @var \SineMacula\Laravel\Authorization\Services\SyncResult $result */
        $result = OperationScope::run($begun, static function (Operation $operation) use ($actor, $kind, $grantee, $reference, $named, $targets, $expiresAt, $begun): SyncResult {
            $plan = static fn (): array => self::plan($kind, $grantee, $operation->actor, $named, $targets, $actor);

            // Every addition that widens the identity's scope runs its hooks
            // first, all of them before any lock and any write (AUTHZ-11.3),
            // handed the operation as begun, with its client.
            $hooks = WideningPhase::before($begun, $grantee, static function () use ($kind, $plan, $expiresAt): array {
                [, $written, $table, $keep] = $plan();

                return WideningPhase::additions($kind, $expiresAt, $written, $table, $keep);
            });

            // The grantee's rows are locked before they are read, so a row the
            // sync keeps as held is held until the write, never one revoked
            // meanwhile and written back undecided.
            OperationScope::pins()?->lockGrantees($reference);

            [$scope, $written, $table, $keep, $held] = $plan();

            $revoked = \array_values(\array_diff($held, \array_map(GrantChanges::key(...), $keep)));
            $changed = [];
            $events  = [];

            $reaches = $table->reaches($revoked);
            $now     = Carbon::now('UTC');
            $live    = $actor === null ? [] : $table->live(\array_map(\strval(...), \array_keys($keep)), $now);

            $actor?->authorizeIn($operation, ...GrantChanges::ofSync($kind, $reference, $live, $keep, $reaches, $written, $expiresAt));

            $hooks->assertCovers(static fn (): array => WideningPhase::additions($kind, $expiresAt, $written, $table, $keep, isLocked: true));

            $table->revoke($revoked);

            foreach ($keep as $model) {
                $id     = GrantChanges::key($model);
                $change = $table->rearm($id, $expiresAt, $now);
                $events = [...$events, ...$kind->changeEvents($operation, $reference, $model, $written, $change, $expiresAt)];

                // A row decided as held live is never written back: one gone by
                // the write was not what was decided.
                if ($change->outcome !== GrantOutcome::UNCHANGED && \in_array($id, $live, true)) {
                    throw DependencyChangedException::rows($kind->table());
                }

                $changed[$change->outcome->value][] = $id;
            }

            foreach ($kind->find($revoked) as $model) {
                $events[] = $kind->revokedEvent($operation, $reference, $model, new GrantScope($scope, $named->application, $reaches[GrantChanges::key($model)]));
            }

            OperationScope::dispatch(...$events);

            return new SyncResult($changed[GrantOutcome::GRANTED->value] ?? [], $changed[GrantOutcome::REARMED->value] ?? [], $revoked);
        }, $actor);

        self::forgetRelation($kind, $grantee);

        return $result;
    }

    /**
     * Return what a sync of the grantee's rows of the kind works from, read
     * afresh on each call: the scope it replaces the rows in (the tenant named,
     * else the tenant that owns every target, else the platform), the scope it
     * writes them in, the grantee's table there, the targets it keeps, keyed by
     * key, and the keys the grantee holds there.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $grantedBy
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $named
     * @param  array<int, mixed>  $targets
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return array{
     *     0: \SineMacula\Laravel\Authorization\Support\Reference|null,
     *     1: \SineMacula\Laravel\Authorization\Support\GrantScope,
     *     2: \SineMacula\Laravel\Authorization\Services\Support\GrantTable,
     *     3: array<string, \Illuminate\Database\Eloquent\Model>,
     *     4: list<string>,
     * }
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InlinePolicyAttachmentException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\ResourcePolicyException
     */
    private static function plan(GrantTarget $kind, Model|Reference $grantee, ?Reference $grantedBy, GrantScope $named, array $targets, ?ActingContext $actor): array
    {
        $scope   = $named->tenant ?? GrantScopes::commonOwner($kind, GrantChanges::guard($grantee), $targets);
        $written = self::scope($scope, $named->includeSubtree, $named->application);
        $table   = GrantChanges::table($kind, Reference::of($grantee), $grantedBy, $written);
        $held    = $table->held();

        return [$scope, $written, $table, self::toKeep($kind, $grantee, $targets, $held, $scope, $actor), $held];
    }

    /**
     * Resolve the sync's targets, keyed by key: a named target keeps every held
     * row of the name, else the row the lookup ranks first; a model given to a
     * delegated sync, its row as stored. Each must be grantable in the sync's
     * scope, and to the grantee.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<int, mixed>  $targets
     * @param  list<string>  $held
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $scope
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return array<string, \Illuminate\Database\Eloquent\Model>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InlinePolicyAttachmentException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\ResourcePolicyException
     */
    private static function toKeep(GrantTarget $kind, Model|Reference $grantee, array $targets, array $held, ?Reference $scope, ?ActingContext $actor): array
    {
        $keep = [];

        foreach ($targets as $target) {
            $models = \is_string($target) ? $kind->heldOrFirst($target, GrantChanges::guard($grantee), $held, $scope) : [self::stored($kind, $kind->assertTarget($target), $actor)];

            foreach ($models as $model) {
                GrantScopes::assertGrantableIn($kind, $model, $scope);
                RoleParity::assertGrantable($kind->value, $model, GrantChanges::guard($grantee));
                InlinePolicies::assertAttachable($model, Reference::of($grantee));

                $keep[GrantChanges::key($model)] = $model;
            }
        }

        return $keep;
    }

    /**
     * Return the target a call hands out as it is weighed and written: for a
     * delegated call, its row as stored (see `StoredRecords`), so the change is
     * never judged on a rank, name or document the model in hand holds but the
     * row does not; for trusted work, the model given.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return \Illuminate\Database\Eloquent\Model
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     */
    private static function stored(GrantTarget $kind, Model $model, ?ActingContext $actor): Model
    {
        return $actor === null ? $model : StoredRecords::of($kind->value, $model);
    }

    /**
     * Clear the grantee's loaded relation onto the rows of the given kind, once
     * the call's transaction has returned.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return void
     */
    private static function forgetRelation(GrantTarget $kind, Model|Reference $grantee): void
    {
        if (!$grantee instanceof Model) {
            return;
        }

        $grantee->unsetRelation($kind->relation());
    }

    /**
     * Return the reference to the grantee, before the call's transaction opens,
     * once the grantee is known to be one a grant can be written for: a saved
     * model with a key, or a reference with a type and a key.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGranteeException
     */
    private static function grantee(Model|Reference $grantee): Reference
    {
        $reference = Reference::of($grantee);

        if ($reference->type === '' || $reference->id === '' || ($grantee instanceof Model && !$grantee->exists)) {
            throw new InvalidGranteeException($grantee);
        }

        return $reference;
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
    private static function named(Model|Reference|null $tenant, bool $includeSubtree, ?string $application): GrantScope
    {
        return new GrantScope(GrantScopes::named($tenant), $application, $includeSubtree);
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
    private static function scope(?Reference $tenant, bool $includeSubtree, ?string $application): GrantScope
    {
        return new GrantScope($tenant, $application, $includeSubtree || $tenant === null);
    }
}
