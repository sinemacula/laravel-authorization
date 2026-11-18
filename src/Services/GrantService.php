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
use SineMacula\Laravel\Authorization\Exceptions\InvalidGranteeException;
use SineMacula\Laravel\Authorization\Exclusions\Support\ExclusionGuard;
use SineMacula\Laravel\Authorization\Hooks\ProposedGrant;
use SineMacula\Laravel\Authorization\Hooks\WideningPhase;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\Support\ActivationEnds;
use SineMacula\Laravel\Authorization\Services\Support\GrantChanges;
use SineMacula\Laravel\Authorization\Services\Support\GrantScopes;
use SineMacula\Laravel\Authorization\Services\Support\StoredRecords;
use SineMacula\Laravel\Authorization\Services\Support\SyncPlan;
use SineMacula\Laravel\Authorization\Services\Support\SystemRoleGuard;
use SineMacula\Laravel\Authorization\Support\DeclaredPermissions;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\RoleParity;
use SineMacula\Laravel\Authorization\Support\RoleReach;

/**
 * Grants, revokes and syncs roles, permissions and policies to a grantee.
 *
 * Every call runs in one transaction on the package's connection, and reads the
 * role, permission and policy classes `authorization.models` configures. A role
 * or permission named by a string is looked up under the grantee's guard (its
 * `getAuthorizationGuard()`, when it declares one), else the package default.
 *
 * Every grant holds in a scope: a role, permission or policy one tenant owns is
 * granted in that tenant, or a tenant below it that a call names, and naming
 * any other is refused with `GrantScopeMismatchException`; one the platform
 * owns is granted in the tenant a call names as `$tenant`, else platform-wide.
 * A name is looked up among the rows visible in the tenant named, else in the
 * current tenant. A revocation follows the same rule, and a sync replaces the
 * grants in one scope: the tenant named, else the tenant that owns every
 * target, else the platform. A grant holds in the application the call names as
 * `$application`, else in every application; a revocation and a sync stay in it
 * the same way.
 *
 * A grant in a tenant also holds in the tenants below it in the tenant tree,
 * unless the call passes `$includeSubtree` false to limit it to that tenant; a
 * platform-wide grant counts everywhere whatever it is given. Granting what the
 * grantee holds, with the same expiry and another reach, changes the reach and
 * is reported as `REACH_CHANGED` with the granted event; a sync writes its
 * reach only to what it grants or re-arms, except to a role listed with a reach
 * of its own (`Support\RoleReach`): a sync compares such a role and its reach,
 * and changes the reach of one held live with the other in place, in one write
 * keeping its expiry, reported the same way.
 *
 * Grants are idempotent: granting what the grantee holds, with the same expiry,
 * changes nothing and is reported as unchanged, and a concurrent duplicate
 * never surfaces a unique-constraint violation. Re-granting a grant that has
 * expired re-arms it with the new expiry, and a different expiry on a live
 * grant is reported as a change.
 *
 * A permission is granted, or listed by a sync, only when its name covers a
 * declared permission (see `Support\DeclaredPermissions`), else the call throws
 * `UndeclaredPermissionException` before anything is decided or written. A
 * grantee keeps an undeclared permission it holds until it is revoked.
 *
 * The grantee events (`RoleAssigned`, `PermissionGranted`, `PolicyAttached`,
 * their revoked and detached counterparts, and the expiry-changed events) are
 * dispatched once the write commits, on the package's connection, and only for
 * a write that changed something; a write that rolls back, alone or with an
 * enclosing transaction, dispatches nothing. A changed expiry dispatches the
 * granted event as well as the expiry-changed one.
 *
 * Each method takes the acting context making the call as `$actor`: null for
 * trusted system work, such as seeders, migrations and console commands. A call
 * with an acting context is delegated administration: each change it makes is
 * decided as the actor, through `check()`, on the change's operation resource,
 * inside the call's transaction before anything is written, and the first
 * refused throws the decision's `AuthorizationException`, leaving nothing
 * written and dispatching no change event. The actor's authority and then the
 * grantee's rows are locked before the call reads them (see
 * `Administration\DependencyPins`), so what is decided is what is written:
 * `revokeAll()` revokes exactly the rows it decided, never one granted
 * meanwhile, and a sync never writes back a row it decided as held that is gone
 * by the write; either is tried again instead. A grant is decided under
 * `authorization:role.grant`, `authorization:permission.grant` or
 * `authorization:policy.attach`, a regrant, a changed expiry and a changed
 * reach included, and a revocation under `authorization:role.revoke`,
 * `authorization:permission.revoke` or `authorization:policy.detach`, each in
 * the scope it is written in. A sync decides a grant of each listed row the
 * grantee does not hold live in its scope, a grant with the expiry it keeps of
 * each role held live with the other reach than its entry names, and a
 * revocation of each it drops; any other row it holds live decides nothing. A
 * revocation by name decides each held row of that name; one by model decides
 * that row whether it is held or not. `revokeAll()` decides the revocation of
 * every row, the removal of every permission boundary
 * (`authorization:boundary.remove`) the grantee has, and the end of each of its
 * unexpired break-glass activations (`authorization:break-glass.revoke`) in the
 * activation's scope. There is no blanket action. Each change is decided in the
 * tenant of the row it changes, so an actor whose authority for the action
 * reaches that tenant, from a parent over its subtree or from the platform,
 * changes it from its own context, and `revokeAll()` clears a grantee's rows
 * across every tenant the actor administers. Every change to an identity or a
 * principal is then weighed by the administration stage (see
 * `OperationConstraints`): the actor must be strictly senior to the grantee
 * anywhere the change reaches (`administration.rank`); one that may widen
 * authority must be allowed across its whole reach (`administration.scope`)
 * and, made to the actor itself, also allowed
 * `authorization:administration.self` (`administration.self`). A change that
 * can only narrow (revoking a permission, a role no deny is attached to,
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
 * Before a grant, a sync's additions, re-arms and changed reaches, an extension
 * or a wider reach that widens an identity's scope is written, trusted or
 * delegated, the bound grant hook is called with every widening grant of the
 * call, before the package takes any lock for it (see `Hooks\WideningPhase`):
 * it may refuse by throwing, which rolls the call back, and the call is tried
 * again when a grant it writes widens with no hook run for it, as read again
 * under the lock once every decision is made, or, inside a transaction the
 * application opened, thrown as `TransactionConflictException`. A widening
 * grant made inside another management call's work is refused with
 * `NestedGrantException`, and one whose identity cannot be resolved with
 * `UnresolvableRecipientException`.
 *
 * Once a role is granted, re-armed, widened below its tenant or given a later
 * expiry, a sync's included, and before any event is dispatched, the call is
 * weighed against the pairs of mutually exclusive roles touching its roles,
 * read before it writes, trusted or delegated alike (see
 * `Exclusions\Support\ExclusionGuard`): a write that would leave someone
 * holding both roles of a declared pair where their reach overlaps throws
 * `RoleExclusionConflictException`, carrying the report of the conflicts it
 * would create, and the call is rolled back. A delegated change is decided
 * before it is weighed, so an actor not allowed it is refused as such, and the
 * grant hook, which runs before any lock, has been called by then.
 *
 * A grantee is a principal, an identity or a role: a policy attached to a role
 * applies to whoever holds the role, within both grants' scopes, and to whoever
 * holds a role below it. A change to a system role's grants is refused with
 * `SystemRoleProtectedException` unless `forceSystem()` on the role given
 * unlocked it, and reported with `SystemOverrideUsed`; a delegated call, or a
 * role named by a reference, guards the role as stored, which carries no
 * unlock; `revokeAll()` on a system role is guarded the same way, as
 * `revoke-all`, and a role whose row is gone has nothing left to guard. An
 * inline policy is attached only to the grantee it belongs to; attaching or
 * syncing it to any other throws `InlinePolicyAttachmentException` before
 * anything is written. A policy whose statements name `principals` is refused
 * for any grantee with `ResourcePolicyException` (see `PolicyPrincipals`).
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

        return $this->grant(GrantTarget::ROLE, $grantee, [$role], $expiresAt, $actor, GrantScopes::ofCall($tenant, $includeSubtree, $application))[0];
    }

    /**
     * Grant each of the given roles to the grantee as `grantRole()` grants one,
     * in one transaction and as one operation, revoking nothing, and return
     * each entry's outcome, keyed as the roles.
     *
     * An entry may give a role its own reach, as `RoleReach::of($role,
     * includeSubtree: false)`, in place of `$includeSubtree`. A role listed
     * twice with the same reach is granted once, each entry reporting its
     * outcome. In a tenant, a role listed twice with different reaches,
     * compared by the role each entry resolves to, is refused with
     * `InvalidArgumentException` before anything is written; platform-wide,
     * both entries name the same reach and the call goes ahead. An entry
     * refused for any reason leaves nothing written.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Role|\SineMacula\Laravel\Authorization\Support\RoleReach|string>  $roles
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @param  string|null  $application
     * @return array<int, \SineMacula\Laravel\Authorization\Enums\GrantOutcome>
     *
     * @throws \Throwable
     */
    public function grantRoles(
        Model|Reference $grantee,
        array $roles,
        ?\DateTimeInterface $expiresAt = null,
        ?ActingContext $actor = null,
        Model|Reference|null $tenant = null,
        bool $includeSubtree = true,
        ?string $application = null,
    ): array {
        PackageState::guardCurrent();

        [$targets, $reaches] = RoleReach::split($roles);

        $outcomes = $this->grant(GrantTarget::ROLE, $grantee, $targets, $expiresAt, $actor, GrantScopes::ofCall($tenant, $includeSubtree, $application), $reaches);

        return \array_combine(\array_keys($roles), $outcomes);
    }

    /**
     * Revoke a role from the grantee, and return how many roles were revoked:
     * none when the grantee held none.
     *
     * A name revokes every held role of that name under the grantee's guard, or
     * guard-agnostic, whichever tenant or the platform owns it, among the roles
     * visible in the tenant named, else the current tenant: a role only another
     * tenant owns is revoked by naming that tenant.
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
     * An entry may give a role its own reach, as `RoleReach::of($role,
     * includeSubtree: false)`, in place of `$includeSubtree`, so one sync holds
     * roles of both reaches. Such a role is compared with its reach: one held
     * live with the other reach has its reach changed in place, keeping its
     * expiry and its row, reported as `REACH_CHANGED` with the granted event
     * and listed in the result's `reachChanged`; one held live with the same
     * reach is left as it is. In a tenant, a role listed twice with different
     * reaches is refused with `InvalidArgumentException` before anything is
     * written. A sync that writes platform-wide, with no tenant named or owning
     * every role, writes grants that reach everywhere, whatever an entry says,
     * so there both entries name the same reach and the sync goes ahead.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Role|\SineMacula\Laravel\Authorization\Support\RoleReach|string>  $roles
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

        [$targets, $reaches] = RoleReach::split($roles);

        return $this->sync(GrantTarget::ROLE, $grantee, $targets, $expiresAt, $actor, GrantScopes::ofCall($tenant, $includeSubtree, $application), $reaches);
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

        return $this->grant(GrantTarget::PERMISSION, $grantee, [$permission], $expiresAt, $actor, GrantScopes::ofCall($tenant, $includeSubtree, $application))[0];
    }

    /**
     * Revoke a direct permission from the grantee, and return how many
     * permissions were revoked: none when the grantee held none.
     *
     * A name revokes every held permission of that name under the grantee's
     * guard, or guard-agnostic, whichever tenant or the platform owns it, among
     * the permissions visible in the tenant named, else the current tenant.
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

        return $this->sync(GrantTarget::PERMISSION, $grantee, $permissions, $expiresAt, $actor, GrantScopes::ofCall($tenant, $includeSubtree, $application));
    }

    /**
     * Attach a policy to the grantee, a principal, an identity or a role, until
     * the given expiry or forever. An inline policy is attached only to the
     * grantee it belongs to.
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

        return $this->grant(GrantTarget::POLICY, $grantee, [$policy], $expiresAt, $actor, GrantScopes::ofCall($tenant, $includeSubtree, $application))[0];
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

        return $this->sync(GrantTarget::POLICY, $grantee, $policies, $expiresAt, $actor, GrantScopes::ofCall($tenant, $includeSubtree, $application));
    }

    /**
     * Revoke every role, permission and policy the grantee holds, remove its
     * permission boundaries and end its break-glass activations not ended or
     * expired, whether break-glass is enabled or not, in one transaction and as
     * one operation, each decided for an acting context before any is written,
     * dispatching a revoked, detached or removed event for each, and return how
     * many there were. An activation is decided under the break-glass revoke
     * right in its scope and ended as revoked, as `BreakGlassService::revoke()`
     * ends one. The `HasAuthorization` trait calls this once a grantee is
     * deleted, `RoleObserver` once a role is deleted, and the grant pruner for
     * a grantee that no longer exists. For an acting context and a grantee that
     * holds nothing, each of the call's actions is decided unchanged at
     * platform scope, so an actor that may not take them is refused either way.
     *
     * A row naming half a tenant, which the package never writes, is revoked or
     * removed too, decided at platform scope in the row's application, so it
     * needs the actor's platform authority for the action, never a scope it
     * names half of; it is counted, and written to the log as malformed rather
     * than reported by an event, which would name it the platform's (see
     * `Support\TenantColumns`).
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
        $actions   = [
            PackagePermissions::ROLE_REVOKE,
            PackagePermissions::PERMISSION_REVOKE,
            PackagePermissions::POLICY_DETACH,
            PackagePermissions::BOUNDARY_REMOVE,
            PackagePermissions::BREAK_GLASS_REVOKE,
        ];
        $operation = Operation::begin($actor, $actions);

        $revoked = OperationScope::run($operation, static function (Operation $operation) use ($actor, $grantee, $reference): int {
            if ($actor === null) {
                [$events, $malformed] = GrantChanges::revokeEverywhere($reference, $operation);
                $activations          = ActivationEnds::unexpiredOf($reference);
            } else {
                // The grantee's rows are locked before they are read, so what
                // is revoked is exactly what was decided, never a row granted
                // meanwhile in a tenant the actor does not administer.
                OperationScope::pins()?->lockGrantees($reference);

                $unchanged = static fn (string $action): OperationResource => OperationResource::unchanged($action, $reference, null, GrantScope::platform());

                [$changes, $grants, $boundaries] = GrantChanges::everything($reference);

                $activations = ActivationEnds::unexpiredOf($reference);
                $further     = [...GrantChanges::malformed($reference, $grants, $boundaries), ...\array_map(ActivationEnds::revocation(...), $activations)];

                $actor->authorizeChanges($operation, [...$changes, ...$further], ...\array_map($unchanged, $operation->actions));

                $events    = GrantChanges::revokeDecided($reference, $operation, $changes);
                $malformed = GrantChanges::revokeMalformed($reference, $operation, $grants, $boundaries);
            }

            SystemRoleGuard::dispatch('revoke-all', $grantee, $actor, ...$events);

            $ended = 0;

            foreach ($activations as $activation) {
                $ended += ActivationEnds::end($activation, 'revoked', $operation);
            }

            return \count($events) + $malformed + $ended;
        }, $actor);

        foreach (GrantTarget::cases() as $kind) {
            self::forgetRelation($kind, $grantee);
        }

        return $revoked;
    }

    /**
     * Grant rows of the given kind in one transaction and one operation, each
     * in the scope its owner fixes or the tenant named, else platform-wide,
     * with the reach its entry names (by position), else the one named, and
     * return each target's outcome in order.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<int, mixed>  $targets
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $named
     * @param  array<int, bool>  $reaches
     * @return list<\SineMacula\Laravel\Authorization\Enums\GrantOutcome>
     *
     * @throws \Throwable
     */
    private function grant(
        GrantTarget $kind,
        Model|Reference $grantee,
        array $targets,
        ?\DateTimeInterface $expiresAt,
        ?ActingContext $actor,
        GrantScope $named,
        array $reaches = [],
    ): array {
        $reference = self::grantee($grantee);
        $begun     = Operation::begin($actor, [$kind->grantAction()]);
        $resolve   = static fn (): array => self::granted($kind, $grantee, $targets, $reaches, $named, $actor);
        $propose   = static fn (array $grant): ProposedGrant => ProposedGrant::of($kind, $grant[0], $grant[1], $expiresAt);

        /** @var list<\SineMacula\Laravel\Authorization\Enums\GrantOutcome> $outcomes */
        $outcomes = OperationScope::run($begun, static function (Operation $operation) use ($actor, $kind, $grantee, $reference, $resolve, $propose, $expiresAt, $begun): array {
            // Each grant that widens the identity's scope runs its hooks first,
            // before the package takes any lock for the call, handed the
            // operation as begun, with its client.
            $hooks = WideningPhase::before($begun, $grantee, static fn (): array => \array_map($propose, $resolve()[0]));

            // The grantee's rows are locked before they are read, so a grant
            // weighed as only shortening one held is weighed on the row as it
            // stays until the write.
            OperationScope::pins()?->lockGrantees($reference);

            [$grants, $keys] = $resolve();

            foreach ($grants as [$model]) {
                RoleParity::assertGrantable($kind->value, $model, GrantChanges::guard($grantee));
                InlinePolicies::assertAttachable($model, $reference);
            }

            $resource = static fn (array $grant): OperationResource => OperationResource::grant($kind->grantAction(), $reference, $grant[0], $grant[1], $expiresAt);

            $actor?->authorizeIn($operation, ...\array_map($resource, $grants));

            $hooks->assertCovers(static fn (): array => \array_map($propose, $grants));

            $pairs   = ExclusionGuard::pairsFor($kind, \array_map(static fn (array $grant): string => GrantChanges::key($grant[0]), $grants));
            $events  = [];
            $changed = [];
            $written = [];

            foreach ($grants as [$model, $scope]) {
                $key           = GrantChanges::key($model);
                $change        = GrantChanges::table($kind, $reference, $operation->actor, $scope)->grant($key, $expiresAt);
                $events        = [...$events, ...$kind->changeEvents($operation, $reference, $model, $scope, $change, $expiresAt)];
                $changed[$key] = $change->outcome;
                $written[]     = [$key, $scope, $change, $expiresAt];
            }

            ExclusionGuard::assertGranted($pairs, $reference, $written);

            SystemRoleGuard::dispatch("{$kind->value}-change", $grantee, $actor, ...$events);

            return \array_map(static fn (string $key): GrantOutcome => $changed[$key], $keys);
        }, $actor);

        self::forgetRelation($kind, $grantee);

        return $outcomes;
    }

    /**
     * Resolve a grant's targets as one is resolved alone, each in the scope its
     * owner fixes or the tenant named, with the reach its entry names (by
     * position), else the one named. Return each row once, with its scope, and
     * the key of each target in order; a row listed with both reaches is
     * refused, except platform-wide, where both are the same.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<int, mixed>  $targets
     * @param  array<int, bool>  $reaches
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $named
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return array{list<array{\Illuminate\Database\Eloquent\Model, \SineMacula\Laravel\Authorization\Support\GrantScope}>, list<string>}
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     */
    private static function granted(GrantTarget $kind, Model|Reference $grantee, array $targets, array $reaches, GrantScope $named, ?ActingContext $actor): array
    {
        $models = [];
        $listed = [];

        foreach ($targets as $index => $target) {
            $model = $kind->resolve($target, GrantChanges::guard($grantee), $named->tenant);
            $model = \is_string($target) ? $model : self::stored($kind, $model, $actor);
            $key   = GrantChanges::key($model);

            if ($model instanceof Permission) {
                DeclaredPermissions::assertStored($model);
            }

            $models[$key] ??= $model;
            $listed[] = [$key, GrantScopes::written(GrantScopes::of($kind, $model, $named->tenant), $reaches[$index] ?? $named->includeSubtree, $named->application)];
        }

        $scopes = GrantScopes::byKey($kind, $listed);
        $grants = [];

        foreach ($models as $key => $model) {
            $grants[] = [$model, $scopes[$key]];
        }

        return [$grants, \array_column($listed, 0)];
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

            SystemRoleGuard::dispatch("{$kind->value}-change", $grantee, $actor, ...$events);

            return \count($events);
        }, $actor);

        self::forgetRelation($kind, $grantee);

        return $revoked;
    }

    /**
     * Replace the grantee's rows of the given kind in one scope, in one
     * transaction: the tenant named, else the tenant that owns every target,
     * else the platform. A target listed with a reach of its own (by its
     * position among the targets) is written and compared with that reach.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<int, mixed>  $targets
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $named
     * @param  array<int, bool>  $reaches
     * @return \SineMacula\Laravel\Authorization\Services\SyncResult
     *
     * @throws \Throwable
     */
    private function sync(
        GrantTarget $kind,
        Model|Reference $grantee,
        array $targets,
        ?\DateTimeInterface $expiresAt,
        ?ActingContext $actor,
        GrantScope $named,
        array $reaches = [],
    ): SyncResult {
        $reference = self::grantee($grantee);
        $begun     = Operation::begin($actor, [$kind->grantAction(), $kind->revokeAction()]);
        $planFor   = static fn (?Reference $grantedBy): SyncPlan => self::plan($kind, $grantee, $grantedBy, $named, $targets, $reaches, $actor);

        /** @var \SineMacula\Laravel\Authorization\Services\SyncResult $result */
        $result = OperationScope::run($begun, static function (Operation $operation) use ($actor, $kind, $grantee, $reference, $planFor, $expiresAt, $begun): SyncResult {
            $plan = static fn (): SyncPlan => $planFor($operation->actor);

            // Every addition, and every change of reach, that widens the
            // identity's scope runs its hooks first, all of them before any
            // lock and any write, handed the operation as begun, with its
            // client.
            $hooks = WideningPhase::before($begun, $grantee, static fn (): array => WideningPhase::additions($plan(), $expiresAt));

            // The grantee's rows are locked before they are read, so a row the
            // sync keeps as held is held until the write, never one revoked
            // meanwhile and written back undecided.
            OperationScope::pins()?->lockGrantees($reference);

            $sync    = $plan();
            $revoked = $sync->revoked();
            $dropped = $sync->table->reaches($revoked);
            $now     = Carbon::now('UTC');
            $rows    = $actor === null ? [] : $sync->table->liveRows($sync->kept(), $now);

            $actor?->authorizeIn($operation, ...GrantChanges::ofSync($sync, $reference, $rows, $dropped, $expiresAt));

            $hooks->assertCovers(static fn (): array => WideningPhase::additions($sync, $expiresAt, isLocked: true));

            $sync->table->revoke($revoked);

            [$events, $changed] = $sync->write($operation, $reference, $expiresAt, $now, GrantChanges::keptAsHeld($rows, $sync->reaches));

            SystemRoleGuard::dispatch("{$kind->value}-change", $grantee, $actor, ...$events, ...$sync->revokedEvents($operation, $reference, $dropped));

            return new SyncResult(
                $changed[GrantOutcome::GRANTED->value] ?? [],
                $changed[GrantOutcome::REARMED->value] ?? [],
                $revoked,
                $changed[GrantOutcome::REACH_CHANGED->value] ?? [],
            );
        }, $actor);

        self::forgetRelation($kind, $grantee);

        return $result;
    }

    /**
     * Return what a sync of the grantee's rows of the kind works from, read
     * afresh on each call (see `SyncPlan`): the scope it writes them in, in the
     * tenant it replaces them in (the tenant named, else the tenant that owns
     * every target, else the platform), the grantee's table there, the targets
     * it keeps, the keys the grantee holds there, and the scope each target
     * listed with a reach of its own is written in.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $grantedBy
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $named
     * @param  array<int, mixed>  $targets
     * @param  array<int, bool>  $reaches
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return \SineMacula\Laravel\Authorization\Services\Support\SyncPlan
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InlinePolicyAttachmentException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\ResourcePolicyException
     */
    private static function plan(
        GrantTarget $kind,
        Model|Reference $grantee,
        ?Reference $grantedBy,
        GrantScope $named,
        array $targets,
        array $reaches,
        ?ActingContext $actor,
    ): SyncPlan {
        $scope   = $named->tenant ?? GrantScopes::commonOwner($kind, GrantChanges::guard($grantee), $targets);
        $written = GrantScopes::written($scope, $named->includeSubtree, $named->application);
        $table   = GrantChanges::table($kind, Reference::of($grantee), $grantedBy, $written);
        $held    = $table->held();

        [$keep, $listed] = self::toKeep($kind, $grantee, $targets, $reaches, $held, $scope, $actor);

        return new SyncPlan($kind, $written, $table, $keep, $held, SyncPlan::reachesOf($kind, $written, $listed));
    }

    /**
     * Resolve the sync's targets, keyed by key: a named target keeps every held
     * row of the name, else the row the lookup ranks first; a model given to a
     * delegated sync, its row as stored. Each must be grantable in the sync's
     * scope, and to the grantee. Return them with each kept key and the reach
     * its entry names, null for none.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<int, mixed>  $targets
     * @param  array<int, bool>  $reaches
     * @param  list<string>  $held
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $scope
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return array{array<string, \Illuminate\Database\Eloquent\Model>, list<array{string, bool|null}>}
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InlinePolicyAttachmentException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\ResourcePolicyException
     */
    private static function toKeep(GrantTarget $kind, Model|Reference $grantee, array $targets, array $reaches, array $held, ?Reference $scope, ?ActingContext $actor): array
    {
        $keep   = [];
        $listed = [];

        foreach ($targets as $index => $target) {
            $models = \is_string($target) ? $kind->heldOrFirst($target, GrantChanges::guard($grantee), $held, $scope) : [self::stored($kind, $kind->assertTarget($target), $actor)];

            foreach ($models as $model) {
                if ($model instanceof Permission) {
                    DeclaredPermissions::assertStored($model);
                }

                GrantScopes::assertGrantableIn($kind, $model, $scope);
                RoleParity::assertGrantable($kind->value, $model, GrantChanges::guard($grantee));
                InlinePolicies::assertAttachable($model, Reference::of($grantee));

                $keep[GrantChanges::key($model)] = $model;
                $listed[]                        = [GrantChanges::key($model), $reaches[$index] ?? null];
            }
        }

        return [$keep, $listed];
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
}
