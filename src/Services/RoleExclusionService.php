<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;
use SineMacula\Laravel\Authorization\Config\ModelClasses;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Diagnostics\PackageState;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Events\Role\ExclusionDeclared;
use SineMacula\Laravel\Authorization\Events\Role\ExclusionRemoved;
use SineMacula\Laravel\Authorization\Exceptions\RoleExclusionConflictException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Exceptions\UnwrittenGrantException;
use SineMacula\Laravel\Authorization\Exclusions\ConflictReport;
use SineMacula\Laravel\Authorization\Exclusions\RoleExclusion;
use SineMacula\Laravel\Authorization\Exclusions\Support\ConflictReader;
use SineMacula\Laravel\Authorization\Exclusions\Support\ExclusionGuard;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Reviews\Support\Definitions;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\Support\ExclusionPair;
use SineMacula\Laravel\Authorization\Services\Support\RecordWriter;
use SineMacula\Laravel\Authorization\Services\Support\RoleExclusionTable;
use SineMacula\Laravel\Authorization\Services\Support\StoredRecords;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Declares, removes and lists pairs of mutually exclusive roles, and reports
 * who holds both roles of a pair (AUTHZ-11.8, N135, N136): separation of
 * duties, so no grantee holds both roles where their reach overlaps.
 *
 * A pair names its two roles by key, in a canonical order, the lower key first,
 * so the pair stays what it is when a role is renamed, and the pair (A, B) is
 * the pair (B, A). A role named by a string is looked up as the role service
 * looks one up, under the package's default guard, in the tenant scope; a role
 * model must be saved (`UnsavedRecordException`). A role is never paired with
 * itself (`InvalidRoleExclusionException`), nor is a role naming half a tenant
 * (`InvalidTenantColumnsException`). A pair is a definition, owned as the
 * others are (D20): by the owner of its role owned furthest down, which may
 * name a role its own tenant, an ancestor or the platform owns, as a role takes
 * its parent, and two roles owned by tenants neither of which lies within the
 * other are refused with `OwnerMismatchException` (see
 * `Support\ExclusionPair`). A role deleted takes its pairs with it.
 *
 * Declaring a pair already declared changes nothing and is reported as
 * `UNCHANGED`, as an idempotent grant is; a new pair is `GRANTED`. Declaring a
 * pair someone already holds both roles of, where their reach overlaps, is
 * refused with `RoleExclusionConflictException`, carrying the conflict report,
 * and nothing is written or removed: an administrator resolves each conflict,
 * by revoking a grant or narrowing its reach, then declares the pair again. The
 * report is read under the locks the declaration writes under, both roles' rows
 * locked first, then every role below them, so a grant of any of them, which
 * locks the role it grants, waits for it, and each row it reads is read under a
 * lock, so it is the row as last committed whatever snapshot the transaction
 * reads. Once declared, every grant, re-parenting and break-glass activation is
 * weighed against the pair (see `Exclusions\Support\ExclusionGuard`).
 *
 * Each write takes the acting context making the call as `$actor`: null for
 * trusted system work (N75), else a delegated change (AUTHZ-11.1), decided as
 * the actor through `check()` on the pair's operation resource (see
 * `OperationResource::exclusion()`), under
 * `authorization:role-exclusion.declare` or `.remove`, inside the write's
 * transaction before anything is read for the report or written, under the
 * concurrency protocol of delegated administration, both roles locked and
 * pinned before it is decided. The change is made only from the tenant that
 * owns the pair, a platform pair's from the platform (`administration.owner`),
 * both roles must be junior to the actor (`administration.rank`), and a
 * removal, which lifts the pair across its owner's whole reach, needs an actor
 * that administers it (`administration.scope`) (see
 * `Administration\ExcludedRoles`). A removal is decided on the owner the pair
 * was stored with, so a pair stays removable after the tree moves its roles'
 * owners apart; one not declared is decided as a declaration would be.
 *
 * Every write runs in one transaction on the package's connection, is one
 * operation for the actor, recorded on the row it writes, and dispatches
 * `ExclusionDeclared` or `ExclusionRemoved` once it commits, only when it
 * changed something.
 *
 * The reads, `pairs()`, `conflicts()` and `conflictsForAll()`, are trusted
 * reads, not decided, of every pair and every grant stored, whatever tenant
 * owns it, on the write connection: a screen shows them only to those it
 * should. The conflict report (see `Exclusions\ConflictReport`) reads the
 * holders of both roles, and of every role below either, in a fixed number of
 * queries, never one for each holder or tenant, a role counting wherever a
 * check sees it held through the grant, and asks the identity directory for
 * each holder's principals.
 *
 * Every operation refuses while the package is not healthy (see
 * `PackageState`), before it reads or writes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RoleExclusionService
{
    use HasContainerInstance;

    /**
     * Create a new role exclusion service.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Container the identity directory is read from on every call. */
        private Container $container,
    ) {}

    /**
     * Declare the two roles mutually exclusive, and return what changed: a new
     * pair, or nothing when the pair was declared already.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $excluded
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    public function declare(Role|string $role, Role|string $excluded, ?ActingContext $actor = null): GrantOutcome
    {
        PackageState::guard($this->container);

        $operation = Operation::begin($actor, [PackagePermissions::ROLE_EXCLUSION_DECLARE]);

        /** @var \SineMacula\Laravel\Authorization\Enums\GrantOutcome */
        return OperationScope::run($operation, function (Operation $operation) use ($actor, $role, $excluded): GrantOutcome {
            $pair = self::pinned($role, $excluded, $actor);

            [$owning, $other, $owner] = $pair->ownership();

            $actor?->authorizeIn($operation, OperationResource::exclusion(PackagePermissions::ROLE_EXCLUSION_DECLARE, $owning, $other));

            self::lock($pair);

            $table = RoleExclusionTable::of($operation->actor);

            return $table->isDeclared($pair->first->id, $pair->second->id) ? GrantOutcome::UNCHANGED : $this->declared($operation, $table, $pair, $owner);
        }, $actor);
    }

    /**
     * Remove the pair of the two roles, and report whether it was declared.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $excluded
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return bool
     *
     * @throws \Throwable
     */
    public function remove(Role|string $role, Role|string $excluded, ?ActingContext $actor = null): bool
    {
        PackageState::guard($this->container);

        $operation = Operation::begin($actor, [PackagePermissions::ROLE_EXCLUSION_REMOVE]);

        /** @var bool */
        return OperationScope::run($operation, static function (Operation $operation) use ($actor, $role, $excluded): bool {
            $pair   = self::pinned($role, $excluded, $actor);
            $table  = RoleExclusionTable::of();
            $stored = $table->find(Definitions::morph(GrantTarget::ROLE), $pair->first->id, $pair->second->id);

            if ($actor !== null) {
                [$owning, $other] = $stored === null ? $pair->ownership() : $pair->ownedBy($stored->tenant);

                $actor->authorizeIn($operation, OperationResource::exclusion(PackagePermissions::ROLE_EXCLUSION_REMOVE, $owning, $other));
            }

            if ($stored === null) {
                return false;
            }

            $table->remove($pair->first->id, $pair->second->id);

            [$first, $second] = $pair->references();

            OperationScope::dispatch(new ExclusionRemoved($operation, $first, $pair->first->name, $second, $pair->second->name, $stored->tenant));

            return true;
        }, $actor);
    }

    /**
     * List every pair declared, or every pair naming the role, ordered by their
     * roles' keys.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string|null  $role
     * @return list<\SineMacula\Laravel\Authorization\Exclusions\RoleExclusion>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnsavedRecordException
     */
    public function pairs(Role|string|null $role = null): array
    {
        PackageState::guard($this->container);

        return RoleExclusionTable::of()->pairs(Definitions::morph(GrantTarget::ROLE), $role === null ? null : self::resolve($role)->id);
    }

    /**
     * Report who holds both roles where their reach overlaps, whether or not
     * the pair is declared.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $excluded
     * @return \SineMacula\Laravel\Authorization\Exclusions\ConflictReport
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidRoleExclusionException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnsavedRecordException
     */
    public function conflicts(Role|string $role, Role|string $excluded): ConflictReport
    {
        PackageState::guard($this->container);

        return $this->reader()->read([ExclusionPair::of(self::resolve($role), self::resolve($excluded))->references()])[0];
    }

    /**
     * Report, for every pair declared, in the order `pairs()` lists them, who
     * holds both its roles where their reach overlaps: the conflicts a tenant
     * moved, an identity linked to a principal or a write made before the pair
     * left behind.
     *
     * @return list<\SineMacula\Laravel\Authorization\Exclusions\ConflictReport>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public function conflictsForAll(): array
    {
        PackageState::guard($this->container);

        $pairs = RoleExclusionTable::of()->pairs(Definitions::morph(GrantTarget::ROLE));

        return $this->reader()->read(\array_map(static fn (RoleExclusion $pair): array => [$pair->role, $pair->excludedRole], $pairs));
    }

    /**
     * Resolve the two roles as a pair and, for a delegated change, lock and pin
     * both before the change is decided.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $excluded
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return \SineMacula\Laravel\Authorization\Services\Support\ExclusionPair
     *
     * @throws \Throwable
     */
    private static function pinned(Role|string $role, Role|string $excluded, ?ActingContext $actor): ExclusionPair
    {
        $pair = ExclusionPair::of(self::resolve($role, $actor), self::resolve($excluded, $actor));

        OperationScope::pins()?->lockGrantees($pair->first, $pair->second);

        return $pair;
    }

    /**
     * Declare the pair, owned by the tenant given or the platform, unless
     * someone holds both its roles where their reach overlaps, which refuses it
     * with the conflict report, read once every role below the pair's is
     * locked, and return what changed.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Services\Support\RoleExclusionTable  $table
     * @param  \SineMacula\Laravel\Authorization\Services\Support\ExclusionPair  $pair
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $owner
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleExclusionConflictException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnwrittenGrantException
     */
    private function declared(Operation $operation, RoleExclusionTable $table, ExclusionPair $pair, ?Reference $owner): GrantOutcome
    {
        ExclusionGuard::lockBelow([$pair->first->id, $pair->second->id]);

        $report = $this->reader()->read([$pair->references()], true)[0];

        if (!$report->isEmpty()) {
            throw new RoleExclusionConflictException($report, $pair->first->name, $pair->second->name);
        }

        $outcome = $table->declare($pair->first->id, $pair->second->id, $owner) ?? throw new UnwrittenGrantException("role exclusion of {$pair->first->name}");

        [$first, $second] = $pair->references();

        if ($outcome === GrantOutcome::GRANTED) {
            OperationScope::dispatch(new ExclusionDeclared($operation, $first, $pair->first->name, $second, $pair->second->name, $owner));
        }

        return $outcome;
    }

    /**
     * Lock both roles' rows, in key order, outside the tenant scope, refusing a
     * role whose row is gone.
     *
     * @param  \SineMacula\Laravel\Authorization\Services\Support\ExclusionPair  $pair
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     */
    private static function lock(ExclusionPair $pair): void
    {
        $keys = self::roleClass()::query()
            ->withoutGlobalScope(TenantScope::class)
            ->useWritePdo()
            ->whereKey([$pair->first->id, $pair->second->id])
            ->orderBy($pair->first->getKeyName())
            ->lockForUpdate()
            ->pluck($pair->first->getKeyName())
            ->all();

        $found = \array_map(static fn (mixed $key): string => \is_scalar($key) ? (string) $key : '', $keys);

        foreach ([$pair->first, $pair->second] as $role) {
            if (!\in_array($role->id, $found, true)) {
                throw new UnknownRoleException($role->name);
            }
        }
    }

    /**
     * Resolve a role: a name through the configured role class, under the
     * package's default guard; a model once it is known to be saved, read again
     * as stored for a delegated change (see `StoredRecords`), so the change is
     * weighed on the row as stored.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnsavedRecordException
     */
    private static function resolve(Role|string $role, ?ActingContext $actor = null): Role
    {
        if (!$role instanceof Role) {
            $found = GuardScopedLookup::findForGuard(self::roleClass(), $role);

            return $found instanceof Role ? $found : throw new UnknownRoleException($role);
        }

        $model = RecordWriter::existing('role', $role);

        return $actor === null ? $model : StoredRecords::of('role', $model);
    }

    /**
     * Return the reader of the conflict report, with the bound identity
     * directory.
     *
     * @return \SineMacula\Laravel\Authorization\Exclusions\Support\ConflictReader
     */
    private function reader(): ConflictReader
    {
        /** @var \SineMacula\Laravel\Authorization\Contracts\IdentityDirectory $directory */
        $directory = $this->container->make(IdentityDirectory::class);

        return new ConflictReader($directory);
    }

    /**
     * Return the role class `authorization.models.role` configures.
     *
     * @return class-string<\SineMacula\Laravel\Authorization\Models\Role>
     */
    private static function roleClass(): string
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> */
        return ModelClasses::get('role');
    }
}
