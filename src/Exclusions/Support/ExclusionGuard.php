<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exclusions\Support;

use Illuminate\Container\Container;
use SineMacula\Laravel\Authorization\Config\ModelClasses;
use SineMacula\Laravel\Authorization\Config\SwitchConfigValidator;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Exceptions\RoleExclusionConflictException;
use SineMacula\Laravel\Authorization\Exclusions\ConflictReport;
use SineMacula\Laravel\Authorization\Exclusions\RoleExclusion;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Reviews\Support\Definitions;
use SineMacula\Laravel\Authorization\Reviews\Support\RoleChains;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\Support\RoleExclusionTable;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Separation of duties enforced on every write that can create a holding
 * (AUTHZ-11.8, N136): a role grant, a widened or re-armed one, a parent given
 * to a role and a break-glass activation are refused with
 * `RoleExclusionConflictException`, carrying the conflicts the write would
 * create, when they would leave someone holding both roles of a declared pair
 * where their reach overlaps; trusted or delegated alike, with no override.
 *
 * Before the write, the pairs touching its roles are found by walking up from
 * them, a read of each level of the hierarchy (see
 * `RoleExclusionTable::touching()`), so a write of a role with no parent that
 * no pair touches costs one indexed query. The walk locks the roles shared and
 * every pair naming them for update, so two writes that could together create a
 * conflict for a pair queue on its row, and the report is read under shared
 * locks as the write leaves the holdings; the lock protocol is set out in
 * `docs/design/separation-of-duties.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExclusionGuard
{
    /**
     * Return the pairs touching the roles of the kind about to be granted, read
     * before the grants are written; none for grants of any other kind.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  list<string>  $roles
     * @return list<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: \SineMacula\Laravel\Authorization\Support\Reference}>
     */
    public static function pairsFor(GrantTarget $kind, array $roles): array
    {
        return $kind === GrantTarget::ROLE ? self::touching($roles) : [];
    }

    /**
     * Refuse the role grants just written for the grantee when those that may
     * widen what it holds would create a conflict for one of the pairs read
     * before the write (see `pairsFor()`); those that only narrow or leave a
     * grant as it was are let through.
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @formatter:off
     *
     * @param  list<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: \SineMacula\Laravel\Authorization\Support\Reference}>  $pairs
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  list<array{0: string, 1: \SineMacula\Laravel\Authorization\Support\GrantScope, 2: \SineMacula\Laravel\Authorization\Services\Support\GrantChange, 3: \DateTimeInterface|null}>  $grants
     * @return void
     *
     * @formatter:on
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleExclusionConflictException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     * @throws \UnexpectedValueException
     */
    public static function assertGranted(array $pairs, Reference $grantee, array $grants): void
    {
        $widened = [];

        foreach ($grants as [$role, $scope, $change, $expiresAt]) {
            if (!$change->isWidening($expiresAt, $scope->includeSubtree)) {
                continue;
            }

            $widened[] = [$role, $scope];
        }

        if ($widened === []) {
            return;
        }

        self::assertNone($pairs, ExclusionWrite::granted($grantee, $widened));
    }

    /**
     * Refuse the parent the role is about to be saved with when it would create
     * a conflict for a holder of the role or of a role below it; a role not
     * saved yet, which no one holds, a parent cleared or unchanged, and any
     * parent while the hierarchy is disabled are let through. A parent a pair
     * touches is weighed only inside a transaction on the package's connection,
     * as `RoleService::setParent()` opens, which holds the locks to the save.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return void
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleExclusionConflictException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     * @throws \UnexpectedValueException
     */
    public static function assertParent(Role $role): void
    {
        $parent = $role->parent_id;

        if (!$role->exists || $parent === null || !$role->isDirty('parent_id') || !SwitchConfigValidator::isEnabled('hierarchy')) {
            return;
        }

        $pairs = self::touching([$parent]);

        if ($pairs === []) {
            return;
        }

        if (AuthorizationConnection::connection()->transactionLevel() === 0) {
            throw new \LogicException('Change a role\'s parent through RoleService::setParent() or inside a transaction.');
        }

        $key = $role->id;

        self::lockBelow([$key]);
        self::assertNone($pairs, ExclusionWrite::reparented($key, $parent));
    }

    /**
     * Refuse a break-glass activation of the role for the grantee in the scope
     * when it would create a conflict, weighed as a live activation beside the
     * stored grants and activations. `BreakGlassService::activate()` calls it
     * holding the role's shared lock, so the role, the pair and the report's
     * rows are locked in a grant's order; the update lock a delegated call's
     * pins take on the role can still deadlock with a write of the pair's other
     * role.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleExclusionConflictException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     * @throws \UnexpectedValueException
     */
    public static function assertActivatable(Reference $grantee, Role $role, GrantScope $scope): void
    {
        $key = $role->id;

        self::assertNone(self::touching([$key]), ExclusionWrite::proposed($grantee, $key, $scope));
    }

    /**
     * Lock the roles and, while the hierarchy is enabled, every role below them
     * for update, in key order, outside the tenant scope: what a declaration
     * and a re-parenting hold, so a grant of any of them, which locks its role
     * shared before it reads the pairs, waits for them.
     *
     * @param  list<string>  $keys
     * @return void
     */
    public static function lockBelow(array $keys): void
    {
        $keys = SwitchConfigValidator::isEnabled('hierarchy') ? RoleChains::descendants($keys) : $keys;

        \sort($keys);

        $model = new (self::roleClass());

        $model->newQuery()->withoutGlobalScope(TenantScope::class)->useWritePdo()->whereKey($keys)->orderBy($model->getKeyName())->lockForUpdate()->pluck($model->getKeyName());
    }

    /**
     * Return the pairs touching the roles, each its two roles in the pair's
     * order.
     *
     * @param  list<string>  $roles
     * @return list<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: \SineMacula\Laravel\Authorization\Support\Reference}>
     */
    private static function touching(array $roles): array
    {
        $pairs = RoleExclusionTable::of()->touching(Definitions::morph(GrantTarget::ROLE), $roles);

        return \array_map(static fn (RoleExclusion $pair): array => [$pair->role, $pair->excludedRole], $pairs);
    }

    /**
     * Refuse the write when it would create a conflict for one of the pairs,
     * reading the report of the first it would create one for under shared
     * locks.
     *
     * @param  list<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: \SineMacula\Laravel\Authorization\Support\Reference}>  $pairs
     * @param  \SineMacula\Laravel\Authorization\Exclusions\Support\ExclusionWrite  $write
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleExclusionConflictException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     * @throws \UnexpectedValueException
     */
    private static function assertNone(array $pairs, ExclusionWrite $write): void
    {
        if ($pairs === []) {
            return;
        }

        /** @var \SineMacula\Laravel\Authorization\Contracts\IdentityDirectory $directory */
        $directory = Container::getInstance()->make(IdentityDirectory::class);

        foreach ((new ConflictReader($directory))->read($pairs, true, $write) as $report) {
            if (!$report->isEmpty()) {
                throw self::refusal($report);
            }
        }
    }

    /**
     * Return the refusal of a write carrying the report, naming its roles as
     * stored.
     *
     * @param  \SineMacula\Laravel\Authorization\Exclusions\ConflictReport  $report
     * @return \SineMacula\Laravel\Authorization\Exceptions\RoleExclusionConflictException
     */
    private static function refusal(ConflictReport $report): RoleExclusionConflictException
    {
        /** @var array<string, string> $names */
        $names = self::roleClass()::query()
            ->withoutGlobalScope(TenantScope::class)
            ->useWritePdo()
            ->whereKey([$report->role->id, $report->excludedRole->id])
            ->pluck('name', (new (self::roleClass()))->getKeyName())
            ->all();

        return RoleExclusionConflictException::written($report, $names[$report->role->id], $names[$report->excludedRole->id]);
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
