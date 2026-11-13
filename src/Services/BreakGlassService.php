<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\OperationGrantee;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;
use SineMacula\Laravel\Authorization\Config\BreakGlassConfigValidator;
use SineMacula\Laravel\Authorization\Config\ModelClasses;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableMachine;
use SineMacula\Laravel\Authorization\Database\BreakGlassActivations;
use SineMacula\Laravel\Authorization\Diagnostics\PackageState;
use SineMacula\Laravel\Authorization\Enums\BreakGlassRefusal;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Exceptions\BreakGlassRefusedException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGranteeException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Exclusions\Support\ExclusionGuard;
use SineMacula\Laravel\Authorization\Hooks\ProposedGrant;
use SineMacula\Laravel\Authorization\Hooks\WideningPhase;
use SineMacula\Laravel\Authorization\Models\BreakGlassActivation;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\Support\GrantChanges;
use SineMacula\Laravel\Authorization\Services\Support\GrantScopes;
use SineMacula\Laravel\Authorization\Services\Support\StoredRecords;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\RoleParity;

/**
 * Activates, surrenders and revokes break-glass activations (AUTHZ-11.7, N133):
 * emergency access to a configured role, for a human principal, for a limited
 * time, with a justification code, granted through the role grant path (see
 * `Database\BreakGlassActivations`).
 *
 * `activate()` writes a record of its own, beside any grant of the role, live
 * from now until now plus the minutes given, in UTC, naming the acting
 * principal as its granter, or no one on a trusted call. It is refused with
 * `BreakGlassRefusedException`, its reason naming why, while break-glass is
 * disabled, for a machine or a model read as another subject's identity, for a
 * role not listed under `break_glass.roles`, for minutes below 1 or above the
 * role's maximum (refused, never shortened), for a justification not among the
 * configured codes, for a note while `notes` is false or one longer than
 * `note_max_length` characters, and for a scope naming half a tenant. A role
 * that does not exist under the grantee's guard throws `UnknownRoleException`,
 * an unsaved grantee `InvalidGranteeException`, and the role's owner and guard
 * are held to what a grant of it is held to. An activation that would leave the
 * grantee holding both roles of a declared pair where their reach overlaps is
 * refused with `RoleExclusionConflictException`, trusted or delegated, weighed
 * under the role's lock (see `ExclusionGuard::assertActivatable()`).
 *
 * Each call takes the acting context making it as `$actor`: null for trusted
 * system work (N75), which skips the right but none of the other refusals. A
 * delegated activation is decided through `check()` (D22), in the activation's
 * tenant and application, under `authorization:break-glass.activate` for the
 * actor itself and `authorization:break-glass.grant` for another, and a
 * delegated revocation under `authorization:break-glass.revoke`. Holding the
 * right across the reach is the gate (N140): the rank, self and possession
 * rules of a role grant are not weighed, while denies, boundaries, guardrails
 * and caps still apply to what the role grants. The grant hooks are asked about
 * an activation as about a grant of its role in its scope until its expiry, and
 * a refusal refuses it. A delegated call locks what a delegated role grant
 * locks, in the same order: the actor's authority, then the grantee's rows and
 * the role, and an activation locks the role before it is written, so it races
 * a role's deletion, a revocation of the right or another activation as a grant
 * does. A delegated call weighs a role given as a model on its row as stored.
 *
 * `surrender()` ends an activation for its own grantee alone, acting as itself
 * and not impersonated, and `revoke()` for a holder of the revoke right in the
 * activation's scope, or a trusted call. Each returns how many it ended, as a
 * revocation does: ending one already ended or expired changes nothing and
 * returns 0, and one that does not exist throws `ModelNotFoundException`.
 * Either may end an activation while break-glass is disabled, when none counts
 * anyway (N139). Every write goes through the model, so the next check sees it.
 * No event is dispatched: the lifecycle events arrive with the audit trail.
 *
 * Every operation refuses while the package is not healthy (see
 * `PackageState`), before it reads or writes.
 *
 * Part of the stable API suite packages may use; breaking changes require a
 * major version bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BreakGlassService
{
    use HasContainerInstance;

    /**
     * Activate the emergency role for the grantee in the scope for the minutes
     * given, and return the activation.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @param  int  $minutes
     * @param  string  $justification
     * @param  string|null  $note
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\BreakGlassActivation
     *
     * @throws \Throwable
     */
    public function activate(
        Model $grantee,
        Role|string $role,
        GrantScope $scope,
        int $minutes,
        string $justification,
        ?string $note = null,
        ?ActingContext $actor = null,
    ): BreakGlassActivation {
        PackageState::guardCurrent();

        $settings  = self::settings($justification, $note);
        $reference = self::grantee($grantee);
        $scope     = self::scope($scope);
        $action    = $actor !== null && OperationGrantee::isActor($reference, $actor->subject) ? PackagePermissions::BREAK_GLASS_ACTIVATE : PackagePermissions::BREAK_GLASS_GRANT;
        $begun     = Operation::begin($actor, [$action]);
        $limits    = $settings['roles'];
        $columns   = [
            'authorizable_type' => $reference->type,
            'authorizable_id'   => $reference->id,
            'tenant_type'       => $scope->tenant?->type,
            'tenant_id'         => $scope->tenant?->id,
            'include_subtree'   => $scope->includeSubtree,
            'application'       => $scope->application,
            'justification'     => $justification,
            'note'              => $note,
        ];

        $work = static function (Operation $operation) use ($grantee, $reference, $role, $scope, $minutes, $columns, $actor, $action, $limits, $begun): BreakGlassActivation {
            $now      = Carbon::now('UTC');
            $expires  = $now->copy()->addMinutes($minutes);
            $held     = self::emergencyRole($role, $grantee, $scope, $minutes, $limits, $actor);
            $proposal = static fn (): array => [ProposedGrant::of(GrantTarget::ROLE, $held, $scope, $expires)];

            // The hooks run before any lock, as for a grant of the role.
            $hooks = WideningPhase::before($begun, $grantee, $proposal);

            $actor?->authorizeIn($operation, OperationResource::breakGlass($action, $reference, $held, $scope, $expires));

            $hooks->assertCovers($proposal);

            self::assertHoldable($grantee, $held, $scope);
            self::lockRole($held);

            ExclusionGuard::assertActivatable($reference, $held, $scope);

            return BreakGlassActivation::query()->create([
                ...$columns,
                'role_id'         => $held->getKey(),
                'granted_by_type' => $operation->actor?->type,
                'granted_by_id'   => $operation->actor?->id,
                'activated_at'    => $now,
                'expires_at'      => $expires,
            ]);
        };

        /** @var \SineMacula\Laravel\Authorization\Models\BreakGlassActivation $activation */
        $activation = OperationScope::run($begun, $work, $actor);

        $grantee->unsetRelation('roles');

        return $activation;
    }

    /**
     * End the activation for its grantee, the actor, and return how many were
     * ended: none when it had ended or expired already.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\BreakGlassActivation|string  $activation
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $actor
     * @return int
     *
     * @throws \Throwable
     */
    public function surrender(BreakGlassActivation|string $activation, ActingContext $actor): int
    {
        PackageState::guardCurrent();

        $key = self::key($activation);

        /** @var int */
        return OperationScope::run(Operation::begin(), static function () use ($key, $actor): int {
            $stored    = self::find($key, true);
            $principal = $actor->principal();

            if ($actor->isImpersonating() || $principal->type !== $stored->authorizable_type || $principal->id !== $stored->authorizable_id) {
                throw new BreakGlassRefusedException(BreakGlassRefusal::NOT_GRANTEE, "Activation '{$key}' can be surrendered only by its own grantee, acting as itself.");
            }

            return self::end($stored, 'surrendered', $principal);
        });
    }

    /**
     * End the activation, and return how many were ended: none when it had
     * ended or expired already.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\BreakGlassActivation|string  $activation
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return int
     *
     * @throws \Throwable
     */
    public function revoke(BreakGlassActivation|string $activation, ?ActingContext $actor = null): int
    {
        PackageState::guardCurrent();

        $key = self::key($activation);

        /** @var int */
        return OperationScope::run(Operation::begin($actor, [PackagePermissions::BREAK_GLASS_REVOKE]), static function (Operation $operation) use ($key, $actor): int {
            if ($actor !== null) {
                $read    = self::find($key);
                $grantee = new Reference($read->authorizable_type, $read->authorizable_id);
                $scope   = new GrantScope(Reference::tenantOf($read), $read->application, $read->include_subtree);

                $actor->authorizeIn($operation, OperationResource::breakGlass(PackagePermissions::BREAK_GLASS_REVOKE, $grantee, self::roleOf($read), $scope));
            }

            return self::end(self::find($key, true), 'revoked', $operation->actor);
        }, $actor);
    }

    /**
     * Return the settings once break-glass is known to be enabled and the
     * justification and note within them.
     *
     * @param  string  $justification
     * @param  string|null  $note
     * @return array{enabled: bool, max_minutes: int, roles: array<string, int>, justifications: list<string>, notes: bool, note_max_length: int}
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\BreakGlassRefusedException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function settings(string $justification, ?string $note): array
    {
        $settings = BreakGlassConfigValidator::read();
        $length   = \mb_strlen($note ?? '');
        $longest  = $settings['note_max_length'];

        [$reason, $message] = match (true) {
            !$settings['enabled']                                         => [BreakGlassRefusal::DISABLED, 'Break-glass is disabled.'],
            !\in_array($justification, $settings['justifications'], true) => [BreakGlassRefusal::JUSTIFICATION, "'{$justification}' is not a justification code."],
            $note !== null && !$settings['notes']                         => [BreakGlassRefusal::NOTE_REFUSED, 'Break-glass notes are switched off.'],
            $length > $longest                                            => [BreakGlassRefusal::NOTE_TOO_LONG, "A note may have at most {$longest} characters."],
            default                                                       => [null, ''],
        };

        return $reason === null ? $settings : throw new BreakGlassRefusedException($reason, $message);
    }

    /**
     * Return the reference to the grantee once it is known to be a saved human
     * principal.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $grantee
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\BreakGlassRefusedException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGranteeException
     */
    private static function grantee(Model $grantee): Reference
    {
        $reference = Reference::of($grantee);

        if (!$grantee->exists || $reference->id === '') {
            throw new InvalidGranteeException($grantee);
        }

        if ($grantee instanceof AuthorizableMachine || BreakGlassActivations::isIdentity($grantee)) {
            throw new BreakGlassRefusedException(BreakGlassRefusal::NOT_HUMAN, 'Break-glass is activated only for a human principal, not ' . $grantee::class . '.');
        }

        return $reference;
    }

    /**
     * Return the scope an activation is written in, refusing one naming half a
     * tenant; a platform-wide one always reaches below.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @return \SineMacula\Laravel\Authorization\Support\GrantScope
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\BreakGlassRefusedException
     */
    private static function scope(GrantScope $scope): GrantScope
    {
        $tenant = $scope->tenant;

        if ($tenant !== null && ($tenant->type === '' || $tenant->id === '')) {
            throw new BreakGlassRefusedException(BreakGlassRefusal::HALF_TENANT, 'A break-glass scope names a whole tenant or none.');
        }

        return new GrantScope($tenant, $scope->application, $scope->includeSubtree || $tenant === null);
    }

    /**
     * Resolve the emergency role as a grant of it is resolved, its row as
     * stored for a delegated call, refusing one not listed and minutes outside
     * its limit.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  \Illuminate\Database\Eloquent\Model  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @param  int  $minutes
     * @param  array<string, int>  $limits
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\BreakGlassRefusedException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     */
    private static function emergencyRole(Role|string $role, Model $grantee, GrantScope $scope, int $minutes, array $limits, ?ActingContext $actor): Role
    {
        $model = GrantTarget::ROLE->resolve($role, GrantChanges::guard($grantee), $scope->tenant);

        /** @var \SineMacula\Laravel\Authorization\Models\Role $held */
        $held  = $actor === null ? $model : StoredRecords::of(GrantTarget::ROLE->value, $model);
        $limit = $limits[$held->name] ?? null;

        if ($limit === null) {
            throw new BreakGlassRefusedException(BreakGlassRefusal::NOT_LISTED, "Role '{$held->name}' is not a break-glass role.");
        }

        if ($minutes < 1 || $minutes > $limit) {
            throw new BreakGlassRefusedException(BreakGlassRefusal::DURATION, "Role '{$held->name}' is activated for 1 to {$limit} minutes, not {$minutes}.");
        }

        return $held;
    }

    /**
     * Refuse the role where the grantee may not hold it, as a grant of it is
     * refused: outside the tenant that owns it and the tenants below, or under
     * another guard.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GranteeGuardMismatchException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException
     */
    private static function assertHoldable(Model $grantee, Role $role, GrantScope $scope): void
    {
        GrantScopes::assertGrantableIn(GrantTarget::ROLE, $role, $scope->tenant);
        RoleParity::assertGrantable(GrantTarget::ROLE->value, $role, GrantChanges::guard($grantee));
    }

    /**
     * Lock the role's row shared, outside every scope, refusing a role whose
     * row is gone, so a deletion racing the activation either waits for it and
     * takes it, or refuses it.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     */
    private static function lockRole(Role $role): void
    {
        $key = $role->newQueryWithoutScopes()->useWritePdo()->whereKey($role->getKey())->sharedLock()->value($role->getKeyName());

        if ($key === null) {
            throw new UnknownRoleException($role->name);
        }
    }

    /**
     * Return the activation's role as stored.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\BreakGlassActivation  $activation
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private static function roleOf(BreakGlassActivation $activation): Role
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $class */
        $class = ModelClasses::get('role');

        return $class::query()->withoutGlobalScopes()->useWritePdo()->whereKey($activation->role_id)->firstOrFail();
    }

    /**
     * Return the activation with the key as stored, under a lock when asked; a
     * key that is not a UUID is found nowhere, on every database.
     *
     * @param  string  $key
     * @param  bool  $isLocked
     * @return \SineMacula\Laravel\Authorization\Models\BreakGlassActivation
     *
     * @throws \Illuminate\Database\Eloquent\ModelNotFoundException
     */
    private static function find(string $key, bool $isLocked = false): BreakGlassActivation
    {
        if (!Str::isUuid($key)) {
            throw (new ModelNotFoundException)->setModel(BreakGlassActivation::class, [$key]);
        }

        $query = BreakGlassActivation::query()->useWritePdo()->whereKey($key);

        if ($isLocked) {
            $query->lockForUpdate();
        }

        return $query->firstOrFail();
    }

    /**
     * End the activation for the reason, by the reference given, unless it has
     * ended or expired already, and return how many were ended.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\BreakGlassActivation  $activation
     * @param  string  $reason
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $by
     * @return int
     */
    private static function end(BreakGlassActivation $activation, string $reason, ?Reference $by): int
    {
        $now = Carbon::now('UTC');

        if ($activation->ended_at !== null || $activation->expires_at->lessThanOrEqualTo($now)) {
            return 0;
        }

        $activation->forceFill(['ended_at' => $now, 'ended_by_type' => $by?->type, 'ended_by_id' => $by?->id, 'end_reason' => $reason])->save();

        return 1;
    }

    /**
     * Return the key of the activation given.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\BreakGlassActivation|string  $activation
     * @return string
     */
    private static function key(BreakGlassActivation|string $activation): string
    {
        return \is_string($activation) ? $activation : $activation->id;
    }
}
