<?php

declare(strict_types = 1);

namespace Tests\Feature\Hooks;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Enums\WideningReason;
use SineMacula\Laravel\Authorization\Events\Identity\RoleAssigned;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException;
use SineMacula\Laravel\Authorization\Exceptions\GrantHookRecursionException;
use SineMacula\Laravel\Authorization\Exceptions\GrantRefusedException;
use SineMacula\Laravel\Authorization\Exceptions\NestedGrantException;
use SineMacula\Laravel\Authorization\Hooks\GrantHooks;
use SineMacula\Laravel\Authorization\Hooks\GrantWidening;
use SineMacula\Laravel\Authorization\Hooks\ProposedGrant;
use SineMacula\Laravel\Authorization\Hooks\WideningPhase;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantScopeQuery;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\Support\GrantChanges;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsAdministrator;
use Tests\Concerns\RecordsRowLocks;
use Tests\Concerns\WidensGrants;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Fixtures\GrantHooks\RefusingGrantHook;
use Tests\TestCase;

/**
 * Feature tests for the grant hook phase (AUTHZ-11.3, N80): the hook called for
 * the widening grants of a call before the package takes any lock, the batch's
 * hooks before any write, a veto rolling everything back, the check of the
 * final grants after the locks, the recursion guard and nested calls.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(WideningPhase::class)]
final class WideningPhaseTest extends TestCase
{
    use ActsAsAdministrator, RecordsRowLocks, WidensGrants;

    /**
     * With nothing bound, or the composite holding no hook, nothing is proposed
     * or classified, and nothing is checked after the locks.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithNoHookNothingIsClassified(): void
    {
        $proposed = new \ArrayObject;
        $propose  = static function () use ($proposed): array {
            $proposed->append(true);

            return [];
        };

        self::assertInstanceOf(GrantHooks::class, app(GrantHook::class));

        WideningPhase::before(Operation::begin(), self::principal(), $propose)->assertCovers($propose);

        $this->app?->offsetUnset(GrantHook::class);

        WideningPhase::before(Operation::begin(), self::principal(), $propose)->assertCovers($propose);

        self::assertCount(0, $proposed);
    }

    /**
     * A grant to a role widens no identity's scope, so it is never classified.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantToARoleIsNeverClassified(): void
    {
        $hook     = $this->hook();
        $proposed = new \ArrayObject;
        $propose  = static function () use ($proposed): array {
            $proposed->append(true);

            return [];
        };

        WideningPhase::before(Operation::begin(), Role::query()->create(['name' => 'holder']), $propose)->assertCovers($propose);

        self::assertCount(0, $proposed);
        self::assertSame([], $hook->widenings);
    }

    /**
     * The hook is called once with the call's widening grants, and not at all
     * when none widens.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheHookIsCalledOnlyForAWidening(): void
    {
        $this->principals();

        $principal = self::principal();
        $role      = Role::query()->create(['name' => 'held']);

        self::grants()->grantRole($principal, $role);

        $hook = $this->hook();

        WideningPhase::before(Operation::begin(), $principal, static fn (): array => [self::proposal($role)]);

        self::assertSame([], $hook->reasons());

        WideningPhase::before(Operation::begin(), $principal, static fn (): array => [self::proposal($role), self::proposal(Role::query()->create(['name' => 'new']))]);

        self::assertCount(1, $hook->widenings);
        self::assertCount(1, $hook->widenings[0]->changes);
        self::assertSame([[WideningReason::PLATFORM->value]], $hook->reasons());
    }

    /**
     * A final grant that widens with no hook run for it is a dependency
     * conflict; one the hook was called for, or one that widens nothing,
     * passes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFinalWideningTheHookWasNotCalledForConflicts(): void
    {
        $this->principals();
        $this->hook();

        $principal = self::principal();
        $covered   = self::proposal(Role::query()->create(['name' => 'covered']));
        $other     = self::proposal(Role::query()->create(['name' => 'other']));
        $phase     = WideningPhase::before(Operation::begin(), $principal, static fn (): array => [$covered]);

        $phase->assertCovers(static fn (): array => [$covered]);
        $phase->assertCovers(static fn (): array => []);

        $this->expectExceptionObject(DependencyChangedException::widening());

        $phase->assertCovers(static fn (): array => [$covered, $other]);
    }

    /**
     * A grant made inside another operation's work that widens is refused, with
     * the hook never called; one that widens nothing goes ahead.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWideningNestedInAnotherOperationIsRefused(): void
    {
        $this->principals();

        $hook      = $this->hook();
        $principal = self::principal();
        $held      = Role::query()->create(['name' => 'held']);

        Role::query()->create(['name' => 'new-role']);

        self::grants()->grantRole($principal, $held);

        $outcome = OperationScope::run(Operation::begin(), static fn (): GrantOutcome => self::grants()->grantRole($principal, $held));

        self::assertSame(GrantOutcome::UNCHANGED, $outcome);

        try {
            OperationScope::run(Operation::begin(), static fn (): GrantOutcome => self::grants()->grantRole($principal, 'new-role'));

            self::fail('The nested grant was made.');
        } catch (NestedGrantException) {
            self::assertCount(1, $hook->widenings);
        }

        self::assertFalse($principal->fresh()?->hasRole('new-role'));
    }

    /**
     * A hook that calls a management service, a grant or any other operation,
     * is refused with the recursion guard, and the grant it was called for goes
     * ahead without what the hook tried.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANestedCallMadeFromTheHookIsRefusedAsRecursion(): void
    {
        $this->principals();

        $principal = self::principal();
        $refusals  = new \ArrayObject;

        Role::query()->create(['name' => 'new-role']);
        Role::query()->create(['name' => 'other-role']);

        $this->hook(static function () use ($principal, $refusals): void {
            try {
                self::grants()->grantRole($principal, 'other-role');
            } catch (GrantHookRecursionException $refusal) {
                $refusals->append($refusal);
            }

            try {
                OperationScope::run(Operation::begin(), static fn (): bool => true);
            } catch (GrantHookRecursionException $refusal) {
                $refusals->append($refusal);
            }
        });

        self::grants()->grantRole($principal, 'new-role');

        self::assertCount(2, $refusals);
        $fresh = self::principal();

        self::assertTrue($fresh->hasRole('new-role'));
        self::assertFalse($fresh->hasRole('other-role'));
    }

    /**
     * A hook may read: the grant scope query answers from inside it, and the
     * guard is lifted once the hook returns, or throws.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAHookMayQueryAndTheGuardIsLiftedAfterIt(): void
    {
        [$person] = $this->principals();

        $principal = self::principal();

        /** @var \ArrayObject<int, string> $answers */
        $answers = new \ArrayObject;

        $this->hook(static function (GrantWidening $widening) use ($answers): void {
            $answers->append(app(GrantScopeQuery::class)->forIdentity($widening->identity, self::tenant('acct1'))->value);
        });

        self::grants()->grantRole($principal, Role::query()->create(['name' => 'new']));

        self::assertSame(['within'], $answers->getArrayCopy());

        $this->app?->instance(GrantHook::class, new RefusingGrantHook);

        try {
            self::grants()->grantRole($person, Role::query()->create(['name' => 'refused']));
        } catch (GrantRefusedException) {
            // The guard must be lifted after a hook that throws.
        }

        self::assertSame(GrantOutcome::GRANTED, OperationScope::run(Operation::begin(), static fn (): GrantOutcome => GrantOutcome::GRANTED));
    }

    /**
     * The hook of a delegated grant runs before the package takes its first
     * lock for the call, inside the call's transaction, with nothing written;
     * the locks follow it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheHookRunsBeforeTheFirstLock(): void
    {
        $actor = self::administrator();

        $this->principals();

        $principal = self::principal();
        $role      = Role::query()->create(['name' => 'new']);
        $locks     = $this->recordRowLocks();

        /** @var \ArrayObject<int, list<int|string|null>> $seen */
        $seen = new \ArrayObject;

        $this->hook(static function () use ($locks, $seen, $principal): void {
            $seen->append([\count($locks), DB::transactionLevel(), $principal->roles()->count(), OperationScope::pins()?->phase()->name]);
        });

        self::grants()->grantRole($principal, $role, actor: $actor, tenant: self::tenant('acct1'));

        self::assertSame([[0, 2, 0, 'ACTOR']], $seen->getArrayCopy());
        self::assertGreaterThan(0, \count($locks));
    }

    /**
     * A veto rolls the whole call back: nothing is written, a sync's
     * revocations included, and no event is dispatched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVetoRollsEverythingBack(): void
    {
        $this->principals();

        $principal = self::principal();
        $held      = Role::query()->create(['name' => 'held']);

        self::grants()->grantRole($principal, $held, tenant: self::tenant('acct1'));

        $refusing = new RefusingGrantHook;

        $this->app?->instance(GrantHook::class, $refusing);

        $events = new \ArrayObject;

        Event::listen(RoleAssigned::class, static fn (RoleAssigned $event) => $events->append($event));

        try {
            self::grants()->syncRoles($principal, [Role::query()->create(['name' => 'new']), Role::query()->create(['name' => 'second'])], tenant: self::tenant('acct2'));

            self::fail('The sync was made.');
        } catch (GrantRefusedException $refusal) {
            self::assertSame('Refused by the test hook.', $refusal->getMessage());
        }

        self::assertSame(1, $refusing->refused);
        self::assertSame([GrantChanges::key($held)], self::rolesOf($principal));
        self::assertCount(0, $events);
    }

    /**
     * A grant that widened nothing as the hook phase read it, but widens once a
     * grant the classification relied on is gone, conflicts and is tried again
     * from the start, the hook running on the retry; trusted and delegated
     * alike.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARaceThatTurnsAGrantWideningIsTriedAgainWithTheHook(): void
    {
        $actor = self::administrator();

        [, [$first, $second]] = $this->principals();

        $hook = $this->hook();

        foreach (['trusted' => null, 'delegated' => $actor] as $mode => $acting) {
            $evidence = Role::query()->create(['name' => 'evidence-' . $mode]);

            self::grants()->grantRole($second, $evidence, tenant: self::tenant($mode));

            self::revokeOnFirstClassification($second, $evidence, self::tenant($mode));

            $outcome = self::grants()->grantRole($first, Role::query()->create(['name' => 'new-' . $mode]), actor: $acting, tenant: self::tenant($mode), includeSubtree: false);

            self::assertSame(GrantOutcome::GRANTED, $outcome, $mode);
        }

        self::assertSame([[WideningReason::NEW_TENANT->value], [WideningReason::NEW_TENANT->value]], $hook->reasons());
    }

    /**
     * A trusted grant whose coverage conflicts on every try is refused as a
     * conflict once the retries are spent, with nothing written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATrustedGrantThatConflictsOnEveryTryIsRefused(): void
    {
        [, [$first, $second]] = $this->principals();

        $this->hook();

        config(['authorization.administration.retries' => 1]);

        $evidence = Role::query()->create(['name' => 'evidence']);

        self::grants()->grantRole($second, $evidence, tenant: self::tenant('acct1'));

        DB::listen(static function (QueryExecuted $query) use ($second, $evidence): void {
            if (!\str_contains($query->sql, 'grant_roots')) {
                return;
            }

            $table = GrantChanges::table(GrantTarget::ROLE, Reference::of($second), null, new GrantScope(self::tenant('acct1'), null, true));
            $rows  = $table->live([GrantChanges::key($evidence)]);

            $rows === [] ? $table->grant(GrantChanges::key($evidence), null) : $table->revoke($rows);
        });

        try {
            self::grants()->grantRole($first, Role::query()->create(['name' => 'new']), tenant: self::tenant('acct1'), includeSubtree: false);

            self::fail('The grant was made.');
        } catch (AuthorizationException $refusal) {
            self::assertSame('administration.conflict', $refusal->getReason()->value);
        }

        self::assertSame([], self::rolesOf($first));
    }

    /**
     * A sync proposes each target it keeps that the grantee does not hold live,
     * with the sync's expiry, and nothing for one held live.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASyncProposesWhatItDoesNotHoldLive(): void
    {
        $this->principals();

        $principal = self::principal();
        $held      = Role::query()->create(['name' => 'held']);
        $expired   = Role::query()->create(['name' => 'expired']);
        $new       = Role::query()->create(['name' => 'new']);
        $scope     = new GrantScope(self::tenant('acct1'), null, true);
        $expiresAt = Carbon::now('UTC')->addDay()->startOfSecond();

        self::grants()->grantRole($principal, $held, tenant: self::tenant('acct1'));
        self::grants()->grantRole($principal, $expired, Carbon::now('UTC')->addHour(), tenant: self::tenant('acct1'));

        $this->travel(2)->hours();

        $table     = GrantChanges::table(GrantTarget::ROLE, Reference::of($principal), null, $scope);
        $proposals = WideningPhase::additions(GrantTarget::ROLE, $expiresAt, $scope, $table, [
            GrantChanges::key($held)    => $held,
            GrantChanges::key($expired) => $expired,
            GrantChanges::key($new)     => $new,
        ]);

        self::assertSame([GrantChanges::key($expired), GrantChanges::key($new)], \array_map(static fn (ProposedGrant $proposal): string => $proposal->target->id, $proposals));
        self::assertSame($expiresAt->getTimestamp(), $proposals[0]->expiresAt?->getTimestamp());
        self::assertSame('acct1', $proposals[1]->tenant?->id);
    }

    /**
     * Revoke the grantee's evidence role once, right after the hook phase's
     * classification reads the grants, so the final classification finds it
     * gone.
     *
     * @param  \Tests\Feature\Stubs\StubSecondIdentity  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $evidence
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return void
     */
    private static function revokeOnFirstClassification(StubSecondIdentity $grantee, Role $evidence, Reference $tenant): void
    {
        $armed = new \ArrayObject([true]);

        DB::listen(static function (QueryExecuted $query) use ($grantee, $evidence, $tenant, $armed): void {
            if ($armed[0] !== true || !\str_contains($query->sql, 'grant_roots')) {
                return;
            }

            $armed[0] = false;

            GrantChanges::table(GrantTarget::ROLE, Reference::of($grantee), null, new GrantScope($tenant, null, true))->revoke([GrantChanges::key($evidence)]);
        });
    }

    /**
     * Return the keys of the roles the grantee holds, in every scope.
     *
     * @param  \Tests\Feature\Stubs\StubSecondIdentity  $grantee
     * @return list<string>
     */
    private static function rolesOf(StubSecondIdentity $grantee): array
    {
        $keys = DB::table('authorizable_roles')
            ->where('authorizable_type', $grantee->getMorphClass())
            ->where('authorizable_id', $grantee->getKey())
            ->pluck('role_id')
            ->all();

        return \array_values(\array_map(static fn (mixed $key): string => \is_scalar($key) ? (string) $key : '', $keys));
    }

    /**
     * Return the proposed platform-wide grant of the role.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return \SineMacula\Laravel\Authorization\Hooks\ProposedGrant
     */
    private static function proposal(Role $role): ProposedGrant
    {
        return ProposedGrant::of(GrantTarget::ROLE, $role, GrantScope::platform(), null);
    }

    /**
     * Return the first principal, created when there is none.
     *
     * @return \Tests\Feature\Stubs\StubSecondIdentity
     */
    private static function principal(): StubSecondIdentity
    {
        /** @var \Tests\Feature\Stubs\StubSecondIdentity */
        return StubSecondIdentity::query()->firstOrCreate(['id' => 'p1']);
    }

    /**
     * Return the grant service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService
     */
    private static function grants(): GrantService
    {
        /** @var \SineMacula\Laravel\Authorization\Services\GrantService */
        return app(GrantService::class);
    }
}
