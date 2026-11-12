<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Events\Role\ExclusionDeclared;
use SineMacula\Laravel\Authorization\Events\Role\ExclusionRemoved;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidRoleExclusionException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\OwnerMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\RoleExclusionConflictException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Exceptions\UnsavedRecordException;
use SineMacula\Laravel\Authorization\Exceptions\UnwrittenGrantException;
use SineMacula\Laravel\Authorization\Exclusions\RoleExclusion;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\RoleExclusionService;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsAdministrator;
use Tests\Concerns\ActsAsTenant;
use Tests\Concerns\AssertsDelegatedRefusals;
use Tests\Concerns\CatchesRefusals;
use Tests\Concerns\ComparesReferences;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Concerns\RecordsRowLocks;
use Tests\Concerns\RefusesThePackage;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\Fixtures\GrantScope\ListedIdentityDirectory;
use Tests\TestCase;

/**
 * Feature tests for `RoleExclusionService`, which declares, removes and lists
 * pairs of mutually exclusive roles and reports who holds both.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(RoleExclusionService::class)]
final class RoleExclusionServiceTest extends TestCase
{
    use ActsAsAdministrator, ActsAsTenant, AssertsDelegatedRefusals, CatchesRefusals, ComparesReferences, ReadsDispatchedEvents, RecordsRowLocks,
        RefusesThePackage;

    /**
     * A pair is declared once whichever order its roles are given in, by name
     * or by model, stored in its canonical order, the lower key first, with its
     * owner, who declared it and when; declaring it again changes nothing, and
     * only a new pair is reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeclaresAPairOnceInEitherOrder(): void
    {
        [$clerk, $auditor] = self::roles();
        [$first, $second]  = self::ordered($clerk, $auditor);

        Event::fake([ExclusionDeclared::class]);

        self::assertSame(GrantOutcome::GRANTED, self::service()->declare('clerk', $auditor));
        self::assertSame(GrantOutcome::UNCHANGED, self::service()->declare($auditor, 'clerk'));
        self::assertSame(GrantOutcome::UNCHANGED, self::service()->declare($clerk, $auditor));

        $row = (array) DB::table('role_exclusions')->sole();

        self::assertSame([$first->id, $second->id], [$row['role_id'], $row['excluded_role_id']]);
        self::assertNull($row['tenant_type']);
        self::assertNull($row['granted_by_type']);

        $events = self::dispatchedEvents(ExclusionDeclared::class);

        self::assertCount(1, $events);
        self::assertTrue(self::refersTo($events[0]->role, $first));
        self::assertSame($first->name, $events[0]->roleName);
        self::assertTrue(self::refersTo($events[0]->excludedRole, $second));
        self::assertSame($second->name, $events[0]->excludedRoleName);
        self::assertNull($events[0]->tenant);
        self::assertTrue($events[0]->operation->isTrusted);
        self::assertSame([PackagePermissions::ROLE_EXCLUSION_DECLARE], $events[0]->operation->actions);
    }

    /**
     * A pair is removed whichever order its roles are given in, reported once,
     * and removing one that is not declared changes nothing and reports
     * nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovesAPair(): void
    {
        [$clerk, $auditor] = self::roles();
        [$first, $second]  = self::ordered($clerk, $auditor);

        self::service()->declare($clerk, $auditor);

        Event::fake([ExclusionRemoved::class]);

        self::assertTrue(self::service()->remove('auditor', $clerk));
        self::assertFalse(self::service()->remove($clerk, 'auditor'));
        self::assertSame(0, DB::table('role_exclusions')->count());

        $events = self::dispatchedEvents(ExclusionRemoved::class);

        self::assertCount(1, $events);
        self::assertTrue(self::refersTo($events[0]->role, $first));
        self::assertSame($first->name, $events[0]->roleName);
        self::assertTrue(self::refersTo($events[0]->excludedRole, $second));
        self::assertSame($second->name, $events[0]->excludedRoleName);
        self::assertSame([PackagePermissions::ROLE_EXCLUSION_REMOVE], $events[0]->operation->actions);
    }

    /**
     * A role is never paired with itself, an unknown name or an unsaved role is
     * refused, and so is a role naming half a tenant, each before anything is
     * written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesARolePairedWithItselfOrUnknown(): void
    {
        [$clerk] = self::roles();

        $half = Role::query()->create(['name' => 'half']);

        DB::table('roles')->where('id', $half->id)->update(['tenant_type' => 'stub_tenant']);

        $half = Role::query()->withoutGlobalScopes()->findOrFail($half->id);

        self::assertInstanceOf(InvalidRoleExclusionException::class, self::refusalOf(static fn () => self::service()->declare($clerk, 'clerk')));
        self::assertInstanceOf(InvalidRoleExclusionException::class, self::refusalOf(static fn () => self::service()->remove($clerk, $clerk)));
        self::assertInstanceOf(InvalidRoleExclusionException::class, self::refusalOf(static fn () => self::service()->conflicts($clerk, $clerk)));
        self::assertInstanceOf(UnknownRoleException::class, self::refusalOf(static fn () => self::service()->declare($clerk, 'nobody')));
        self::assertInstanceOf(UnknownRoleException::class, self::refusalOf(static fn () => self::service()->pairs('nobody')));
        self::assertInstanceOf(UnsavedRecordException::class, self::refusalOf(static fn () => self::service()->declare(new Role(['name' => 'draft']), $clerk)));
        self::assertInstanceOf(InvalidTenantColumnsException::class, self::refusalOf(static fn () => self::service()->declare($clerk, $half)));
        self::assertSame(0, DB::table('role_exclusions')->count());
    }

    /**
     * A role whose row is gone by the time the pair is written is refused: read
     * again under the lock for trusted work, as stored for a delegated change.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARoleGoneBeforeTheWriteIsRefused(): void
    {
        [$clerk, $auditor] = self::roles();

        $actor = self::administrator();

        DB::table('roles')->where('id', $auditor->id)->delete();

        $trusted = self::refusalOf(static fn () => self::service()->declare($clerk, $auditor));

        self::assertInstanceOf(UnknownRoleException::class, $trusted);
        self::assertSame('auditor', $trusted->getRole());
        self::assertInstanceOf(InvalidGrantTargetException::class, self::refusalOf(static fn () => self::service()->declare($clerk, $auditor, $actor)));

        [$first, $second] = self::ordered(Role::query()->create(['name' => 'payer']), Role::query()->create(['name' => 'keeper']));

        DB::table('roles')->where('id', $first->id)->delete();

        $gone = self::refusalOf(static fn () => self::service()->declare($second, $first));

        self::assertInstanceOf(UnknownRoleException::class, $gone);
        self::assertSame($first->name, $gone->getRole());
        self::assertSame(0, DB::table('role_exclusions')->count());
    }

    /**
     * A pair is owned by the owner of its role owned furthest down: the
     * platform for two platform roles, a tenant for its own role paired with
     * the platform's or its ancestor's; roles of two tenants neither within the
     * other are never paired.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPairIsOwnedByItsRoleOwnedFurthestDown(): void
    {
        [$parent, $child, $sibling] = \array_map(self::createTenant(...), ['parent', 'child', 'sibling']);

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($child), Reference::of($parent))->put(Reference::of($sibling), Reference::of($parent)));

        $platform = Role::query()->create(['name' => 'platform']);
        $above    = Role::query()->withoutGlobalScopes()->create(['name' => 'above', ...self::ownedBy($parent)]);
        $below    = Role::query()->withoutGlobalScopes()->create(['name' => 'below', ...self::ownedBy($child)]);
        $beside   = Role::query()->withoutGlobalScopes()->create(['name' => 'beside', ...self::ownedBy($sibling)]);

        self::service()->declare($below, $platform);
        self::service()->declare($above, $below);
        self::service()->declare($above, $platform);

        $owners = [];

        foreach (self::service()->pairs() as $pair) {
            /** @var list<string> $names */
            $names = Role::query()->withoutGlobalScopes()->whereKey([$pair->role->id, $pair->excludedRole->id])->orderBy('name')->pluck('name')->all();

            $owners[\implode('+', $names)] = $pair->tenant?->id;
        }

        \ksort($owners);

        self::assertSame(['above+below' => 'child', 'above+platform' => 'parent', 'below+platform' => 'child'], $owners);

        $mismatch = self::refusalOf(static fn () => self::service()->declare($below, $beside));

        self::assertInstanceOf(OwnerMismatchException::class, $mismatch);
        self::assertSame('excluded role', $mismatch->getRelatedKind());
    }

    /**
     * A pair is removed on the owner it was stored with, by a trusted call or
     * by an actor in that owner's context, after the tree moves its roles'
     * owners apart, and the removal is reported with that owner.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPairStaysRemovableAfterTheTreeMovesItsOwnersApart(): void
    {
        [$parent, $child, $other] = \array_map(self::createTenant(...), ['parent', 'child', 'other']);

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($child), Reference::of($parent)));

        $above  = Role::query()->withoutGlobalScopes()->create(['name' => 'above', ...self::ownedBy($parent)]);
        $beside = Role::query()->withoutGlobalScopes()->create(['name' => 'beside', ...self::ownedBy($parent)]);
        $below  = Role::query()->withoutGlobalScopes()->create(['name' => 'below', ...self::ownedBy($child)]);

        self::service()->declare($above, $below);
        self::service()->declare($beside, $below);

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($child), Reference::of($other)));

        $admin = self::administrator();

        Event::fake([ExclusionRemoved::class]);

        self::assertTrue(self::service()->remove($above, $below));

        $this->actAsTenant($child);

        self::assertTrue(self::service()->remove($below, $beside, $admin));
        self::assertSame([], self::service()->pairs());

        foreach (self::dispatchedEvents(ExclusionRemoved::class) as $event) {
            self::assertSame([$child->getMorphClass(), 'child'], [$event->tenant?->type, $event->tenant?->id]);
        }

        self::assertCount(2, self::dispatchedEvents(ExclusionRemoved::class));
    }

    /**
     * A delegated declaration or removal locks both roles' rows before it is
     * decided, under the concurrency protocol of delegated administration.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedChangeLocksBothRolesBeforeItIsDecided(): void
    {
        [$clerk, $auditor] = self::roles();

        $admin  = self::administrator();
        $locks  = $this->recordRowLocks();
        $before = [];

        Event::listen(DecisionEvaluated::class, static function () use ($locks, &$before): void {
            $before[] = \array_slice($locks->getArrayCopy(), 0);
        });

        self::service()->declare($clerk, $auditor, $admin);
        self::service()->remove($clerk, $auditor, $admin);

        $pair = [$clerk->id, $auditor->id];

        \sort($pair);

        self::assertCount(2, $before);

        foreach ($before as $taken) {
            $roles = \array_map(static function (array $lock): array {
                \sort($lock[1]);

                return $lock[1];
            }, \array_filter($taken, static fn (array $lock): bool => $lock[0] === 'roles'));

            self::assertContains($pair, $roles);

            $locks->exchangeArray([]);
        }
    }

    /**
     * The report a declaration reads sees a grant committed after its
     * transaction first read, as each row it reads is read locked, so a pair
     * someone came to hold both roles of meanwhile is still refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheReportSeesAGrantCommittedAfterTheDeclarationBegan(): void
    {
        $connection = DB::connection();

        if ($connection->getDriverName() === 'sqlite') {
            self::markTestSkipped('SQLite has one writer, so no grant commits while a declaration runs.');
        }

        config(['database.connections.bl71a_concurrent' => $connection->getConfig()]);

        try {
            self::assertInstanceOf(RoleExclusionConflictException::class, self::refusalOf(self::raced(...)));
        } finally {
            foreach (['role_exclusions', 'authorizable_roles', 'roles', 'stub_identities'] as $table) {
                DB::table($table)->delete();
            }

            DB::purge('bl71a_concurrent');
        }
    }

    /**
     * Declaring a pair someone holds both roles of, where their reach overlaps,
     * is refused with the conflict report, and nothing is written or removed;
     * once the conflict is resolved, the pair is declared. The report is read
     * under the locks the pair is written under, both roles locked first, in
     * key order, outside the tenant scope, the grants it reads locked too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeclaringIsRefusedWithTheReportWhileSomeoneHoldsBoth(): void
    {
        [$clerk, $auditor] = self::roles();
        [$first, $second]  = self::ordered($clerk, $auditor);

        $user = StubIdentity::query()->create(['id' => 'user']);

        self::grants()->grantRole($user, $clerk);
        self::grants()->grantRole($user, $auditor);

        $this->actAsTenant(self::createTenant('tenant-a'));

        $locks   = $this->recordRowLocks();
        $refusal = self::refusalOf(static fn () => self::service()->declare($clerk, $auditor));

        self::assertInstanceOf(RoleExclusionConflictException::class, $refusal);
        self::assertSame(['roles', [$first->id, $second->id]], $locks[0] ?? null);
        self::assertContains('authorizable_roles', $this->lockedTables(static fn () => self::refusalOf(static fn () => self::service()->declare($clerk, $auditor))));
        self::assertTrue(self::refersTo($refusal->getReport()->role, $first));
        self::assertSame(['user'], \array_map(static fn (Reference $holder): string => $holder->id, $refusal->getReport()->holders()));
        self::assertSame(0, DB::table('role_exclusions')->count());
        self::assertSame(2, DB::table('authorizable_roles')->count());

        self::grants()->revokeRole($user, $auditor);

        self::assertSame(GrantOutcome::GRANTED, self::service()->declare($clerk, $auditor));
        self::assertSame(1, DB::table('authorizable_roles')->count());
    }

    /**
     * Return the trees and grants of the report's holding cases, each with the
     * tenants a check sees both roles held in.
     *
     * @return iterable<string, array{bool, bool, list<string>}>
     */
    public static function trees(): iterable
    {
        yield from [
            'grants below the owner, reaching below' => [false, true, ['grants']],
            'grants below the owner, limited'        => [false, false, ['grants']],
            'grants above the owner, reaching below' => [true, true, ['owner']],
            'grants above the owner, limited'        => [true, false, []],
        ];
    }

    /**
     * The report finds a holding wherever a check sees both roles held, and
     * nowhere else: with the grants' tenant below the owner of a role, and with
     * it above the owner when the grants reach below it; declaring is refused
     * exactly then.
     *
     * @param  bool  $isInverted
     * @param  bool  $includeSubtree
     * @param  list<string>  $held
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('trees')]
    public function testTheReportFindsAHoldingWhereverACheckSeesIt(bool $isInverted, bool $includeSubtree, array $held): void
    {
        [$grants, $owner] = \array_map(self::createTenant(...), ['grants', 'owner']);
        [$below, $above]  = $isInverted ? [$owner, $grants] : [$grants, $owner];

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($below), Reference::of($above)));

        $approver  = Role::query()->withoutGlobalScopes()->create(['name' => 'approver', ...self::ownedBy($owner)]);
        $requester = Role::query()->create(['name' => 'requester']);
        $approve   = Permission::query()->create(['name' => 'approve']);
        $user      = StubIdentity::query()->create(['id' => 'user']);

        DB::table('role_permissions')->insert(['role_id' => $approver->id, 'permission_id' => $approve->id]);

        foreach ([$approver, $requester] as $role) {
            DB::table('authorizable_roles')->insert([
                'role_id'           => $role->id,
                'authorizable_type' => $user->getMorphClass(),
                'authorizable_id'   => 'user',
                'tenant_type'       => $grants->getMorphClass(),
                'tenant_id'         => 'grants',
                'include_subtree'   => $includeSubtree,
            ]);
        }

        $seen = [];

        foreach (['grants' => $grants, 'owner' => $owner] as $name => $tenant) {
            $this->actAsTenant($tenant);

            $checked = StubIdentity::query()->findOrFail('user');

            if (!$checked->hasPermission('approve') || !$checked->hasRole('requester')) {
                continue;
            }

            $seen[] = $name;
        }

        $this->actAsTenant(null);

        self::assertSame($held, $seen);
        self::assertCount($held === [] ? 0 : 1, self::service()->conflicts($approver, $requester)->conflicts);
        self::assertSame($held !== [], self::isRefusedForAConflict(static fn () => self::service()->declare($approver, $requester)));
        self::assertSame($held === [] ? 1 : 0, DB::table('role_exclusions')->count());
    }

    /**
     * A pair is declared once the report finds no conflict, and a row that
     * could not be written or found once tried again is refused rather than
     * reported declared.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPairWhoseRowIsNeverWrittenIsRefused(): void
    {
        [$clerk, $auditor] = self::roles();
        [$first, $second]  = self::ordered($clerk, $auditor);

        $isInserting = false;
        $isPair      = static fn (QueryExecuted $query, string $start): bool => \str_contains($query->sql, 'role_exclusions') && \str_starts_with(\strtolower($query->sql), $start);

        // The pair is written by a concurrent call once it is found missing,
        // then removed again once the insert has been ignored for it.
        DB::listen(static function (QueryExecuted $query) use ($first, $second, $isPair, &$isInserting): void {
            $sql = \strtolower($query->sql);

            if ($isInserting || !$isPair($query, 'insert') || (!\str_contains($sql, 'ignore') && !\str_contains($sql, 'on conflict'))) {
                return;
            }

            $isInserting = true;

            DB::table('role_exclusions')->where('role_id', $first->id)->where('excluded_role_id', $second->id)->delete();
        });

        DB::listen(static function (QueryExecuted $query) use ($first, $second, $isPair, &$isInserting): void {
            if ($isInserting || !$isPair($query, 'select exists')) {
                return;
            }

            $isInserting = true;

            DB::table('role_exclusions')->insert(['role_id' => $first->id, 'excluded_role_id' => $second->id]);

            $isInserting = false;
        });

        $refusal = self::refusalOf(static fn () => self::service()->declare($clerk, $auditor));

        self::assertInstanceOf(UnwrittenGrantException::class, $refusal);
        self::assertSame('role exclusion of ' . $first->name, $refusal->getGrant());
    }

    /**
     * A delegated declaration or removal is decided under its action before
     * anything is written, whether or not there is anything to change, and a
     * pair declared or removed by an actor allowed it is reported with the
     * actor and the operation its decision was made on.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedChangeIsDecidedUnderItsAction(): void
    {
        [$clerk, $auditor] = self::roles();

        $nobody = self::administrator([], 'nobody', null);
        $admin  = self::administrator();

        self::assertDelegatedRefusal(DecisionReason::NO_MATCH, static fn () => self::service()->declare($clerk, $auditor, $nobody));
        self::assertSame([PackagePermissions::ROLE_EXCLUSION_DECLARE], self::actionsDecided());
        self::assertDelegatedRefusal(DecisionReason::NO_MATCH, static fn () => self::service()->remove($clerk, $auditor, $nobody));
        self::assertSame([PackagePermissions::ROLE_EXCLUSION_REMOVE], self::actionsDecided());

        self::fakePackageEvents();

        self::assertSame(GrantOutcome::GRANTED, self::service()->declare($clerk, $auditor, $admin));
        self::assertTrue(self::service()->remove($clerk, $auditor, $admin));

        $declared = self::dispatchedEvents(ExclusionDeclared::class)[0]           ?? null;
        $removed  = self::dispatchedEvents(ExclusionRemoved::class)[0]            ?? null;
        $resource = self::dispatchedEvents(DecisionEvaluated::class)[0]->resource ?? null;

        self::assertNotNull($declared);
        self::assertNotNull($removed);
        self::assertFalse($declared->operation->isTrusted);
        self::assertTrue(self::refersTo($declared->operation->actor, $admin->principal()));
        self::assertSame('authorization:operation:' . $declared->operation->id, $resource);
        self::assertNotSame($declared->operation->id, $removed->operation->id);
        self::assertSame(0, DB::table('role_exclusions')->count());
    }

    /**
     * A delegated declaration records the actor on the row, and is made only
     * from the tenant that owns the pair, of roles junior to the actor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedChangeFollowsTheOwnerAndRankRules(): void
    {
        $tenant = self::createTenant('tenant-a');
        $owned  = Role::query()->withoutGlobalScopes()->create(['name' => 'owned', ...self::ownedBy($tenant)]);
        $clerk  = Role::query()->create(['name' => 'clerk', 'rank' => 9]);
        $chief  = Role::query()->create(['name' => 'chief', 'rank' => 0]);
        $admin  = self::administrator(rank: 1);

        self::assertDelegatedRefusal(DecisionReason::ADMINISTRATION_OWNER, static fn () => self::service()->declare($owned, $clerk, $admin));
        self::assertDelegatedRefusal(DecisionReason::ADMINISTRATION_RANK, static fn () => self::service()->declare($chief, $clerk, $admin));

        $this->actAsTenant($tenant);

        self::assertSame(GrantOutcome::GRANTED, self::service()->declare($owned, $clerk, $admin));

        $row = (array) DB::table('role_exclusions')->sole();

        self::assertSame([$tenant->getMorphClass(), 'tenant-a'], [$row['tenant_type'], $row['tenant_id']]);
        self::assertSame([$admin->principal()->type, 'admin-1'], [$row['granted_by_type'], $row['granted_by_id']]);
    }

    /**
     * The pairs are listed in their canonical order, every one or those naming
     * a role, each with its owner, who declared it and when; the report of a
     * pair is read whether or not it is declared, and the report of every pair
     * finds a conflict a grant made after the pair left behind.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testListsThePairsAndReportsTheirConflicts(): void
    {
        [$clerk, $auditor] = self::roles();

        $payer = Role::query()->create(['name' => 'payer']);
        $user  = StubIdentity::query()->create(['id' => 'user']);

        self::service()->declare($clerk, $auditor);
        self::service()->declare($payer, $auditor);

        self::assertCount(2, self::service()->pairs());
        self::assertCount(1, self::service()->pairs('payer'));
        self::assertCount(2, self::service()->pairs($auditor));
        self::assertSame([], self::service()->pairs(Role::query()->create(['name' => 'idle'])));

        $pair = self::service()->pairs('payer')[0];

        self::assertInstanceOf(RoleExclusion::class, $pair);
        self::assertNotNull($pair->createdAt);
        self::assertTrue(self::service()->conflicts($clerk, $payer)->isEmpty());

        self::grants()->grantRole($user, $clerk);
        self::grants()->grantRole($user, $payer);
        self::grants()->grantRole($user, $auditor, application: 'admin');

        $reports = self::service()->conflictsForAll();

        self::assertCount(2, $reports);
        self::assertFalse(self::service()->conflicts($payer, $clerk)->isEmpty());

        foreach ($reports as $index => $report) {
            self::assertSame(self::service()->pairs()[$index]->role->id, $report->role->id);
            self::assertSame(['user'], \array_map(static fn (Reference $holder): string => $holder->id, $report->holders()));
        }
    }

    /**
     * The report reads the bound identity directory, so a principal holding one
     * role through its identity conflicts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheReportReadsTheBoundIdentityDirectory(): void
    {
        [$clerk, $auditor] = self::roles();

        $person = StubIdentity::query()->create(['id' => 'person']);
        $member = StubSecondIdentity::query()->create(['id' => 'member']);

        self::grants()->grantRole($person, $clerk);
        self::grants()->grantRole($member, $auditor);

        self::assertTrue(self::service()->conflicts($clerk, $auditor)->isEmpty());

        $this->app?->instance(IdentityDirectory::class, new ListedIdentityDirectory([
            ListedIdentityDirectory::key(Reference::of($person)) => [Reference::of($member)],
        ]));

        self::assertSame(['member'], \array_map(static fn (Reference $holder): string => $holder->id, self::service()->conflicts($clerk, $auditor)->holders()));
        self::assertInstanceOf(RoleExclusionConflictException::class, self::refusalOf(static fn () => self::service()->declare($clerk, $auditor)));
    }

    /**
     * Deleting a role takes its pairs with it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARoleDeletedTakesItsPairsWithIt(): void
    {
        [$clerk, $auditor] = self::roles();

        self::service()->declare($clerk, $auditor);
        $clerk->delete();

        self::assertSame([], self::service()->pairs());
    }

    /**
     * Once the package refuses, every operation of the service refuses by its
     * own guard, before it reads or writes anything.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryOperationRefusesOnceThePackageRefuses(): void
    {
        [$clerk, $auditor] = self::roles();

        $service = $this->container()->make(RoleExclusionService::class);

        $this->refuseThePackage();

        $this->assertEachRefused([
            'declare'         => static fn () => $service->declare($clerk, $auditor),
            'remove'          => static fn () => $service->remove($clerk, $auditor),
            'pairs'           => static fn () => $service->pairs(),
            'conflicts'       => static fn () => $service->conflicts($clerk, $auditor),
            'conflictsForAll' => static fn () => $service->conflictsForAll(),
        ]);
    }

    /**
     * The service is bound as a singleton.
     *
     * @return void
     */
    public function testIsBoundAsASingleton(): void
    {
        self::assertSame(RoleExclusionService::instance(), app(RoleExclusionService::class));
    }

    /**
     * Run the race outside the test's transaction, so the declaration sees what
     * another session commits; SQLite, which skips it, keeps its transaction.
     *
     * @return list<string|null>
     */
    #[\Override]
    protected function connectionsToTransact(): array
    {
        $isRaced = $this->name() === 'testTheReportSeesAGrantCommittedAfterTheDeclarationBegan' && DB::connection()->getDriverName() !== 'sqlite';

        /** @var list<string|null> $connections */
        $connections = parent::connectionsToTransact();

        return $isRaced ? [] : $connections;
    }

    /**
     * Declare a pair one holder holds one role of, while another session grants
     * the holder the other role and commits once the declaration's transaction
     * has first read.
     *
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    private static function raced(): GrantOutcome
    {
        [$clerk, $auditor] = self::roles();

        $user    = StubIdentity::query()->create(['id' => 'user']);
        $isRaced = false;
        $package = DB::connection();

        self::grants()->grantRole($user, $clerk);

        DB::listen(static function (QueryExecuted $query) use ($package, $auditor, $user, &$isRaced): void {
            if ($isRaced || $query->connectionName !== $package->getName() || $package->transactionLevel() === 0 || !\str_starts_with(\strtolower($query->sql), 'select')) {
                return;
            }

            $isRaced = true;

            DB::connection('bl71a_concurrent')->table('authorizable_roles')->insert([
                'role_id'           => $auditor->id,
                'authorizable_type' => $user->getMorphClass(),
                'authorizable_id'   => 'user',
                'include_subtree'   => true,
            ]);
        });

        return self::service()->declare('clerk', 'auditor');
    }

    /**
     * Determine whether the declaration was refused for a conflict.
     *
     * @param  \Closure(): mixed  $declare
     * @return bool
     */
    private static function isRefusedForAConflict(\Closure $declare): bool
    {
        try {
            $declare();
        } catch (RoleExclusionConflictException) {
            return true;
        }

        return false;
    }

    /**
     * Return the role exclusion service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\RoleExclusionService
     */
    private static function service(): RoleExclusionService
    {
        return app(RoleExclusionService::class);
    }

    /**
     * Return the grant service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService
     */
    private static function grants(): GrantService
    {
        return app(GrantService::class);
    }

    /**
     * Return two platform roles, `clerk` and `auditor`.
     *
     * @return array{0: \SineMacula\Laravel\Authorization\Models\Role, 1: \SineMacula\Laravel\Authorization\Models\Role}
     */
    private static function roles(): array
    {
        return [Role::query()->create(['name' => 'clerk']), Role::query()->create(['name' => 'auditor'])];
    }

    /**
     * Return the two roles in a pair's order, the lower key first.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $one
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $other
     * @return array{0: \SineMacula\Laravel\Authorization\Models\Role, 1: \SineMacula\Laravel\Authorization\Models\Role}
     */
    private static function ordered(Role $one, Role $other): array
    {
        return \strcmp($one->id, $other->id) < 0 ? [$one, $other] : [$other, $one];
    }
}
