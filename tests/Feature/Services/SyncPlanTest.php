<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Events\Identity\RoleAssigned;
use SineMacula\Laravel\Authorization\Events\Identity\RoleExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\RoleRevoked;
use SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException;
use SineMacula\Laravel\Authorization\Exceptions\RoleExclusionConflictException;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\Support\GrantChanges;
use SineMacula\Laravel\Authorization\Services\Support\GrantTable;
use SineMacula\Laravel\Authorization\Services\Support\RoleExclusionTable;
use SineMacula\Laravel\Authorization\Services\Support\SyncPlan;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\CatchesRefusals;
use Tests\TestCase;

/**
 * Feature tests for `SyncPlan`, what a sync of a grantee's rows of one kind
 * works from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(SyncPlan::class)]
final class SyncPlanTest extends TestCase
{
    use CatchesRefusals;

    /** @var string The instant every test starts at. */
    private const string NOW = '2026-07-01 12:00:00';

    /**
     * Freeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(self::NOW);
    }

    /**
     * Reset the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * Each key listed with a reach is written in the written scope's tenant and
     * application with that reach, a key listed with none is not, and the same
     * key listed with the same reach twice is listed once; on the platform,
     * every reach reaches below.
     *
     * @return void
     */
    public function testEachKeyListedWithAReachIsWrittenWithIt(): void
    {
        $tenant  = self::tenant();
        $written = new GrantScope($tenant, 'admin', true);
        $reaches = SyncPlan::reachesOf(GrantTarget::ROLE, $written, [['a', false], ['b', null], ['c', true], ['a', false], ['b', true]]);

        $below = new GrantScope($tenant, 'admin', true);

        self::assertEquals(['a' => new GrantScope($tenant, 'admin', false), 'c' => $below, 'b' => $below], $reaches);
        self::assertSame(['a', 'c', 'b'], \array_keys($reaches));
        self::assertEquals(['a' => new GrantScope(null, 'admin', true)], SyncPlan::reachesOf(GrantTarget::ROLE, new GrantScope(null, 'admin'), [['a', false]]));
        self::assertSame([], SyncPlan::reachesOf(GrantTarget::ROLE, $written, [['a', null]]));
        self::assertSame([], SyncPlan::reachesOf(GrantTarget::ROLE, $written, []));
    }

    /**
     * A key listed with both reaches is refused, naming the kind and the key,
     * whichever comes first; on the platform, where both reach below, it is
     * not.
     *
     * @return void
     */
    public function testAKeyListedWithBothReachesIsRefused(): void
    {
        $written = new GrantScope(self::tenant());

        foreach ([[['a', true], ['a', false]], [['a', false], ['b', true], ['a', true]]] as $listed) {
            try {
                SyncPlan::reachesOf(GrantTarget::PERMISSION, $written, $listed);
                self::fail('Both reaches were accepted.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('The permission [a] is listed with both reaches.', $exception->getMessage());
            }
        }

        self::assertCount(1, SyncPlan::reachesOf(GrantTarget::ROLE, GrantScope::platform(), [['a', true], ['a', false]]));
    }

    /**
     * The plan names the keys it keeps, in order, the held keys it drops, and
     * the scope each kept key is written in: the one its reach names, else the
     * written scope.
     *
     * @return void
     */
    public function testNamesWhatItKeepsDropsAndWhereEachIsWritten(): void
    {
        [$kept, $listed, $dropped] = [self::role('kept'), self::role('listed'), self::role('dropped')];

        $written = new GrantScope(self::tenant());
        $node    = new GrantScope(self::tenant(), null, false);
        $keep    = [$kept->id => $kept, $listed->id => $listed];
        $plan    = new SyncPlan(GrantTarget::ROLE, $written, self::table($written), $keep, [$kept->id, $dropped->id], [$listed->id => $node]);

        self::assertSame([$kept->id, $listed->id], $plan->kept());
        self::assertSame([$dropped->id], $plan->revoked());
        self::assertSame($written, $plan->scopeOf($kept->id));
        self::assertSame($node, $plan->scopeOf($listed->id));
        self::assertSame($written, $plan->scopeOf('absent'));
        self::assertSame([], (new SyncPlan(GrantTarget::ROLE, $written, self::table($written), []))->kept());
        self::assertSame([], (new SyncPlan(GrantTarget::ROLE, $written, self::table($written), []))->revoked());
    }

    /**
     * Writing grants a key not held with the reach it is written in, re-arms an
     * expired one, changes the reach of a key listed with one and held live
     * with the other, keeping its expiry, and leaves a key listed with none
     * held live with the other reach as it is; each event carries the scope
     * written and the expiry the row carries, and each outcome lists its keys.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWritesEachKeptKeyInItsScope(): void
    {
        [$fresh, $expired, $moved, $plain] = [self::role('fresh'), self::role('expired'), self::role('moved'), self::role('plain')];

        $written = new GrantScope(self::tenant());
        $node    = new GrantScope(self::tenant(), null, false);
        $kept    = Carbon::parse('2026-07-02 12:00:00', 'UTC');
        $synced  = Carbon::parse('2026-07-09 12:00:00', 'UTC');

        self::table($written)->grant($moved->id, $kept);
        self::table($written)->grant($expired->id, Carbon::parse('2026-06-30 12:00:00', 'UTC'));
        self::table($node)->grant($plain->id, null);

        $keep = [$fresh->id => $fresh, $expired->id => $expired, $moved->id => $moved, $plain->id => $plain];
        $plan = new SyncPlan(GrantTarget::ROLE, $written, self::table($written), $keep, [], [$fresh->id => $node, $expired->id => $node, $moved->id => $node]);

        [$events, $changed] = $plan->write(Operation::begin(), self::grantee(), $synced, Carbon::now('UTC'), []);

        self::assertSame(['granted' => [$fresh->id], 'rearmed' => [$expired->id], 'reach_changed' => [$moved->id], 'unchanged' => [$plain->id]], $changed);
        self::assertSame([$fresh->id => false, $expired->id => false, $moved->id => false, $plain->id => false], self::reaches([$fresh->id, $expired->id, $moved->id, $plain->id]));
        self::assertSame('2026-07-02 12:00:00', DB::table('authorizable_roles')->where('role_id', $moved->id)->value('expires_at'));
        self::assertSame(
            [
                [RoleAssigned::class, 'fresh', false, '2026-07-09 12:00:00'],
                [RoleAssigned::class, 'expired', false, '2026-07-09 12:00:00'],
                [RoleExpiryChanged::class, 'expired', false, null],
                [RoleAssigned::class, 'moved', false, '2026-07-02 12:00:00'],
            ],
            \array_map(static fn (object $event): array => match (true) {
                $event instanceof RoleAssigned      => [RoleAssigned::class, $event->name, $event->scope->includeSubtree, $event->expiresAt?->format('Y-m-d H:i:s')],
                $event instanceof RoleExpiryChanged => [RoleExpiryChanged::class, $event->name, $event->scope->includeSubtree, null],
                default                             => [$event::class],
            }, $events),
        );
    }

    /**
     * Writing a row decided as held live that the write changes, a reach
     * changed or a row gone and granted again, conflicts, so the call is tried
     * again; one left as it is does not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWritingARowDecidedAsLiveThatChangesConflicts(): void
    {
        $role    = self::role('editor');
        $written = new GrantScope(self::tenant());
        $node    = new GrantScope(self::tenant(), null, false);

        self::table($written)->grant($role->id, null);

        $unchanged = new SyncPlan(GrantTarget::ROLE, $written, self::table($written), [$role->id => $role], [], [$role->id => $written]);

        self::assertSame([[], ['unchanged' => [$role->id]]], $unchanged->write(Operation::begin(), self::grantee(), null, Carbon::now('UTC'), [$role->id]));

        $moved = new SyncPlan(GrantTarget::ROLE, $written, self::table($written), [$role->id => $role], [], [$role->id => $node]);

        $this->expectException(DependencyChangedException::class);

        $moved->write(Operation::begin(), self::grantee(), null, Carbon::now('UTC'), [$role->id]);
    }

    /**
     * Once every kept key is written, the roles granted are weighed against the
     * pairs of mutually exclusive roles: a plan granting both roles of a
     * declared pair is refused, and one leaving both as they are held, here as
     * the refused write left them outside any transaction, is not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRolesWrittenAreWeighedAgainstThePairs(): void
    {
        [$clerk, $auditor] = [self::role('clerk'), self::role('auditor')];

        $written = new GrantScope(self::tenant());
        $pair    = [$clerk->id, $auditor->id];

        \sort($pair);

        RoleExclusionTable::of()->declare($pair[0], $pair[1], null);

        $plan = new SyncPlan(GrantTarget::ROLE, $written, self::table($written), [$clerk->id => $clerk, $auditor->id => $auditor]);

        $write = static fn (): array => $plan->write(Operation::begin(), self::grantee(), null, Carbon::now('UTC'), []);

        self::assertInstanceOf(RoleExclusionConflictException::class, self::refusalOf($write));

        self::assertSame([[], ['unchanged' => [$clerk->id, $auditor->id]]], $write());
    }

    /**
     * The revocation of each dropped row is reported in the written scope's
     * tenant and application, with the reach the row had, and none for a row
     * kept.
     *
     * @return void
     */
    public function testReportsEachDroppedRowWithTheReachItHad(): void
    {
        [$kept, $node, $below] = [self::role('kept'), self::role('node'), self::role('below')];

        $written = new GrantScope(self::tenant(), 'admin');
        $plan    = new SyncPlan(GrantTarget::ROLE, $written, self::table($written), [$kept->id => $kept], [$kept->id, $node->id, $below->id]);
        $events  = $plan->revokedEvents(Operation::begin(), self::grantee(), [$node->id => false, $below->id => true]);
        $summary = [];

        foreach ($events as $event) {
            self::assertInstanceOf(RoleRevoked::class, $event);

            $summary[$event->name] = [$event->scope->tenant?->id, $event->scope->application, $event->scope->includeSubtree];
        }

        self::assertEquals(['node' => ['tenant-a', 'admin', false], 'below' => ['tenant-a', 'admin', true]], $summary);
    }

    /**
     * Return the grant table writer for the stub identity's roles in the scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @return \SineMacula\Laravel\Authorization\Services\Support\GrantTable
     */
    private static function table(GrantScope $scope): GrantTable
    {
        return GrantChanges::table(GrantTarget::ROLE, self::grantee(), null, $scope);
    }

    /**
     * Return whether each of the given roles' grant reaches below its tenant,
     * keyed by the role, in the order given.
     *
     * @param  list<string>  $ids
     * @return array<string, bool>
     */
    private static function reaches(array $ids): array
    {
        $stored  = DB::table('authorizable_roles')->pluck('include_subtree', 'role_id')->all();
        $reaches = [];

        foreach ($ids as $id) {
            $reaches[$id] = (bool) ($stored[$id] ?? null);
        }

        return $reaches;
    }

    /**
     * Return the grantee the plans write for.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    private static function grantee(): Reference
    {
        return new Reference('stub_identity', 'user-1');
    }

    /**
     * Return the tenant the plans write in.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    private static function tenant(): Reference
    {
        return new Reference('stub_tenant', 'tenant-a');
    }

    /**
     * Create a role.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private static function role(string $name): Role
    {
        return Role::query()->create(['name' => $name]);
    }
}
