<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Administration\DependencyPins;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Enums\DependencyPhase;
use SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;
use Tests\Concerns\ActsAsTenant;
use Tests\Concerns\RecordsRowLocks;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\Fixtures\EmptyLockGrammar;
use Tests\Fixtures\ReversingLockGrammar;
use Tests\TestCase;

/**
 * Feature tests for `DependencyPins`, which lock and pin what a delegated
 * operation's decisions read and validate it before the write: rows read under
 * a lock on the write connection, in one order, each set once, and read again
 * both ways before the write; chains read afresh; a tree reported moved; and
 * the actor's authority locked before what the operation changes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(DependencyPins::class)]
final class DependencyPinsTest extends TestCase
{
    use ActsAsTenant, RecordsRowLocks;

    /**
     * A set of rows is read under a lock, its rows returned, and a set pinned
     * already is neither read nor locked again: its rows are those read first.
     *
     * @return void
     */
    public function testRowsAreReadUnderALockOnceEach(): void
    {
        $read  = Permission::query()->create(['name' => 'posts:read']);
        $pins  = self::pins();
        $locks = $this->recordRowLocks();

        $rows = $pins->lock(DependencyPhase::ACTOR, self::permissions('posts:read'));

        Permission::query()->create(['name' => 'posts:edit']);

        $again = $pins->lock(DependencyPhase::ACTOR, self::permissions('posts:read'));

        self::assertSame([$read->getKey()], \array_column($rows, 'id'));
        self::assertIsArray($rows[0]);
        self::assertSame($rows, $again);
        self::assertSame([['permissions', ['posts:read']]], $locks->getArrayCopy());
    }

    /**
     * The sets of one call are locked sorted by their query, whatever order
     * they are given in, and the rows of each are returned in that order.
     *
     * @return void
     */
    public function testTheSetsOfOneCallAreLockedInOrder(): void
    {
        Permission::query()->create(['name' => 'posts:read']);
        Policy::query()->create(['name' => 'readers', 'document' => ['statements' => []]]);

        $locks = $this->recordRowLocks();
        $rows  = self::pins()->lock(DependencyPhase::ACTOR, self::table('policies')->where('name', 'readers'), self::permissions('posts:read'));

        self::assertSame([['permissions', ['posts:read']], ['policies', ['readers']]], $locks->getArrayCopy());
        self::assertSame(['posts:read', 'readers'], \array_column($rows, 'name'));
    }

    /**
     * The parts are locked in order, actor, target, holders, and a part locked
     * after a later one is refused; the latest part locked is kept.
     *
     * @return void
     */
    public function testAPartLockedAfterALaterOneIsRefused(): void
    {
        $pins = self::pins();

        self::assertSame(DependencyPhase::ACTOR, $pins->phase());

        $pins->lock(DependencyPhase::TARGET);
        $pins->lock(DependencyPhase::TARGET);

        self::assertSame(DependencyPhase::TARGET, $pins->phase());

        $pins->lockChains(DependencyPhase::HOLDERS);

        self::assertSame(DependencyPhase::HOLDERS, $pins->phase());

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The TARGET dependencies of a delegated operation are locked after its HOLDERS ones.');

        $pins->lock(DependencyPhase::TARGET);
    }

    /**
     * The coverage check's rows are locked as the last part: inside a delegated
     * operation through its pins, so no earlier part may follow them, and with
     * no pins, inside a trusted operation or none, under a lock directly, read
     * afresh each time.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCoverageRowsAreLockedLast(): void
    {
        $read  = Permission::query()->create(['name' => 'posts:read']);
        $locks = $this->recordRowLocks();

        self::assertSame([$read->getKey()], \array_column(DependencyPins::lockCoverage(self::permissions('posts:read')), 'id'));
        self::assertSame([], OperationScope::run(Operation::begin(), static fn (): array => DependencyPins::lockCoverage(self::permissions('posts:edit'))));

        $edit = Permission::query()->create(['name' => 'posts:edit']);

        self::assertSame([$edit->getKey()], \array_column(DependencyPins::lockCoverage(self::permissions('posts:edit')), 'id'));
        self::assertSame([['permissions', ['posts:read']], ['permissions', ['posts:edit']], ['permissions', ['posts:edit']]], $locks->getArrayCopy());

        $operation = new Operation('op', new Reference(StubIdentity::class, 'admin'), CarbonImmutable::now('UTC'), false);

        $refusal = OperationScope::run($operation, static function (): ?string {
            $pins = OperationScope::delegatedPins();

            $pins->lock(DependencyPhase::HOLDERS);

            self::assertSame([], DependencyPins::lockCoverage(self::permissions('posts:delete')));
            self::assertSame(DependencyPhase::COVERAGE, $pins->phase());

            try {
                $pins->lock(DependencyPhase::HOLDERS);
            } catch (\LogicException $exception) {
                return $exception->getMessage();
            }

            return null;
        });

        self::assertSame('The HOLDERS dependencies of a delegated operation are locked after its COVERAGE ones.', $refusal);
    }

    /**
     * Chains cannot go back a part either.
     *
     * @return void
     */
    public function testAChainLockedAfterALaterPartIsRefused(): void
    {
        $pins = self::pins();

        $pins->lock(DependencyPhase::HOLDERS);

        $this->expectException(\LogicException::class);

        $pins->lockChains(DependencyPhase::ACTOR, null);
    }

    /**
     * Nothing changed, the pins validate.
     *
     * @return void
     */
    public function testNothingChangedValidates(): void
    {
        Permission::query()->create(['name' => 'posts:read']);

        $pins = self::pins();

        $pins->lock(DependencyPhase::ACTOR, self::permissions('posts:read'));
        $pins->validate();

        self::assertSame(DependencyPhase::ACTOR, $pins->phase());
    }

    /**
     * Return each concurrent change to a pinned set: a row written, one
     * inserted and one removed.
     *
     * @return iterable<string, array{\Closure(): mixed}>
     */
    public static function changes(): iterable
    {
        yield 'a row written' => [static fn (): int => DB::table('permissions')->where('name', 'posts:read')->update(['description' => 'changed'])];
        yield 'a row inserted' => [static fn (): Permission => Permission::query()->create(['name' => 'posts:read', 'guard' => 'api'])];
        yield 'a row removed' => [static fn (): int => DB::table('permissions')->where('name', 'posts:read')->delete()];
    }

    /**
     * A pinned set changed in any way since it was read fails validation,
     * naming its table.
     *
     * @param  \Closure(): mixed  $change
     * @return void
     */
    #[DataProvider('changes')]
    public function testAChangedSetFailsValidation(\Closure $change): void
    {
        Permission::query()->create(['name' => 'posts:read']);

        $pins = self::pins();

        $pins->lock(DependencyPhase::ACTOR, self::permissions('posts:read'));

        $change();

        $this->expectException(DependencyChangedException::class);
        $this->expectExceptionMessage('The rows of [permissions] a delegated decision read changed before the write.');

        $pins->validate();
    }

    /**
     * A set read without the lock that differs from what was pinned fails
     * validation, as a snapshot older than the locks would on MySQL.
     *
     * @return void
     */
    public function testAReadWithoutTheLockThatDiffersFails(): void
    {
        $connection = self::sqlite();
        $grammar    = new EmptyLockGrammar($connection);

        Permission::query()->create(['name' => 'posts:read']);

        $connection->setQueryGrammar($grammar);

        try {
            $pins = self::pins();

            self::assertSame([], $pins->lock(DependencyPhase::ACTOR, self::permissions('posts:read')));

            $this->expectException(DependencyChangedException::class);

            $pins->validate();
        } finally {
            $connection->useDefaultQueryGrammar();
        }
    }

    /**
     * A set read under the lock that differs from what was pinned fails
     * validation, even when the read without it agrees.
     *
     * @return void
     */
    public function testAReadUnderTheLockThatDiffersFails(): void
    {
        $connection = self::sqlite();
        $grammar    = new EmptyLockGrammar($connection);

        $grammar->isEmptying = false;

        Permission::query()->create(['name' => 'posts:read']);

        $connection->setQueryGrammar($grammar);

        try {
            $pins = self::pins();

            self::assertCount(1, $pins->lock(DependencyPhase::ACTOR, self::permissions('posts:read')));

            $grammar->isEmptying = true;

            $this->expectException(DependencyChangedException::class);

            $pins->validate();
        } finally {
            $connection->useDefaultQueryGrammar();
        }
    }

    /**
     * The chain of each tenant is read afresh and returned, the platform's
     * empty, and a tenant moved since fails validation, as does a tree reported
     * changed, even with no chain pinned.
     *
     * @return void
     */
    public function testAMovedTreeFailsValidation(): void
    {
        $child  = new Reference('stub_tenant', 'child');
        $parent = new Reference('stub_tenant', 'parent');
        $other  = new Reference('stub_tenant', 'other');
        $tree   = (new StubTenantTree)->put($child, $parent);

        $this->app?->instance(TenantTree::class, $tree);

        $pins = self::pins();

        self::assertEquals([$child, $parent, $parent, $child, $parent], $pins->lockChains(DependencyPhase::TARGET, $child, null, $parent, $child));

        $pins->validate();
        $tree->put($child, $other);

        try {
            $pins->validate();

            self::fail('A moved tenant validated.');
        } catch (DependencyChangedException $exception) {
            self::assertSame('The tenant tree moved after a delegated decision read it, before the write.', $exception->getMessage());
        }

        $reported = self::pins();

        $reported->validate();
        $reported->treeChanged();

        $this->expectException(DependencyChangedException::class);

        $reported->validate();
    }

    /**
     * The actor's authority is locked once, from its principal's and identity's
     * grant rows and live break-glass activations on, with the guardrails of
     * the request's tenant and the operation type's resource policies.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheActorIsLockedOnce(): void
    {
        $tenant = self::createTenant('team');

        $this->actAsTenant($tenant);

        $locks = $this->recordRowLocks();
        $pins  = self::pins();

        $pins->lockActor();
        $pins->lockActor();

        $locked = $locks->getArrayCopy();

        self::assertSame(
            ['authorizable_roles', 'break_glass_activations', 'authorizable_permissions', 'authorizable_policies', 'authorizable_boundaries', 'guardrails', 'resource_policies'],
            \array_column($locked, 0),
        );
        self::assertSame([StubIdentity::class, 'admin', StubIdentity::class, 'identity'], $locked[0][1]);
        self::assertSame($locked[0][1], \array_slice($locked[1][1], 0, 4));
        self::assertSame([$tenant->getMorphClass(), 'team'], $locked[5][1]);
        self::assertSame([OperationResource::TYPE], $locked[6][1]);
        self::assertSame(DependencyPhase::ACTOR, $pins->phase());
    }

    /**
     * The changes are locked after the actor, at the target part, and a
     * guardrail change after the actor too, its policy's row included when it
     * has a key.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChangesAndGuardrailsAreLockedAfterTheActor(): void
    {
        $permission = Permission::query()->create(['name' => 'posts:read']);
        $policy     = Policy::query()->create(['name' => 'rail', 'document' => ['statements' => []]]);
        $locks      = $this->recordRowLocks();
        $pins       = self::pins();

        $pins->lockChanges(OperationResource::grant(PackagePermissions::PERMISSION_GRANT, new Reference(StubIdentity::class, 'user'), $permission, GrantScope::platform()));

        self::assertSame(DependencyPhase::TARGET, $pins->phase());
        self::assertSame('authorizable_roles', $locks[0][0] ?? null);
        self::assertContains(['permissions', [$permission->getKey()]], $locks->getArrayCopy());

        $guarded = self::pins();
        $before  = $locks->count();

        $guarded->lockGuardrail($policy, null);
        $guarded->lockGuardrail(new Policy(['name' => 'unsaved']), null);

        $locked = \array_slice($locks->getArrayCopy(), $before);

        self::assertSame('authorizable_roles', $locked[0][0]);
        self::assertContains(['policies', [$policy->getKey()]], $locked);
        self::assertSame(DependencyPhase::TARGET, $guarded->phase());
    }

    /**
     * A grant made between the actor's pin and the validation is noticed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantToTheActorFailsValidation(): void
    {
        $actor = StubIdentity::query()->create(['id' => 'admin']);
        $pins  = self::pins();

        $pins->lockActor();

        GrantService::instance()?->grantPermission($actor, Permission::query()->create(['name' => 'posts:read']));

        $this->expectException(DependencyChangedException::class);
        $this->expectExceptionMessage('[authorizable_permissions]');

        $pins->validate();
    }

    /**
     * A query is pinned as it was given: a caller that goes on to change its
     * own query never changes what is read again.
     *
     * @return void
     */
    public function testAPinnedQueryIsCopied(): void
    {
        Permission::query()->create(['name' => 'posts:read']);

        $pins  = self::pins();
        $query = self::permissions('posts:read');

        $pins->lock(DependencyPhase::ACTOR, $query);

        $query->where('name', 'posts:edit');

        $pins->validate();

        self::assertSame(1, self::permissions('posts:read')->count());
    }

    /**
     * Two reads of the same rows in different orders hold the same rows: the
     * digest is of the rows whatever their order.
     *
     * @return void
     */
    public function testRowsReadInAnotherOrderValidate(): void
    {
        $connection = self::sqlite();

        Permission::query()->create(['name' => 'posts:read']);
        Permission::query()->create(['name' => 'posts:edit']);

        $connection->setQueryGrammar(new ReversingLockGrammar($connection));

        try {
            $pins = self::pins();
            $rows = $pins->lock(DependencyPhase::ACTOR, self::table('permissions')->whereIn('name', ['posts:read', 'posts:edit']));

            self::assertSame(['posts:read', 'posts:edit'], \array_column($rows, 'name'));

            $pins->validate();
        } finally {
            $connection->useDefaultQueryGrammar();
        }
    }

    /**
     * An actor with no identity behind its principal has its principal's rows
     * locked alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActorWithNoIdentityLocksItsPrincipalAlone(): void
    {
        $locks = $this->recordRowLocks();
        $pins  = new DependencyPins(new Operation('op', new Reference(StubIdentity::class, 'admin'), CarbonImmutable::now('UTC'), false));

        $pins->lockActor();

        self::assertSame(['authorizable_roles', [StubIdentity::class, 'admin']], $locks[0] ?? null);
    }

    /**
     * A tenant pinned again after its chain moved keeps its first chain, so the
     * move fails validation; and two tenants of one id and two types are pinned
     * apart, so a move of either fails it.
     *
     * @return void
     */
    public function testATenantKeepsTheChainItWasFirstPinnedWith(): void
    {
        $child  = new Reference('stub_tenant', 'x');
        $twin   = new Reference('other_tenant', 'x');
        $parent = new Reference('stub_tenant', 'parent');
        $other  = new Reference('stub_tenant', 'other');
        $tree   = (new StubTenantTree)->put($child, $parent)->put($twin, $parent);

        $this->app?->instance(TenantTree::class, $tree);

        $pins = self::pins();

        $pins->lockChains(DependencyPhase::TARGET, $child, $twin);
        $tree->put($child, $other);
        $pins->lockChains(DependencyPhase::HOLDERS, $child);

        self::assertDependencyChanged($pins);

        $tree->put($child, $parent);

        $twins = self::pins();

        $twins->lockChains(DependencyPhase::TARGET, $child, $twin);
        $tree->put($twin, $other);

        self::assertDependencyChanged($twins);
    }

    /**
     * A chain is read afresh, never from the answer a batch of checks keeps, so
     * a tenant moved by another process, unreported, still fails validation.
     *
     * @return void
     */
    public function testAChainIsReadAfreshWithinABatch(): void
    {
        $child  = new Reference('stub_tenant', 'child');
        $parent = new Reference('stub_tenant', 'parent');
        $other  = new Reference('stub_tenant', 'other');
        $tree   = (new StubTenantTree)->put($child, $parent);
        $cache  = new ResolutionCache;

        $this->app?->instance(TenantTree::class, $tree);
        $this->app?->instance(ResolutionCache::class, $cache);

        $cache->batch(static function () use ($child, $other, $tree): void {
            TenantChain::of($child, $tree);

            $pins = self::pins();

            $pins->lockChains(DependencyPhase::TARGET, $child);
            $tree->put($child, $other);

            self::assertDependencyChanged($pins);
        });
    }

    /**
     * The grantees' rows are locked after the actor's, in the target part: an
     * identity's grant rows, and a role's chain; a role, permission or policy
     * given as a model is then compared with its row as locked, and one that
     * changed since it was read, or is gone, fails, while any other model, or
     * one not saved, is not compared.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testGranteesAreLockedAfterTheActorAndComparedWithTheirRows(): void
    {
        $role  = Role::query()->whereKey(Role::query()->create(['name' => 'editor', 'rank' => 5])->getKey())->firstOrFail();
        $user  = StubIdentity::query()->create(['id' => 'user']);
        $locks = $this->recordRowLocks();
        $pins  = self::pins();

        $pins->lockGrantees($user, $role);
        $pins->lockChanges(OperationResource::definition(PackagePermissions::ROLE_CREATE, new Role(['name' => 'new'])));

        self::assertSame(DependencyPhase::TARGET, $pins->phase());
        self::assertSame(['authorizable_roles', [StubIdentity::class, 'admin', StubIdentity::class, 'identity']], $locks[0] ?? null);
        self::assertContains(['authorizable_roles', [StubIdentity::class, 'user']], $locks->getArrayCopy());
        self::assertContains(['roles', [$role->getKey()]], $locks->getArrayCopy());

        DB::table('roles')->where('id', $role->getKey())->update(['rank' => 1]);

        self::assertDependencyChanged(static fn () => self::pins()->lockGrantees($role));

        $fresh = Role::query()->whereKey($role->getKey())->firstOrFail();

        self::pins()->lockGrantees($fresh, $user, Role::query()->create(['name' => 'author']));

        DB::table('roles')->where('id', $role->getKey())->delete();

        self::assertDependencyChanged(static fn () => self::pins()->lockGrantees($fresh));
    }

    /**
     * What a change hands out or redefines, as the service read it, is compared
     * with its row as locked: a permission renamed, or a policy rewritten,
     * since it was read fails, as stored it passes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWhatAChangeHandsOutIsComparedWithItsRow(): void
    {
        $permission = Permission::query()->whereKey(Permission::query()->create(['name' => 'posts:read'])->getKey())->firstOrFail();
        $policy     = Policy::query()->whereKey(Policy::query()->create(['name' => 'readers', 'document' => ['statements' => []]])->getKey())->firstOrFail();
        $grantee    = new Reference(StubIdentity::class, 'user');
        $grant      = OperationResource::grant(PackagePermissions::PERMISSION_GRANT, $grantee, $permission, GrantScope::platform());
        $rewrite    = OperationResource::definition(PackagePermissions::POLICY_UPDATE, $policy);

        self::pins()->lockChanges($grant, $rewrite);

        DB::table('permissions')->where('id', $permission->getKey())->update(['name' => 'posts:edit']);

        self::assertDependencyChanged(static fn () => self::pins()->lockChanges($grant));

        DB::table('policies')->where('id', $policy->getKey())->update(['description' => 'changed']);

        self::assertDependencyChanged(static fn () => self::pins()->lockChanges($rewrite));
    }

    /**
     * A set within the limit is locked, pinned and returned, and a second lock
     * of it reads nothing again; a set over it is returned as null, never
     * pinned, so a change to it fails nothing.
     *
     * @return void
     */
    public function testASetIsLockedWithinTheLimitOnly(): void
    {
        foreach (['posts:read', 'posts:edit', 'posts:delete'] as $name) {
            Permission::query()->create(['name' => $name]);
        }

        $locks = $this->recordRowLocks();
        $pins  = self::pins();
        $all   = self::table('permissions')->where('name', 'like', 'posts:%');

        self::assertNull($pins->lockWithin(DependencyPhase::HOLDERS, $all, 2));

        DB::table('permissions')->where('name', 'posts:delete')->delete();

        $pins->validate();

        self::assertCount(2, (array) $pins->lockWithin(DependencyPhase::HOLDERS, $all, 2));
        self::assertCount(2, (array) $pins->lockWithin(DependencyPhase::HOLDERS, $all, 2));
        self::assertCount(2, $locks);
        self::assertSame(DependencyPhase::HOLDERS, $pins->phase());

        Permission::query()->create(['name' => 'posts:publish']);

        self::assertDependencyChanged($pins);
    }

    /**
     * The keys in a column of a set within the limit are returned as text, each
     * once, in the order read; a set over it is null. Outside a delegated
     * operation the rows are read as they stand; inside one they are locked and
     * pinned, so a row added before the write fails validation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheKeysOfASetWithinTheLimit(): void
    {
        $user = StubIdentity::query()->create(['id' => 'user']);

        foreach ([['a', 'posts:read'], ['a', 'posts:edit'], ['b', 'posts:read']] as [$id, $name]) {
            GrantService::instance()?->grantPermission(StubIdentity::query()->firstOrCreate(['id' => $id]), Permission::query()->firstOrCreate(['name' => $name]));
        }

        $rows = static fn (): Builder => self::table('authorizable_permissions')->orderBy('authorizable_id');

        self::assertSame(['a', 'b'], DependencyPins::keysWithin($rows(), 'authorizable_id', 3));
        self::assertNull(DependencyPins::keysWithin($rows(), 'authorizable_id', 2));

        $operation = new Operation('op', new Reference(StubIdentity::class, 'admin'), CarbonImmutable::now('UTC'), false);

        OperationScope::run($operation, static function () use ($rows, $user): void {
            self::assertSame(['a', 'b'], DependencyPins::keysWithin($rows(), 'authorizable_id', 3));

            GrantService::instance()?->grantPermission($user, Permission::query()->create(['name' => 'posts:publish']));

            self::assertDependencyChanged(OperationScope::delegatedPins());
        });
    }

    /**
     * Assert that the pins fail validation, or that the call throws, with
     * `DependencyChangedException`.
     *
     * @param  \Closure(): mixed|\SineMacula\Laravel\Authorization\Administration\DependencyPins  $pins
     * @return void
     */
    private static function assertDependencyChanged(\Closure|DependencyPins $pins): void
    {
        $thrown = null;

        try {
            $pins instanceof DependencyPins ? $pins->validate() : $pins();
        } catch (DependencyChangedException $exception) {
            $thrown = $exception;
        }

        self::assertInstanceOf(DependencyChangedException::class, $thrown, 'Nothing that changed was noticed.');
    }

    /**
     * Return the pins of a new delegated operation by the principal `admin` and
     * the identity `identity`.
     *
     * @return \SineMacula\Laravel\Authorization\Administration\DependencyPins
     */
    private static function pins(): DependencyPins
    {
        $operation = new Operation('op', new Reference(StubIdentity::class, 'admin'), CarbonImmutable::now('UTC'), false, new Reference(StubIdentity::class, 'identity'));

        return new DependencyPins($operation);
    }

    /**
     * Return a query of the permissions of the name.
     *
     * @param  string  $name
     * @return \Illuminate\Database\Query\Builder
     */
    private static function permissions(string $name): Builder
    {
        return self::table('permissions')->where('name', $name);
    }

    /**
     * Return a query of the table on the default connection.
     *
     * @param  string  $table
     * @return \Illuminate\Database\Query\Builder
     */
    private static function table(string $table): Builder
    {
        return DB::table($table);
    }

    /**
     * Return the default connection, skipping a test that needs SQLite's
     * grammar elsewhere.
     *
     * @return \Illuminate\Database\Connection
     */
    private static function sqlite(): Connection
    {
        /** @var \Illuminate\Database\Connection $connection */
        $connection = DB::connection();

        if ($connection->getDriverName() !== 'sqlite') {
            self::markTestSkipped('A grammar of SQLite\'s stands in for a stale snapshot.');
        }

        return $connection;
    }
}
