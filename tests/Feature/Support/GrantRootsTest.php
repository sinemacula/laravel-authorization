<?php

declare(strict_types = 1);

namespace Tests\Feature\Support;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Enums\DependencyPhase;
use SineMacula\Laravel\Authorization\Enums\GrantScopeStatus;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Support\GrantRoots;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;
use Tests\Concerns\RecordsRowLocks;
use Tests\Concerns\UsesAnAuthorizationConnection;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\Fixtures\QueryScoping\SubtreeQueryTree;
use Tests\TestCase;

/**
 * Feature tests for the reader of a set of grantees' grant roots, across every
 * tenant and application.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(GrantRoots::class)]
final class GrantRootsTest extends TestCase
{
    use RecordsRowLocks, UsesAnAuthorizationConnection;

    /**
     * Roots are classified against a tenant: within at the tenant, outside at
     * another tenant or the platform, and, without a condition for a tree that
     * cannot be read, outside only at the platform.
     *
     * @return void
     */
    public function testRootsAreClassifiedAgainstTheTenant(): void
    {
        $user   = StubIdentity::create(['id' => 'user']);
        $tenant = new Reference('tenant', 'a');
        $within = GrantRoots::within($tenant, new FlatTenantTree);
        $roots  = static fn (?\Closure $within): array => [(new GrantRoots([Reference::of($user)]))->against($within)];

        $user->givePermission(Permission::create(['name' => 'posts:read']), null, $tenant);

        self::assertSame([GrantScopeStatus::WITHIN, GrantScopeStatus::WITHIN], [...$roots($within), ...$roots(null)]);

        $user->givePermission(Permission::create(['name' => 'posts:edit']), null, new Reference('tenant', 'b'));

        self::assertSame([GrantScopeStatus::OUTSIDE, GrantScopeStatus::WITHIN], [...$roots($within), ...$roots(null)]);

        $user->givePermission(Permission::create(['name' => 'posts:delete']));

        self::assertSame([GrantScopeStatus::OUTSIDE, GrantScopeStatus::OUTSIDE], [...$roots($within), ...$roots(null)]);
    }

    /**
     * A row naming a tenant's type without its key, or its key without its
     * type, cannot be read.
     *
     * @return void
     */
    public function testARowNamingHalfATenantCannotBeRead(): void
    {
        $permission = Permission::create(['name' => 'posts:read']);
        $within     = GrantRoots::within(new Reference('tenant', 'a'), new FlatTenantTree);

        foreach (['type' => ['tenant', null], 'key' => [null, 'a']] as $half => [$type, $id]) {
            $user = StubIdentity::create(['id' => 'user-' . $half]);

            DB::table('authorizable_permissions')->insert([
                'permission_id'     => $permission->getKey(),
                'authorizable_type' => $user->getMorphClass(),
                'authorizable_id'   => $user->getKey(),
                'tenant_type'       => $type,
                'tenant_id'         => $id,
            ]);

            self::assertSame(GrantScopeStatus::UNKNOWN, (new GrantRoots([Reference::of($user)]))->against($within), $half);
            self::assertSame(GrantScopeStatus::UNKNOWN, (new GrantRoots([Reference::of($user)]))->against(null), $half);
        }
    }

    /**
     * With no grantees nothing is read, and no other grantee's grant is ever
     * taken for theirs.
     *
     * @return void
     */
    public function testNoGranteesReadNothing(): void
    {
        StubIdentity::create(['id' => 'other'])->givePermission(Permission::create(['name' => 'posts:read']));

        $roots   = new GrantRoots([]);
        $queries = $this->queriesOf(static function () use ($roots): void {
            self::assertSame(GrantScopeStatus::WITHIN, $roots->against(GrantRoots::within(new Reference('tenant', 'a'), new FlatTenantTree)));
            self::assertFalse($roots->appliesIn(new TenantChain([new Reference('tenant', 'a')])));
        });

        self::assertSame([], $queries);
    }

    /**
     * Each answer is one query, naming each grantee once, however often it is
     * given.
     *
     * @return void
     */
    public function testEachAnswerIsOneQueryNamingEachGranteeOnce(): void
    {
        $roots   = new GrantRoots([new Reference('stub', 'user-key'), new Reference('stub', 'user-key'), new Reference('stub', 'other-key')]);
        $tenant  = new Reference('tenant', 'a');
        $queries = $this->queriesOf(static function () use ($roots, $tenant): void {
            $roots->against(GrantRoots::within($tenant, new FlatTenantTree));
            $roots->appliesIn(new TenantChain([$tenant]));
        });

        self::assertCount(2, $queries);

        foreach ($queries as $bindings) {
            self::assertCount(3, \array_keys($bindings, 'user-key', true));
            self::assertCount(3, \array_keys($bindings, 'other-key', true));
        }
    }

    /**
     * Two grantees sharing a key under different types are two grantees, each
     * read, in whichever order they are given.
     *
     * @return void
     */
    public function testGranteesSharingAKeyUnderTwoTypesAreBothRead(): void
    {
        $first  = StubIdentity::create(['id' => 'shared-key']);
        $second = new StubSecondIdentity(['id' => 'shared-key']);
        $tenant = new Reference('tenant', 'a');
        $within = GrantRoots::within($tenant, new FlatTenantTree);

        $second->save();

        $first->givePermission(Permission::create(['name' => 'posts:read']), null, $tenant);
        $second->givePermission(Permission::create(['name' => 'posts:edit']), null, new Reference('tenant', 'b'));

        foreach (['first first' => [$first, $second], 'second first' => [$second, $first]] as $order => $grantees) {
            self::assertSame(GrantScopeStatus::OUTSIDE, (new GrantRoots(\array_map(Reference::of(...), $grantees)))->against($within), $order);
        }
    }

    /**
     * A grant applies in a tenant as a check there reads it, and, given an
     * application, only when it holds in that application.
     *
     * @return void
     */
    public function testAGrantAppliesWhereACheckReadsIt(): void
    {
        $user   = StubIdentity::create(['id' => 'user']);
        $tenant = new Reference('tenant', 'a');
        $roots  = new GrantRoots([Reference::of($user)]);

        $user->givePermission(Permission::create(['name' => 'posts:read']), null, new Reference('tenant', 'parent'));

        self::assertFalse($roots->appliesIn(new TenantChain([$tenant])));
        self::assertTrue($roots->appliesIn(new TenantChain([$tenant, new Reference('tenant', 'parent')])));

        $user->givePermission(Permission::create(['name' => 'posts:edit']), null, $tenant, application: 'admin');

        self::assertTrue($roots->appliesIn(new TenantChain([$tenant]), 'admin'));
        self::assertFalse($roots->appliesIn(new TenantChain([$tenant]), 'mobile'));
        self::assertTrue($roots->appliesIn(new TenantChain([$tenant])));
    }

    /**
     * An inline policy attached to a grantee it does not belong to is no grant
     * of that grantee, as no check applies it; a managed policy is.
     *
     * @return void
     */
    public function testAnotherGranteesInlinePolicyIsNoGrant(): void
    {
        $user   = StubIdentity::create(['id' => 'user']);
        $inline = Policy::create(['name' => 'theirs', 'owner_type' => 'stub', 'owner_id' => 'someone', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['*']]]]]);
        $roots  = new GrantRoots([Reference::of($user)]);
        $tenant = new Reference('tenant', 'a');

        // A row the write paths refuse, written past them.
        DB::table('authorizable_policies')->insert(['policy_id' => $inline->getKey(), 'authorizable_type' => $user->getMorphClass(), 'authorizable_id' => $user->getKey()]);

        self::assertSame(GrantScopeStatus::WITHIN, $roots->against(GrantRoots::within($tenant, new FlatTenantTree)));
        self::assertFalse($roots->appliesIn(new TenantChain([$tenant])));

        $user->attachPolicy(Policy::create(['name' => 'shared', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['*']]]]]));

        self::assertSame(GrantScopeStatus::OUTSIDE, $roots->against(GrantRoots::within($tenant, new FlatTenantTree)));
        self::assertTrue($roots->appliesIn(new TenantChain([$tenant])));
    }

    /**
     * A subtree written as an Eloquent query is nested as its base query.
     *
     * @return void
     */
    public function testAnEloquentSubtreeIsNested(): void
    {
        $closure = new class extends Model {
            /** @var string|null The closure table. */
            protected $table = ClosureTenantTree::TABLE;
        };

        $tree = new SubtreeQueryTree(static fn (Reference $tenant): Builder => $closure->newQuery()
            ->select(['descendant_type as tenant_type', 'descendant_id as tenant_id'])
            ->where('ancestor_type', $tenant->type)
            ->where('ancestor_id', $tenant->id));

        $org     = new Reference('tenant', 'org');
        $account = new Reference('tenant', 'account');
        $user    = StubIdentity::create(['id' => 'user']);

        ClosureTenantTree::add($org);
        ClosureTenantTree::add($account, $org);

        $user->givePermission(Permission::create(['name' => 'posts:read']), null, $account);

        self::assertSame(GrantScopeStatus::WITHIN, (new GrantRoots([Reference::of($user)]))->against(GrantRoots::within($org, $tree)));
        self::assertSame(GrantScopeStatus::WITHIN, (new GrantRoots([Reference::of($user)]))->against(GrantRoots::within($account, $tree)));

        $user->givePermission(Permission::create(['name' => 'posts:edit']), null, $org);

        self::assertSame(GrantScopeStatus::OUTSIDE, (new GrantRoots([Reference::of($user)]))->against(GrantRoots::within($account, $tree)));
    }

    /**
     * A subtree on another connection than the package's, or one that is no
     * query, cannot be nested, and is refused.
     *
     * @return void
     */
    public function testASubtreeThatCannotBeNestedIsRefused(): void
    {
        config()->set('database.connections.tenants', config('database.connections.' . DB::getDefaultConnection()));

        $trees = [
            'another connection' => new SubtreeQueryTree(static fn (Reference $tenant): Builder => DB::connection('tenants')->query()
                ->selectRaw('? as tenant_type, ? as tenant_id', [$tenant->type, $tenant->id])),
            'a relation' => new SubtreeQueryTree(static fn (): Builder => (new StubIdentity)->roles()),
        ];

        foreach ($trees as $shape => $tree) {
            try {
                GrantRoots::within(new Reference('tenant', 'a'), $tree);

                self::fail("A subtree on {$shape} was nested.");
            } catch (\UnexpectedValueException $exception) {
                self::assertSame('The tenant tree\'s subtree is not a query on the package\'s connection.', $exception->getMessage(), $shape);
            }
        }
    }

    /**
     * The grants are read on the write connection, so a replica that lags never
     * hides one. The package's tables are on a connection outside the test's
     * transaction, where Laravel would read on the read connection, and that
     * connection throws when it is used.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function testTheGrantsAreReadOnTheWriteConnection(): void
    {
        $this->useAnAuthorizationConnection();

        $user       = StubIdentity::create(['id' => 'user']);
        $connection = self::authorizationConnection();

        $user->givePermission(Permission::create(['name' => 'posts:read']));

        $connection->setReadPdo(static fn (): never => throw new \LogicException('The read connection was used.'));

        self::assertSame(0, $connection->transactionLevel());
        self::assertSame(GrantScopeStatus::OUTSIDE, (new GrantRoots([Reference::of($user)]))->against(null));
        self::assertTrue((new GrantRoots([Reference::of($user)]))->appliesIn(new TenantChain));
    }

    /**
     * Under a lock, a grant applies where `appliesIn()` says it does, each
     * grant table read on its own and locked, the role grants, then the
     * permission grants, then the policy attachments, stopping at the first
     * that holds one; with no grantees nothing is read.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function testAGrantAppliesUnderALockTableByTable(): void
    {
        $user   = StubIdentity::create(['id' => 'user']);
        $tenant = new Reference('tenant', 'a');
        $roots  = new GrantRoots([Reference::of($user)]);
        $inside = new TenantChain([$tenant, new Reference('tenant', 'parent')]);

        $user->givePermission(Permission::create(['name' => 'posts:read']), null, new Reference('tenant', 'parent'));
        StubIdentity::create(['id' => 'someone-else'])->givePermission(Permission::create(['name' => 'posts:edit']), null, $tenant);

        $locks = $this->recordRowLocks();

        self::assertFalse($roots->appliesUnderLock(new TenantChain([$tenant])));
        self::assertSame(['authorizable_roles', 'authorizable_permissions', 'authorizable_policies'], \array_column($locks->getArrayCopy(), 0));

        $locks->exchangeArray([]);

        self::assertTrue($roots->appliesUnderLock($inside));
        self::assertSame(['authorizable_roles', 'authorizable_permissions'], \array_column($locks->getArrayCopy(), 0));

        foreach ($locks as [, $bindings]) {
            self::assertContains('user', $bindings);
            self::assertNotContains('someone-else', $bindings);
        }

        $locks->exchangeArray([]);

        $queries = $this->queriesOf(static fn () => self::assertFalse((new GrantRoots([]))->appliesUnderLock($inside)));

        self::assertSame([], $queries);
        self::assertCount(0, $locks);
    }

    /**
     * Under a lock, a grant counts as `appliesIn()` counts it: one made at an
     * ancestor counts only when it reaches below it, an expired one never, and
     * neither does another grantee's inline policy.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function testUnderALockAGrantCountsAsACheckReadsIt(): void
    {
        $user   = StubIdentity::create(['id' => 'user']);
        $tenant = new Reference('tenant', 'a');
        $parent = new Reference('tenant', 'parent');
        $roots  = new GrantRoots([Reference::of($user)]);
        $inline = Policy::create(['name' => 'theirs', 'owner_type' => 'stub', 'owner_id' => 'someone', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['*']]]]]);

        // A row the write paths refuse, written past them.
        DB::table('authorizable_policies')->insert(['policy_id' => $inline->getKey(), 'authorizable_type' => $user->getMorphClass(), 'authorizable_id' => $user->getKey()]);

        $user->givePermission(Permission::create(['name' => 'posts:read']), null, $parent, includeSubtree: false);
        $user->givePermission(Permission::create(['name' => 'posts:edit']), now()->addHour(), $tenant);

        $this->travel(2)->hours();

        self::assertFalse($roots->appliesUnderLock(new TenantChain([$tenant, $parent])));
        self::assertTrue($roots->appliesUnderLock(new TenantChain([$parent])));
    }

    /**
     * Inside a delegated operation, the grants are locked through its pins, as
     * the coverage part, after every other part.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInsideADelegatedOperationTheGrantsArePinnedLast(): void
    {
        $user      = StubIdentity::create(['id' => 'user']);
        $roots     = new GrantRoots([Reference::of($user)]);
        $operation = new Operation((string) Str::uuid(), new Reference('user', 'actor'), CarbonImmutable::now('UTC'), false);

        $user->givePermission(Permission::create(['name' => 'posts:read']));

        $phase = OperationScope::run($operation, static function () use ($roots): ?DependencyPhase {
            self::assertTrue($roots->appliesUnderLock(new TenantChain));

            return OperationScope::pins()?->phase();
        });

        self::assertSame(DependencyPhase::COVERAGE, $phase);
    }

    /**
     * Run the callback, and return the bindings of each query it ran.
     *
     * @param  \Closure(): void  $callback
     * @return list<array<int, mixed>>
     */
    private function queriesOf(\Closure $callback): array
    {
        $queries = [];

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->bindings;
        });

        $callback();

        $this->app?->make('events')->forget(QueryExecuted::class);

        return $queries;
    }
}
