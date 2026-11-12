<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use SineMacula\Laravel\Authorization\Testing\Concerns\TenantTreeContract;
use SineMacula\Laravel\Authorization\Testing\FakeTenantTree;
use Tests\Concerns\ScopesQueries;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\Fixtures\QueryScoping\TenantScopedPost;
use Tests\Fixtures\TenantTrees\ClashingTenants;
use Tests\TestCase;

/**
 * The fake tenant tree: it keeps the tenant tree contract over a fixture of two
 * types whose ids clash, is built from typed nodes alone or added to, refuses a
 * node it holds, a parent it does not and a move into its own subtree, nests
 * its subtree in `whereAuthorized()` on the connection it is built for, carries
 * a grant to the tenants below its tenant, and, once a node moves, answers the
 * move after the change is reported.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeTenantTree::class)]
#[CoversTrait(TenantTreeContract::class)]
final class FakeTenantTreeTest extends TestCase
{
    use ScopesQueries, TenantTreeContract;

    /**
     * A tree built from the nodes and one added to node by node are the same
     * tree, each `add()` returning the tree itself.
     *
     * @return void
     */
    public function testATreeOfTheNodesIsTheTreeAddedNodeByNode(): void
    {
        $built = new FakeTenantTree;

        foreach (ClashingTenants::nodes() as [$node, $parent]) {
            self::assertSame($built, $built->add($node, $parent));
        }

        $of = FakeTenantTree::of(ClashingTenants::nodes());

        foreach (ClashingTenants::nodes() as [$node]) {
            self::assertEquals($built->ancestors($node), $of->ancestors($node));
            self::assertSame(self::pairs($built, $node), self::pairs($of, $node));
        }

        self::assertEquals([new Reference('team', '2'), new Reference('org', '1')], $of->ancestors(new Reference('team', '7')));
        self::assertSame([], $of->ancestors(new Reference('org', '7')));
    }

    /**
     * A tenant the tree does not hold is at the top, with nothing below it: it
     * has no ancestors, is within itself alone, and its subtree is itself.
     *
     * @return void
     */
    public function testATenantTheTreeDoesNotHoldIsAloneAtTheTop(): void
    {
        $tree    = FakeTenantTree::of(ClashingTenants::nodes());
        $unknown = new Reference('team', '9');

        self::assertSame([], $tree->ancestors($unknown));
        self::assertTrue($tree->isWithin($unknown, $unknown));
        self::assertFalse($tree->isWithin($unknown, new Reference('org', '1')));
        self::assertFalse($tree->isWithin(new Reference('org', '1'), $unknown));
        self::assertSame(['["team","9"]'], self::pairs($tree, $unknown));
    }

    /**
     * The subtree lists the tenant and each node below it once, typed, never a
     * node of another type sharing an id with one of them.
     *
     * @return void
     */
    public function testTheSubtreeListsEachTenantWithinOnce(): void
    {
        $tree = FakeTenantTree::of(ClashingTenants::nodes());

        self::assertSame(['["account","3"]', '["org","1"]', '["team","1"]', '["team","2"]', '["team","7"]'], self::pairs($tree, new Reference('org', '1')));
        self::assertSame(['["org","7"]', '["team","8"]'], self::pairs($tree, new Reference('org', '7')));
        self::assertSame(['["team","2"]', '["team","7"]'], self::pairs($tree, new Reference('team', '2')));
        self::assertSame(['["team","7"]'], self::pairs($tree, new Reference('team', '7')));
    }

    /**
     * A subtree of more tenants than SQLite joins in one compound select is
     * still one query, listing each tenant once, and nests in a scoped query.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALargeSubtreeIsOneQueryThatNests(): void
    {
        [$org, $sibling, $deep] = self::tenants('org', 'sibling', 'n1999');

        $tree = (new FakeTenantTree)->add(Reference::of($org))->add(Reference::of($sibling));
        $type = $org->getMorphClass();
        $pair = static fn (string $id): string => \json_encode([$type, $id], \JSON_THROW_ON_ERROR);

        for ($index = 1; $index < 2000; $index++) {
            $tree->add(new Reference($type, "n{$index}"), $index < 1000 ? Reference::of($org) : new Reference($type, 'n' . ($index - 999)));
        }

        $rows = self::pairs($tree, Reference::of($org));

        self::assertCount(2000, $rows);
        self::assertSame($rows, \array_values(\array_unique($rows)));
        self::assertNotContains($pair('sibling'), $rows);
        self::assertSame([$pair('n1'), $pair('n1000'), $pair('n1999')], self::pairs($tree, new Reference($type, 'n1')));

        $this->app?->instance(TenantTree::class, $tree);

        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:view']), tenant: $org);

        foreach ([$org, $sibling, $deep] as $tenant) {
            self::postIn($tenant);
        }

        self::assertSame(['org', 'n1999'], self::scoped($this->resolveRequest($user, $org)));
        self::assertTrue($this->canIn($user, $deep));
        self::assertFalse($this->canIn($user, $sibling));
    }

    /**
     * The subtree is a query on the application's default connection, as it is
     * when the subtree is asked for, unless the tree is built for another.
     *
     * @return void
     */
    public function testTheSubtreeIsOnTheDefaultConnectionUnlessOneIsNamed(): void
    {
        $default = DB::getDefaultConnection();
        $tenant  = new Reference('org', '1');

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(ConfigRepository::class);
        $config->set('database.connections.fake_tree', $config->get("database.connections.{$default}"));

        self::assertSame($default, self::connectionOf((new FakeTenantTree)->subtree($tenant)));
        self::assertSame('fake_tree', self::connectionOf((new FakeTenantTree('fake_tree'))->subtree($tenant)));
        self::assertSame('fake_tree', self::connectionOf(FakeTenantTree::of(ClashingTenants::nodes(), 'fake_tree')->subtree($tenant)));

        DB::setDefaultConnection('fake_tree');

        try {
            self::assertSame('fake_tree', self::connectionOf(FakeTenantTree::of(ClashingTenants::nodes())->subtree($tenant)));
        } finally {
            DB::setDefaultConnection($default);
        }
    }

    /**
     * A node the tree holds is not added again, nor a node under a parent it
     * does not hold; a refused node is not held.
     *
     * @return void
     */
    public function testAddingRefusesANodeHeldAndAParentNotHeld(): void
    {
        $tree = FakeTenantTree::of(ClashingTenants::nodes());

        self::assertRefusal('The fake tenant tree already holds ["team","2"]: move it instead.', static fn () => $tree->add(new Reference('team', '2')));
        self::assertRefusal(
            'The fake tenant tree does not hold ["org","9"], the parent given for ["team","9"]: add it first.',
            static fn () => $tree->add(new Reference('team', '9'), new Reference('org', '9')),
        );

        $tree->add(new Reference('team', '9'), new Reference('org', '7'));

        self::assertEquals([new Reference('org', '7')], $tree->ancestors(new Reference('team', '9')));

        // A refusal names a tenant as JSON, its slashes, its characters and any
        // byte that is not UTF-8 written as read.
        $odd = new Reference('team', "a/\u{e9}\xff");

        $tree->add($odd);

        self::assertRefusal("The fake tenant tree already holds [\"team\",\"a/\u{e9}\u{fffd}\"]: move it instead.", static fn () => $tree->add($odd));

        // Yet an id differing from it in any byte is another tenant, neither
        // within the other nor reaching the nodes below the other.
        $other = new Reference('team', "a/\u{e9}\xfe");
        $below = new Reference('team', 'below');

        $tree->add($other)->add($below, $odd);

        self::assertEquals([$odd], $tree->ancestors($below));
        self::assertTrue($tree->isWithin($below, $odd));
        self::assertFalse($tree->isWithin($below, $other));
        self::assertFalse($tree->isWithin($other, $odd));

        foreach ([[$odd, ['team', "a/\u{e9}\xff", 'team', 'below']], [$other, ['team', "a/\u{e9}\xfe"]]] as [$tenant, $bindings]) {
            $subtree = $tree->subtree($tenant);

            self::assertInstanceOf(QueryBuilder::class, $subtree);
            self::assertSame($bindings, $subtree->getBindings());
        }
    }

    /**
     * A node moves under another parent, or to the top, carrying the nodes
     * below it; a node the tree does not hold, a parent it does not hold, and a
     * parent that is the node or below it are refused, leaving the tree as it
     * was.
     *
     * @return void
     */
    public function testMovingANodeCarriesItsSubtreeAndRefusesACycle(): void
    {
        $tree = FakeTenantTree::of(ClashingTenants::nodes());
        $team = new Reference('team', '2');

        self::assertSame($tree, $tree->move($team, new Reference('org', '7')));
        self::assertEquals([$team, new Reference('org', '7')], $tree->ancestors(new Reference('team', '7')));
        self::assertSame(['["org","7"]', '["team","2"]', '["team","7"]', '["team","8"]'], self::pairs($tree, new Reference('org', '7')));

        $tree->move($team, null);

        self::assertSame([], $tree->ancestors($team));

        self::assertRefusal('The fake tenant tree does not hold ["team","9"]: add it instead.', static fn () => $tree->move(new Reference('team', '9'), null));
        self::assertRefusal(
            'The fake tenant tree does not hold ["org","9"], the parent given for ["team","2"]: add it first.',
            static fn () => $tree->move($team, new Reference('org', '9')),
        );
        self::assertRefusal(
            'The fake tenant tree cannot put ["team","2"] under ["team","7"], which is it or below it.',
            static fn () => $tree->move($team, new Reference('team', '7')),
        );
        self::assertRefusal('The fake tenant tree cannot put ["team","2"] under ["team","2"], which is it or below it.', static fn () => $tree->move($team, $team));

        self::assertSame([], $tree->ancestors($team));
        self::assertEquals([$team], $tree->ancestors(new Reference('team', '7')));
    }

    /**
     * Bound as the tree, the fake scopes a query: a subject granted a
     * permission in a tenant sees the rows of that tenant and those below it,
     * never a tenant beside it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAScopedQueryKeepsTheRowsOfTheSubtree(): void
    {
        [$org, $account, $sibling] = self::tenants('org', 'account', 'sibling');

        $tree = FakeTenantTree::of([[Reference::of($org), null], [Reference::of($account), Reference::of($org)], [Reference::of($sibling), null]]);

        $this->app?->instance(TenantTree::class, $tree);

        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:view']), tenant: $org);

        foreach ([$org, $account, $sibling] as $tenant) {
            self::postIn($tenant);
        }

        self::assertSame(['org', 'account'], self::scoped($this->resolveRequest($user, $org)));
        self::assertSame(['account'], self::scoped($this->resolveRequest($user, $account)));
        self::assertSame([], self::scoped($this->resolveRequest($user, $sibling)));
    }

    /**
     * A grant in a tenant reaches every tenant below it in the fake, at any
     * depth, and no tenant beside it nor above it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantReachesTheSubtreeThroughTheFake(): void
    {
        [$top, $org, $account, $sibling] = self::tenants('top', 'org', 'account', 'sibling');

        $this->app?->instance(TenantTree::class, (new FakeTenantTree)
            ->add(Reference::of($top))
            ->add(Reference::of($org), Reference::of($top))
            ->add(Reference::of($account), Reference::of($org))
            ->add(Reference::of($sibling), Reference::of($top)));

        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:view']), tenant: $org);

        self::assertTrue($this->canIn($user, $org));
        self::assertTrue($this->canIn($user, $account));
        self::assertFalse($this->canIn($user, $sibling));
        self::assertFalse($this->canIn($user, $top));
    }

    /**
     * Once a node moves in the bound fake, a check keeps the answer it read for
     * the request until the move is reported through `treeChanged()`, after
     * which the grant no longer reaches it, in a check or a scoped query.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMoveTakesEffectOnceTheTreeChangeIsReported(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(ConfigRepository::class);
        $config->set('authorization.cache.store', 'array');

        (new AuthorizationServiceProvider($this->container()))->register();

        [$org, $account, $sibling] = self::tenants('org', 'account', 'sibling');

        $tree = FakeTenantTree::of([[Reference::of($org), null], [Reference::of($account), Reference::of($org)], [Reference::of($sibling), null]]);
        $user = StubIdentity::create(['id' => 'user-1']);

        $this->app?->instance(TenantTree::class, $tree);

        $user->givePermission(Permission::create(['name' => 'posts:view']), tenant: $org);

        foreach ([$org, $account, $sibling] as $tenant) {
            self::postIn($tenant);
        }

        self::assertTrue($this->canIn($user, $account));

        $tree->move(Reference::of($account), Reference::of($sibling));

        self::assertTrue($this->canIn($user, $account));

        Authorization::treeChanged($account);

        self::assertFalse($this->canIn($user, $account));
        self::assertSame(['org'], self::scoped($this->resolveRequest($user, $org)));
    }

    /**
     * Return the tree under test, built from the fixture.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\TenantTree
     */
    #[\Override]
    protected function tenantTree(): TenantTree
    {
        return FakeTenantTree::of(ClashingTenants::nodes());
    }

    /**
     * Return the fixture the tree is built from.
     *
     * @return list<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: \SineMacula\Laravel\Authorization\Support\Reference|null}>
     */
    #[\Override]
    protected function tenantTreeNodes(): array
    {
        return ClashingTenants::nodes();
    }

    /**
     * Claim mixed types: the fixture's teams and organisations share ids.
     *
     * @return bool
     */
    protected function hasMixedTenantTypes(): bool
    {
        return true;
    }

    /**
     * Determine whether the user is allowed to view posts in the tenant, as the
     * request's subject there.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  \Tests\Feature\Stubs\StubTenant  $tenant
     * @return bool
     */
    private function canIn(StubIdentity $user, StubTenant $tenant): bool
    {
        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($user, $tenant));
        $this->app?->forgetInstance(ResolvedTenant::class);

        return Authorization::can('posts:view');
    }

    /**
     * Return the subtree's pairs, each its type and id as a JSON pair, sorted,
     * every row kept.
     *
     * @param  \SineMacula\Laravel\Authorization\Testing\FakeTenantTree  $tree
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return list<string>
     */
    private static function pairs(FakeTenantTree $tree, Reference $tenant): array
    {
        $query = $tree->subtree($tenant);

        self::assertInstanceOf(QueryBuilder::class, $query);

        $pairs = \array_map(static fn (object $row): string => \json_encode(\array_values((array) $row), \JSON_THROW_ON_ERROR), $query->get()->all());

        \sort($pairs);

        return $pairs;
    }

    /**
     * Return the name of the connection the subtree is a query on.
     *
     * @param  mixed  $subtree
     * @return string|null
     */
    private static function connectionOf(mixed $subtree): ?string
    {
        self::assertInstanceOf(QueryBuilder::class, $subtree);

        $connection = $subtree->getConnection();

        self::assertInstanceOf(Connection::class, $connection);

        return $connection->getName();
    }

    /**
     * Assert the callback is refused with the message.
     *
     * @param  string  $message
     * @param  \Closure(): mixed  $callback
     * @return void
     */
    private static function assertRefusal(string $message, \Closure $callback): void
    {
        try {
            $callback();
        } catch (\InvalidArgumentException $exception) {
            self::assertSame($message, $exception->getMessage());

            return;
        }

        self::fail("The fake tenant tree did not refuse: {$message}");
    }

    /**
     * Create a stub tenant for each id.
     *
     * @param  string  ...$ids
     * @return list<\Tests\Feature\Stubs\StubTenant>
     */
    private static function tenants(string ...$ids): array
    {
        return \array_values(\array_map(static fn (string $id): StubTenant => StubTenant::query()->create(['id' => $id, 'name' => $id]), $ids));
    }

    /**
     * Create a post in the tenant, titled with its id.
     *
     * @param  \Tests\Feature\Stubs\StubTenant  $tenant
     * @return void
     */
    private static function postIn(StubTenant $tenant): void
    {
        TenantScopedPost::query()->create(['title' => Reference::of($tenant)->id, 'tenant_type' => $tenant->getMorphClass(), 'tenant_id' => $tenant->getKey()]);
    }

    /**
     * Return the titles of the posts the manager may view, in the order made.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $manager
     * @return list<mixed>
     */
    private static function scoped(AuthorizationManager $manager): array
    {
        /** @var \Illuminate\Database\Eloquent\Builder<\Tests\Fixtures\QueryScoping\TenantScopedPost> $query */
        $query = TenantScopedPost::query()->whereAuthorized('posts:view', [], $manager); // @phpstan-ignore method.notFound

        return \array_values($query->orderBy('id')->pluck('title')->all());
    }
}
