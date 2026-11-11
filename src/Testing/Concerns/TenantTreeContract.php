<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Testing\Concerns;

use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Contract tests for a tenant tree (AUTHZ-5.3, N111), for the test case of an
 * implementation of `Contracts\TenantTree` to use.
 *
 * The test case supplies the tree under test (`tenantTree()`), built once its
 * fixture rows are in place, and the shape it was seeded with, as data
 * (`tenantTreeNodes()`): each node a `Reference` and its parent's, or null for
 * a tenant at the top. Three hooks are protected, so a test case may override
 * them, and reach the kit's own through an alias of the trait method:
 *
 * - `tenantTreeConnection()` names the connection the subtree must be on: by
 *   default the package's, as `authorization.connection` resolves it; null for
 *   the application's default.
 * - `hasMixedTenantTypes()` claims mixed types, false by default.
 * - `tenantTreeOutsider()` returns a tenant outside the fixture, which the
 *   checks ask the tree about. By default it is of the first node's type, with
 *   an id shaped as the fixture's are, so the tree's storage can hold it: the
 *   largest id plus one when every id is digits, a new UUID when every id is a
 *   UUID, else `outside`, with a `-` added until no node has it.
 *
 * Each check is a test of its own, named `testTenantTree...`, and holds for
 * every node of the fixture: the ancestors are the parent chain, nearest first;
 * `isWithin()` holds for a node and those below it alone, never for the
 * outsider either way; the subtree is a query on the connection, each row
 * carrying both `tenant_type` and `tenant_id`, its pairs, compared as strings,
 * exactly the node and those below it, alone and nested in a query of typed
 * rows as the grant scope query nests it, whatever the tenant scope. A subtree
 * may return a pair more than once, since every reader asks it whether a pair
 * exists, but never a pair missing or one too many. A failure names the node
 * and the pairs missing or extra.
 *
 * A tree claiming mixed types needs a fixture on which confusing types fails: a
 * node with a node of another type below it, so a subtree typing every row with
 * its root's type misses that one, and a node below it, or the node itself,
 * sharing its id with a node of another type outside it, so a subtree matching
 * tenants by id alone holds one too many. The kit fails a fixture holding no
 * such node.
 *
 * The checks assert through `PHPUnit\Framework\Assert`, and need the
 * application booted with the package, as a Testbench test case boots it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait TenantTreeContract
{
    /**
     * The fixture is a tree: it holds a node, lists each once, holds every
     * parent and has no cycle; and, for a tree claiming mixed types, it fails a
     * subtree that confuses them.
     *
     * @return void
     */
    public function testTenantTreeFixtureIsATree(): void
    {
        $chains = $this->tenantTreeChains();

        if (!$this->hasMixedTenantTypes()) {
            return;
        }

        $exposing = \array_filter(\array_keys($chains), static fn (string $key): bool => self::hasTenantTreeTypeClash($chains, $key));

        Assert::assertNotSame([], $exposing, 'The tenant tree claims mixed types, but no node of its fixture has both a node of another type below it, '
            . 'and a node below it, or itself, sharing its id with a node of another type outside it, so a subtree typing every tenant with its root\'s '
            . 'type, or matching tenants by id alone, could pass: add them, such as ["team","7"] below ["org","1"] and ["org","7"] outside it.');
    }

    /**
     * A node's ancestors are its parent chain, nearest first, the node left
     * out.
     *
     * @return void
     */
    public function testTenantTreeAncestorsAreTheParentChain(): void
    {
        $tree = $this->tenantTree();

        foreach ($this->tenantTreeChains() as $key => $chain) {
            $expected = \array_map(self::tenantTreeKey(...), \array_slice($chain, 1));
            $actual   = \array_map(self::tenantTreeKey(...), $tree->ancestors($chain[0]));

            Assert::assertSame($expected, $actual, "The ancestors of {$key} are not its parent chain, nearest first, the tenant left out.");
        }
    }

    /**
     * A tenant is within a node exactly when it is the node or below it, and
     * the tenant outside the fixture is neither within a node nor above one.
     *
     * @return void
     */
    public function testTenantTreeIsWithinHoldsForTheSubtreeAlone(): void
    {
        $tree     = $this->tenantTree();
        $chains   = $this->tenantTreeChains();
        $outsider = $this->tenantTreeOutsider();
        $outside  = self::tenantTreeKey($outsider);

        foreach ($chains as $key => $chain) {
            $within = self::tenantTreeWithin($chains, $key);

            foreach ($chains as $candidate => [$tenant]) {
                $expected = \in_array($candidate, $within, true);

                $failure = $expected
                    ? "isWithin({$candidate}, {$key}) does not hold, though {$candidate} is {$key} or below it."
                    : "isWithin({$candidate}, {$key}) holds, though {$candidate} is not {$key} nor below it.";

                Assert::assertSame($expected, $tree->isWithin($tenant, $chain[0]), $failure);
            }

            Assert::assertFalse($tree->isWithin($outsider, $chain[0]), "isWithin({$outside}, {$key}) holds for a tenant outside the fixture.");
            Assert::assertFalse($tree->isWithin($chain[0], $outsider), "isWithin({$key}, {$outside}) holds for a tenant outside the fixture.");
        }
    }

    /**
     * A node's subtree is a query on the connection, whose rows each carry a
     * `tenant_type` and a `tenant_id`, and whose pairs are exactly the node and
     * those below it.
     *
     * @return void
     */
    public function testTenantTreeSubtreeSelectsTheTypedSubtree(): void
    {
        $tree   = $this->tenantTree();
        $chains = $this->tenantTreeChains();

        foreach ($chains as $key => $chain) {
            $rows = $this->tenantTreeSubtree($tree, $chain[0])->get();

            self::tenantTreeAssertPairs(self::tenantTreeWithin($chains, $key), self::tenantTreePairs($rows, $key), "The subtree of {$key}");
        }
    }

    /**
     * A node's subtree nested whole in a query of typed rows, a row for each
     * node and one for the tenant outside the fixture, compared column by
     * column as the grant scope query compares it, finds exactly the node and
     * those below it.
     *
     * @return void
     */
    public function testTenantTreeSubtreeNestsInAQuery(): void
    {
        $tree   = $this->tenantTree();
        $chains = $this->tenantTreeChains();
        $nodes  = [...\array_column($chains, 0), $this->tenantTreeOutsider()];

        foreach ($chains as $key => $chain) {
            $subtree = $this->tenantTreeSubtree($tree, $chain[0]);
            $selects = \array_map(static fn (Reference $node): Builder => $subtree->newQuery()->selectRaw('? as tenant_type, ? as tenant_id', [$node->type, $node->id]), $nodes);
            $typed   = \array_shift($selects);

            foreach ($selects as $select) {
                $typed->unionAll($select);
            }

            $rows = $subtree->newQuery()
                ->fromSub($typed, 'typed')
                ->select(['typed.tenant_type', 'typed.tenant_id'])
                ->whereExists(static function (Builder $exists) use ($subtree): void {
                    $exists->selectRaw('1')
                        ->fromSub($subtree, 'subtree')
                        ->whereColumn('subtree.tenant_type', 'typed.tenant_type')
                        ->whereColumn('subtree.tenant_id', 'typed.tenant_id');
                })
                ->get();

            self::tenantTreeAssertPairs(self::tenantTreeWithin($chains, $key), self::tenantTreePairs($rows, $key), "Nested in a query, the subtree of {$key}");
        }
    }

    /**
     * A node's subtree is the same inside the tenant scope of the tenant
     * outside the fixture.
     *
     * @return void
     */
    public function testTenantTreeSubtreeIgnoresTheTenantScope(): void
    {
        $tree     = $this->tenantTree();
        $chains   = $this->tenantTreeChains();
        $outsider = $this->tenantTreeOutsider();
        $scope    = self::tenantTreeKey($outsider);

        foreach ($chains as $key => $chain) {
            $rows = AuthorizationScope::tenant($outsider)->within(fn (): iterable => $this->tenantTreeSubtree($tree, $chain[0])->get());

            self::tenantTreeAssertPairs(self::tenantTreeWithin($chains, $key), self::tenantTreePairs($rows, $key), "In the tenant scope of {$scope}, the subtree of {$key}");
        }
    }

    /**
     * Return the tree under test, its fixture rows already in place.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\TenantTree
     */
    abstract protected function tenantTree(): TenantTree;

    /**
     * Return the fixture the tree was seeded with: each node and its parent, or
     * null for a tenant at the top.
     *
     * @return list<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: \SineMacula\Laravel\Authorization\Support\Reference|null}>
     */
    abstract protected function tenantTreeNodes(): array;

    /**
     * Return the connection the subtree must be on: the package's, by default,
     * as `authorization.connection` resolves it; null for the application's
     * default.
     *
     * @return string|null
     */
    protected function tenantTreeConnection(): ?string
    {
        return AuthorizationConnection::resolve();
    }

    /**
     * Determine whether the tree claims mixed types, so the fixture must be one
     * on which confusing them fails.
     *
     * @return bool
     */
    protected function hasMixedTenantTypes(): bool
    {
        return false;
    }

    /**
     * Return a tenant outside the fixture, of the first node's type, with an id
     * shaped as the fixture's are, so the tree's storage can hold it: the
     * largest plus one when every id is digits, a new UUID when every id is a
     * UUID, else `outside`, with a `-` added until no node has it.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    protected function tenantTreeOutsider(): Reference
    {
        $chains = $this->tenantTreeChains();
        $type   = \reset($chains)[0]->type;
        $ids    = \array_map(static fn (Reference $node): string => $node->id, \array_column($chains, 0));
        $digits = \array_filter($ids, static fn (string $id): bool => \ctype_digit($id));

        if ($digits === $ids) {
            return new Reference($type, (string) (\max($digits) + 1));
        }

        if (\array_filter($ids, Str::isUuid(...)) === $ids) {
            return new Reference($type, Str::uuid()->toString());
        }

        $id = 'outside';

        while (\in_array($id, $ids, true)) {
            $id .= '-';
        }

        return new Reference($type, $id);
    }

    /**
     * Return the chain of each node of the fixture, the node first, then its
     * ancestors nearest first, by the node's key, failing for a fixture with no
     * node, a node listed twice, a parent outside the fixture or a cycle.
     *
     * @return non-empty-array<string, non-empty-list<\SineMacula\Laravel\Authorization\Support\Reference>>
     */
    private function tenantTreeChains(): array
    {
        $nodes   = [];
        $parents = [];

        foreach ($this->tenantTreeNodes() as [$node, $parent]) {
            $key = self::tenantTreeKey($node);

            Assert::assertArrayNotHasKey($key, $nodes, "The tenant tree fixture lists {$key} twice.");

            $nodes[$key]   = $node;
            $parents[$key] = $parent;
        }

        $chains = [];

        foreach ($nodes as $key => $node) {
            $chain  = [$node];
            $parent = $parents[$key];

            while ($parent !== null) {
                $above = self::tenantTreeKey($parent);

                Assert::assertArrayHasKey($above, $nodes, "The parent {$above} of {$key} is not in the tenant tree fixture.");
                Assert::assertLessThan(\count($nodes), \count($chain), "The parents of {$key} in the tenant tree fixture form a cycle.");

                $chain[] = $nodes[$above];
                $parent  = $parents[$above];
            }

            $chains[$key] = $chain;
        }

        Assert::assertNotSame([], $chains, 'The tenant tree fixture holds no tenant.');

        return $chains;
    }

    /**
     * Return the subtree of the tenant as a query, failing for one that is no
     * query, or that is on another connection than the one it must be on.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\TenantTree  $tree
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \Illuminate\Database\Query\Builder
     */
    private function tenantTreeSubtree(TenantTree $tree, Reference $tenant): Builder
    {
        $key     = self::tenantTreeKey($tenant);
        $subtree = $tree->subtree($tenant);
        $query   = $subtree instanceof EloquentBuilder ? $subtree->toBase() : $subtree;

        if (!$query instanceof Builder) {
            Assert::fail("The subtree of {$key} is a " . $subtree::class . ', not a query the package can run or nest.');
        }

        $connection = $query->getConnection();
        $expected   = $this->tenantTreeConnection() ?? DB::getDefaultConnection();

        $name = $connection instanceof Connection ? $connection->getName() : null;

        Assert::assertSame($expected, $name, "The subtree of {$key} is not a query on the connection '{$expected}', where it is nested.");

        return $query;
    }

    /**
     * Determine whether the node has a node of another type below it, and a
     * node below it, or itself, sharing its id with a node of another type
     * outside it.
     *
     * @param  array<string, non-empty-list<\SineMacula\Laravel\Authorization\Support\Reference>>  $chains
     * @param  string  $key
     * @return bool
     */
    private static function hasTenantTreeTypeClash(array $chains, string $key): bool
    {
        $root    = $chains[$key][0];
        $within  = self::tenantTreeWithin($chains, $key);
        $inside  = \array_map(static fn (string $node): Reference => $chains[$node][0], $within);
        $outside = \array_map(static fn (string $node): Reference => $chains[$node][0], \array_diff(\array_keys($chains), $within));

        $isMixed  = \array_filter($inside, static fn (Reference $node): bool => $node->type !== $root->type) !== [];
        $clashing = \array_filter($inside, static fn (Reference $in): bool => \array_filter(
            $outside,
            static fn (Reference $out): bool => $out->id === $in->id && $out->type !== $in->type,
        ) !== []);

        return $isMixed && $clashing !== [];
    }

    /**
     * Return the key of each node of the fixture within the ancestor, in the
     * fixture's order.
     *
     * @param  array<string, non-empty-list<\SineMacula\Laravel\Authorization\Support\Reference>>  $chains
     * @param  string  $ancestor
     * @return list<string>
     */
    private static function tenantTreeWithin(array $chains, string $ancestor): array
    {
        $within = [];

        foreach ($chains as $key => $chain) {
            if (!\in_array($ancestor, \array_map(self::tenantTreeKey(...), $chain), true)) {
                continue;
            }

            $within[] = $key;
        }

        return $within;
    }

    /**
     * Return the key of each pair the subtree's rows select, keyed by itself,
     * so a pair selected twice is kept once, failing for a row without both a
     * `tenant_type` and a `tenant_id`.
     *
     * @param  iterable<mixed>  $rows
     * @param  string  $key
     * @return array<string, string>
     */
    private static function tenantTreePairs(iterable $rows, string $key): array
    {
        $pairs = [];

        foreach ($rows as $row) {
            $columns = (array) $row;
            $type    = $columns['tenant_type'] ?? null;
            $id      = $columns['tenant_id']   ?? null;

            if ((!\is_string($type) && !\is_int($type)) || (!\is_string($id) && !\is_int($id))) {
                Assert::fail("The subtree of {$key} returns a row without both a tenant_type and a tenant_id: it must select both, typed, for every tenant, never an id alone.");
            }

            $pair = self::tenantTreeKey(new Reference((string) $type, (string) $id));

            $pairs[$pair] = $pair;
        }

        return $pairs;
    }

    /**
     * Assert the pairs found are the pairs expected, compared as sets, naming
     * those missing and those extra.
     *
     * @param  array<array-key, string>  $expected
     * @param  array<array-key, string>  $actual
     * @param  string  $subject
     * @return void
     */
    private static function tenantTreeAssertPairs(array $expected, array $actual, string $subject): void
    {
        $missing = \array_diff($expected, $actual);
        $extra   = \array_diff($actual, $expected);

        Assert::assertTrue($missing === [] && $extra === [], \sprintf(
            '%s is missing %s and has %s extra.',
            $subject,
            self::tenantTreeList($missing),
            self::tenantTreeList($extra),
        ));
    }

    /**
     * Return the keys, sorted and joined, or `nothing` for none.
     *
     * @param  array<array-key, string>  $keys
     * @return string
     */
    private static function tenantTreeList(array $keys): string
    {
        \sort($keys);

        return $keys === [] ? 'nothing' : \implode(', ', $keys);
    }

    /**
     * Return the key of a tenant, which also names it in a failure: its type
     * and id, as a JSON pair.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return string
     */
    private static function tenantTreeKey(Reference $tenant): string
    {
        return \json_encode([$tenant->type, $tenant->id], \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_INVALID_UTF8_SUBSTITUTE);
    }
}
