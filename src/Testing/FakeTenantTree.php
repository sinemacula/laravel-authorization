<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Testing;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * An in-memory tenant tree for an application's tests, built from typed nodes,
 * so a test can bind a hierarchy without a table of its own.
 *
 * Build it from each node and its parent, or null for a tenant at the top,
 * every parent before its children, through `of()`, or node by node through
 * `add()`, which returns the tree, and bind it as the tenant tree. Nodes are
 * told apart by type and id together, so tenants of different types sharing an
 * id are never confused, and ids are compared byte for byte. A tenant the tree
 * does not hold is a tenant at the top with nothing below it, as the flat
 * default tree has it.
 *
 * The subtree is a query of typed literal rows, a `UNION ALL` of one select for
 * each tenant, in groups nested as derived tables past the most selects SQLite
 * takes in one compound select, reading no table, so it runs and nests on any
 * database the package supports, however many tenants it holds. It is on the
 * connection that is the application's default when the subtree is asked for,
 * unless the tree is built for a connection named: `whereAuthorized()` needs it
 * on the connection of the models it scopes, and the grant scope query on the
 * package's connection (`authorization.connection`), so a test whose models or
 * package tables are on another connection names that one.
 *
 * The tree can change once bound: `move()` puts a node under another parent, or
 * at the top. As with a real tree, the package keeps what it has read of the
 * tree for the request, so a test moving a node reports the change through
 * `Authorization::treeChanged($tenant)` before the move takes effect.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class FakeTenantTree implements TenantTree
{
    /** The most selects one compound select joins: SQLite's limit. */
    private const int TERMS = 500;

    /** The alias the subtree's rows, and each group of them, are read under. */
    private const string ROWS = 'fake_tenant_tree';

    /** @var array<string, \SineMacula\Laravel\Authorization\Support\Reference> Each node of the tree, by its key, in the order added. */
    private array $nodes = [];

    /** @var array<string, \SineMacula\Laravel\Authorization\Support\Reference|null> Each node's parent, or null for one at the top, by the node's key. */
    private array $parents = [];

    /**
     * Create a new, empty fake tenant tree.
     *
     * @param  string|null  $connection
     */
    public function __construct(

        /** The connection the subtree is a query on, or null for the application's default. */
        private readonly ?string $connection = null,
    ) {}

    /**
     * Return a tree of the nodes, each with its parent, or null for a tenant at
     * the top, every parent before its children.
     *
     * @param  iterable<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: \SineMacula\Laravel\Authorization\Support\Reference|null}>  $nodes
     * @param  string|null  $connection
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function of(iterable $nodes, ?string $connection = null): self
    {
        $tree = new self($connection);

        foreach ($nodes as [$node, $parent]) {
            $tree->add($node, $parent);
        }

        return $tree;
    }

    /**
     * Add the node under the parent, or at the top of the tree for none,
     * refusing a node the tree already holds and a parent it does not.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $node
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $parent
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function add(Reference $node, ?Reference $parent = null): self
    {
        $key = self::key($node);

        if (\array_key_exists($key, $this->nodes)) {
            throw new \InvalidArgumentException('The fake tenant tree already holds ' . self::name($node) . ': move it instead.');
        }

        $this->parents[$key] = $this->parentOf($node, $parent);
        $this->nodes[$key]   = $node;

        return $this;
    }

    /**
     * Put the node the tree holds under another parent, or at the top for none,
     * refusing a parent it does not hold and one that is the node or below it.
     * Report the move through `Authorization::treeChanged()`.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $node
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $parent
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function move(Reference $node, ?Reference $parent): self
    {
        $key = self::key($node);

        if (!\array_key_exists($key, $this->nodes)) {
            throw new \InvalidArgumentException('The fake tenant tree does not hold ' . self::name($node) . ': add it instead.');
        }

        $this->parents[$key] = $this->parentOf($node, $parent);

        return $this;
    }

    /**
     * Return the tenant's ancestors, nearest first.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    #[\Override]
    public function ancestors(Reference $tenant): array
    {
        $ancestors = [];
        $key       = self::key($tenant);

        while (($parent = $this->parents[$key] ?? null) !== null) {
            $ancestors[] = $parent;
            $key         = self::key($parent);
        }

        return $ancestors;
    }

    /**
     * Determine whether the tenant is the ancestor or below it.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
     * @return bool
     */
    #[\Override]
    public function isWithin(Reference $tenant, Reference $ancestor): bool
    {
        $key = self::key($ancestor);

        foreach ([$tenant, ...$this->ancestors($tenant)] as $node) {
            if (self::key($node) === $key) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return the tenant and every node below it, as a query of typed literal
     * rows on the tree's connection.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \Illuminate\Contracts\Database\Query\Builder
     */
    #[\Override]
    public function subtree(Reference $tenant): Builder
    {
        $rows     = [$tenant, ...$this->below($tenant)];
        $terms    = \array_fill(0, \count($rows), 'select ? as tenant_type, ? as tenant_id');
        $bindings = \array_merge(...\array_map(static fn (Reference $node): array => [$node->type, $node->id], $rows));

        return DB::connection($this->connection)->query()
            ->select(['tenant_type', 'tenant_id'])
            ->fromRaw('(' . self::union($terms) . ') as ' . self::ROWS, $bindings);
    }

    /**
     * Return every node below the tenant, nearest first.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    private function below(Reference $tenant): array
    {
        $children = [];

        foreach ($this->parents as $key => $parent) {
            if ($parent === null) {
                continue;
            }

            $children[self::key($parent)][] = $key;
        }

        $keys = [self::key($tenant)];

        for ($index = 0; $index < \count($keys); $index++) {
            \array_push($keys, ...($children[$keys[$index]] ?? []));
        }

        return \array_map(fn (string $key): Reference => $this->nodes[$key], \array_slice($keys, 1));
    }

    /**
     * Return the selects as one `UNION ALL`, or, past the most selects SQLite
     * takes in one compound select, as a `UNION ALL` of groups of them, each
     * nested as a derived table, so any number of rows is one query on every
     * database.
     *
     * @param  list<literal-string>  $terms
     * @return literal-string
     */
    private static function union(array $terms): string
    {
        if (\count($terms) <= self::TERMS) {
            return \implode(' union all ', $terms);
        }

        $groups = [];

        foreach (\array_chunk($terms, self::TERMS) as $group) {
            $groups[] = 'select tenant_type, tenant_id from (' . self::union($group) . ') as ' . self::ROWS;
        }

        return self::union($groups);
    }

    /**
     * Return the parent the tree holds for the node, or null for none, refusing
     * a parent the tree does not hold and one that is the node or below it.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $node
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $parent
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     *
     * @throws \InvalidArgumentException
     */
    private function parentOf(Reference $node, ?Reference $parent): ?Reference
    {
        if ($parent === null) {
            return null;
        }

        if (!\array_key_exists(self::key($parent), $this->nodes)) {
            throw new \InvalidArgumentException('The fake tenant tree does not hold ' . self::name($parent) . ', the parent given for ' . self::name($node) . ': add it first.');
        }

        if ($this->isWithin($parent, $node)) {
            throw new \InvalidArgumentException('The fake tenant tree cannot put ' . self::name($node) . ' under ' . self::name($parent) . ', which is it or below it.');
        }

        return $parent;
    }

    /**
     * Return the key a tenant is held under: its type and id, each as hex, so
     * that ids differing in any byte are told apart.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return string
     */
    private static function key(Reference $tenant): string
    {
        return \bin2hex($tenant->type) . ':' . \bin2hex($tenant->id);
    }

    /**
     * Return the tenant's name in a refusal: its type and id, as a JSON pair.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return string
     */
    private static function name(Reference $tenant): string
    {
        return \json_encode([$tenant->type, $tenant->id], \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_INVALID_UTF8_SUBSTITUTE);
    }
}
