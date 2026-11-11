<?php

declare(strict_types = 1);

namespace Tests\Fixtures\TenantTrees;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\ColumnDefinition;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * A tenant tree kept in a closure table whose tenant keys are typed columns, an
 * integer or a UUID, as a tree over integer- or UUID-keyed records keeps them:
 * its ancestors and `isWithin()` compare the keys in their own type, and its
 * subtree selects each key as text, so it can be nested in a query of the
 * package's tables, which hold keys as strings.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class KeyedTenantTree implements TenantTree
{
    /** @var string The closure table keyed by integers. */
    public const string NUMBERED = 'scoped_numbered_tenant_closure';

    /** @var string The closure table keyed by UUIDs. */
    public const string UUID = 'scoped_uuid_tenant_closure';

    /**
     * Create a new tree kept in the closure table.
     *
     * @param  string  $table
     */
    public function __construct(

        /** The closure table. */
        private string $table,
    ) {}

    /**
     * Create both closure tables.
     *
     * @return void
     */
    public static function createTables(): void
    {
        $keys = [
            self::NUMBERED => static fn (Blueprint $schema, string $column): ColumnDefinition => $schema->bigInteger($column),
            self::UUID     => static fn (Blueprint $schema, string $column): ColumnDefinition => $schema->uuid($column),
        ];

        foreach ($keys as $table => $key) {
            Schema::create($table, static function (Blueprint $schema) use ($key): void {
                foreach (['ancestor', 'descendant'] as $end) {
                    $schema->string($end . '_type', 191);
                    $key($schema, $end . '_id');
                }

                $schema->unsignedInteger('depth');
            });
        }
    }

    /**
     * Seed the tree with the nodes, each under its parent, or at the top, every
     * parent before its children.
     *
     * @param  list<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: \SineMacula\Laravel\Authorization\Support\Reference|null}>  $nodes
     * @return void
     */
    public function seed(array $nodes): void
    {
        foreach ($nodes as [$node, $parent]) {
            $rows = [self::row($node, $node, 0)];

            foreach ($parent === null ? [] : [$parent, ...$this->ancestors($parent)] as $depth => $ancestor) {
                $rows[] = self::row($ancestor, $node, $depth + 1);
            }

            DB::table($this->table)->insert($rows);
        }
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
        $rows = DB::table($this->table)
            ->where('descendant_type', $tenant->type)
            ->where('descendant_id', $tenant->id)
            ->where('depth', '>', 0)
            ->orderBy('depth')
            ->get(['ancestor_type', 'ancestor_id']);

        $ancestors = [];

        foreach ($rows as $row) {
            ['ancestor_type' => $type, 'ancestor_id' => $id] = (array) $row;

            $ancestors[] = new Reference((string) $type, (string) $id); // @phpstan-ignore cast.string, cast.string
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
        return DB::table($this->table)
            ->where('ancestor_type', $ancestor->type)
            ->where('ancestor_id', $ancestor->id)
            ->where('descendant_type', $tenant->type)
            ->where('descendant_id', $tenant->id)
            ->exists();
    }

    /**
     * Return the tenant and every tenant below it, each key selected as text.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \Illuminate\Contracts\Database\Query\Builder
     */
    #[\Override]
    public function subtree(Reference $tenant): Builder
    {
        $text = DB::connection()->getDriverName() === 'mysql' ? 'char' : 'text';

        return DB::table($this->table)
            ->select(['descendant_type as tenant_type'])
            ->selectRaw("cast(descendant_id as {$text}) as tenant_id")
            ->where('ancestor_type', $tenant->type)
            ->where('ancestor_id', $tenant->id);
    }

    /**
     * Return a row of the closure table.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $descendant
     * @param  int  $depth
     * @return array<string, int|string>
     */
    private static function row(Reference $ancestor, Reference $descendant, int $depth): array
    {
        return [
            'ancestor_type'   => $ancestor->type,
            'ancestor_id'     => $ancestor->id,
            'descendant_type' => $descendant->type,
            'descendant_id'   => $descendant->id,
            'depth'           => $depth,
        ];
    }
}
