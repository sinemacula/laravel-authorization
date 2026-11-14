<?php

declare(strict_types = 1);

namespace Tests\Feature\Reviews\Support;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Reviews\Support\Definitions;
use SineMacula\Laravel\Authorization\Reviews\Support\GrantRow;
use SineMacula\Laravel\Authorization\Reviews\Support\GrantRows;
use SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActivatesBreakGlass;
use Tests\Concerns\CompilesQueries;
use Tests\Concerns\ReviewsAccess;
use Tests\TestCase;

/**
 * Feature tests for the queries a review reads stored rows through: their
 * columns, the grantees they are limited to, their order and their pages.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(GrantRows::class)]
final class GrantRowsTest extends TestCase
{
    use ActivatesBreakGlass, CompilesQueries, ReviewsAccess;

    /**
     * A grant table's rows are read with their target, grantee and every column
     * a review reads, an edge's with its permission, role and expiry.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRowsAreReadWithEveryColumnAReviewReads(): void
    {
        $role = self::role('editor');

        self::grants()->grantRole(self::identity('ann'), $role, now()->addDay(), tenant: self::tenant('t1'), includeSubtree: false, application: 'web');
        self::roles()->grantPermission($role, $permission = self::permission('posts:edit'));

        $grant = GrantRows::all(GrantRows::of(GrantTarget::ROLE), 'role')[0];

        self::assertSame(
            [Reference::of($role)->id, 'ann', 't1', 'web', false],
            [$grant->targetId, $grant->grantee->id, $grant->scope?->tenant?->id, $grant->scope?->application, $grant->scope?->includeSubtree],
        );
        self::assertNotNull($grant->expiresAt());
        self::assertNotNull($grant->times['created_at']);

        $edge = GrantRows::page(GrantRows::edges(), GrantRow::EDGE, 10, 'role')[0];

        self::assertSame([Reference::of($permission)->id, Reference::of($role)->id, null], [$edge->targetId, $edge->grantee->id, $edge->expiresAt()]);
    }

    /**
     * Role grants are read with every break-glass activation not ended or
     * expired at the run's instant, whether break-glass is enabled or not, each
     * as a role grant row with its key, justification code, activation and
     * granter, never its note; a grant's row carries none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRoleGrantsAreHeldWithTheUnexpiredActivations(): void
    {
        $role = self::role('responder');
        $ann  = self::identity('ann');

        self::grants()->grantRole($ann, $role);

        $live = self::activate($ann, $role, ['granted_by_type' => 'admin', 'granted_by_id' => '1', 'tenant_type' => 'tenant', 'tenant_id' => 't1']);

        self::activate($ann, $role, ['ended_at' => Carbon::now()]);
        self::activate($ann, $role, ['expires_at' => Carbon::now()->subSecond()]);
        self::switchBreakGlass(false);

        $built   = [];
        $queries = self::held(static function (Builder $query, string $table) use (&$built): Builder {
            $built[] = $table;

            return $query;
        });

        [$grant, $activation] = $rows = [...GrantRows::all($queries['authorizable_roles'], 'role'), ...GrantRows::all($queries['break_glass_activations'], 'role')];

        self::assertSame(['authorizable_roles', 'break_glass_activations'], $built);
        self::assertSame($built, \array_keys($queries));
        self::assertCount(2, $rows);
        self::assertNull($grant->breakGlass);
        self::assertSame(['activation' => $live->id, 'justification' => 'incident'], $activation->breakGlass);
        self::assertSame(
            [Reference::of($role)->id, 'ann', 't1', 'admin'],
            [$activation->targetId, $activation->grantee->id, $activation->scope?->tenant?->id, $activation->grantedBy?->type],
        );
        self::assertSame($live->expires_at->format('Y-m-d H:i:s'), $activation->expiresAt()?->format('Y-m-d H:i:s'));
        self::assertSame($live->activated_at->format('Y-m-d H:i:s'), $activation->times['created_at']?->format('Y-m-d H:i:s'));
        self::assertStringNotContainsString(self::NOTE, \serialize($rows));
        self::assertSame(
            ['authorizable_permissions' => GrantRows::of(GrantTarget::PERMISSION)->toSql()],
            \array_map(
                static fn (Builder $query): string => $query->toSql(),
                GrantRows::held(ReviewRun::of(ReviewScope::everywhere()), GrantTarget::PERMISSION, static fn (Builder $query): Builder => $query),
            ),
        );
    }

    /**
     * A query limited to grantees keeps each one's rows by its exact type and
     * key, and none at all for no grantee.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAQueryIsLimitedToTheGranteesByExactReference(): void
    {
        $role  = self::role('editor');
        $table = GrantTarget::ROLE->table();

        foreach ([new Reference('a', '1'), new Reference('a', '2'), new Reference('b', '1')] as $grantee) {
            self::grants()->grantRole($grantee, $role);
        }

        $read = static fn (Reference ...$grantees): array => \array_map(
            static fn (GrantRow $row): string => $row->grantee->type . ':' . $row->grantee->id,
            GrantRows::all(GrantRows::ordered(GrantRows::grantedTo(GrantRows::of(GrantTarget::ROLE), $table, \array_values($grantees)), $table, 'role_id'), 'role'),
        );

        self::assertSame(['a:1', 'b:1'], $read(new Reference('a', '1'), new Reference('b', '1')));
        self::assertSame(['a:2'], $read(new Reference('a', '2')));
        self::assertSame([], $read(new Reference('b', '2')));
        self::assertSame([], $read());
    }

    /**
     * Rows are ordered by their target first, or by it last, or, for one
     * target, not by it, then by grantee and scope, an activation after a grant
     * of the same scope, and read a page at a time by keyset, a grant's and an
     * activation's merged from one query, each limited to the page: each page
     * after any row, or from it too when asked, never at an offset.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRowsAreOrderedAndPagedByKeyset(): void
    {
        $roles = [self::role('one'), self::role('two')];
        $table = GrantTarget::ROLE->table();

        \usort($roles, static fn ($one, $other): int => \strcmp(Reference::of($one)->id, Reference::of($other)->id));

        self::grants()->grantRole(new Reference('u', 'b'), $roles[0]);
        self::grants()->grantRole(new Reference('u', 'a'), $roles[1]);
        self::grants()->grantRole(new Reference('u', 'a'), $roles[0], tenant: self::tenant('t'));
        self::grants()->grantRole(new Reference('u', 'a'), $roles[0]);
        self::activate(new Reference('u', 'a'), $roles[0], ['include_subtree' => true]);
        self::activate(new Reference('u', 'a'), $roles[1], ['tenant_type' => 'tenant', 'tenant_id' => 't', 'include_subtree' => true]);

        $describe = static fn (array $rows): array => \array_map(
            static fn (GrantRow $row): string => ($row->targetId === $roles[0]->getKey() ? 'r0' : 'r1') . ' ' . $row->grantee->id . ' ' . ($row->scope?->tenant->id ?? '-')
                . ($row->breakGlass === null ? '' : ' bg'),
            $rows,
        );

        // A query of one target is ordered, and resumed, by the grantee and the
        // scope alone.
        $queries = static fn (?bool $isTargetFirst): array => self::held(static fn (Builder $query, string $table): Builder => GrantRows::ordered(
            $isTargetFirst === null ? $query->where($table . '.role_id', $roles[0]->getKey()) : $query,
            $table,
            'role_id',
            $isTargetFirst,
        ));

        self::assertSame(['r0 a -', 'r0 a - bg', 'r0 a t', 'r0 b -', 'r1 a -', 'r1 a t bg'], $describe(self::pageFrom($queries(true), true)));
        self::assertSame(['r0 a -', 'r1 a -', 'r0 a - bg', 'r0 a t', 'r1 a t bg', 'r0 b -'], $describe(self::pageFrom($queries(false), false)));
        self::assertSame(['r0 a -', 'r0 a - bg', 'r0 a t', 'r0 b -'], $describe(self::pageFrom($queries(null), null)));

        foreach ([true, false, null] as $isTargetFirst) {
            $held = $queries($isTargetFirst);
            $all  = self::pageFrom($held, $isTargetFirst);

            self::assertSame($describe($all), $describe(self::pagedByOne($held, $isTargetFirst)));

            foreach ($all as $index => $row) {
                $position = GrantRows::positionOf($row, $isTargetFirst);

                self::assertSame($describe(\array_slice($all, $index)), $describe(self::pageFrom($held, $isTargetFirst, $position, true)), "from row {$index}");
                self::assertSame($describe(\array_slice($all, $index + 1)), $describe(self::pageFrom($held, $isTargetFirst, $position)), "after row {$index}");
            }

            // A page leaves the queries it reads as they were.
            self::assertSame($describe($all), $describe(self::pageFrom($held, $isTargetFirst)));
        }

        $read = [];

        DB::listen(static function (QueryExecuted $executed) use (&$read): void {
            $read[] = $executed->sql;
        });

        self::pageFrom($queries(true), true, null, false, 2);

        self::assertCount(1, $read);
        self::assertSame(2, \substr_count($read[0], ' limit 2'));
        self::assertStringNotContainsString(' offset ', $read[0]);

        $this->expectException(\UnexpectedValueException::class);

        GrantRows::after(GrantRows::of(GrantTarget::ROLE), 'authorizable_roles', 'role_id', true, ['short']);
    }

    /**
     * The position of the stored row a review's row starts from is read from
     * the row's sort key: its target around its grantee and scope, or the role
     * granted, the first of its route, last, or its grantee and scope alone for
     * a query of one target; an edge's is its permission, then its role.
     *
     * @return void
     */
    public function testPositionsAreReadFromARowsSortKey(): void
    {
        $key = [3, 'permission', 'p', 'u', 'a', 1, 'tenant', 1, 't', 0, '', true, 1, 'a1', 'r', 'edge'];

        self::assertSame(['p', 'u', 'a', 1, 'tenant', 1, 't', 0, '', true, 1, 'a1'], GrantRows::positionAt($key, true));
        self::assertSame(['u', 'a', 1, 'tenant', 1, 't', 0, '', true, 1, 'a1', 'r'], GrantRows::positionAt($key, false));
        self::assertSame(['u', 'a', 1, 'tenant', 1, 't', 0, '', true, 1, 'a1'], GrantRows::positionAt($key, null));
        self::assertSame(['p', 'a'], GrantRows::edgeAt($key));
        self::assertSame([null, null], GrantRows::edgeAt([6]));
        self::assertSame([null], \array_slice(GrantRows::positionAt([0], true), 0, 1));
    }

    /**
     * A grant of any other kind is ordered and resumed by its grantee and scope
     * alone, the activation's part of a position passed over, its target first
     * or left out.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOtherGrantsArePagedWithoutAnActivation(): void
    {
        $permissions = [self::permission('a'), self::permission('b')];
        $table       = GrantTarget::PERMISSION->table();

        foreach ([new Reference('u', 'b'), new Reference('u', 'a')] as $grantee) {
            foreach ($permissions as $permission) {
                self::grants()->grantPermission($grantee, $permission);
            }
        }

        $first = $permissions[0]->getKey();

        foreach ([true, null] as $isTargetFirst) {
            $ordered = static fn (): Builder => GrantRows::ordered(
                $isTargetFirst === null ? GrantRows::of(GrantTarget::PERMISSION)->where($table . '.permission_id', $first) : GrantRows::of(GrantTarget::PERMISSION),
                $table,
                'permission_id',
                $isTargetFirst,
            );

            $all  = GrantRows::page($ordered(), 'permission', 10);
            $from = GrantRows::page(GrantRows::after($ordered(), $table, 'permission_id', $isTargetFirst, GrantRows::positionOf($all[0], $isTargetFirst)), 'permission', 10);

            self::assertStringNotContainsString('break_glass_id', $ordered()->toSql());
            self::assertSame(
                \array_map(static fn (GrantRow $row): string => $row->key(), \array_slice($all, 1)),
                \array_map(static fn (GrantRow $row): string => $row->key(), $from),
            );
        }
    }

    /**
     * Role permission edges are read after the edge a page ended at, by
     * permission then role.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEdgesArePagedByPermissionThenRole(): void
    {
        $roles       = [self::role('one'), self::role('two')];
        $permissions = [self::permission('a'), self::permission('b')];

        foreach ($roles as $role) {
            foreach ($permissions as $permission) {
                self::roles()->grantPermission($role, $permission);
            }
        }

        $table   = Definitions::edges();
        $ordered = static fn (): Builder => GrantRows::edges()->orderBy($table . '.permission_id')->orderBy($table . '.role_id');
        $all     = GrantRows::page($ordered(), GrantRow::EDGE, 10, 'role');
        $key     = static fn (GrantRow $edge): array => [6, 'permission', $edge->targetId, 'role', $edge->grantee->id];

        self::assertCount(4, $all);
        $after = GrantRows::page(GrantRows::afterEdge($ordered(), GrantRows::edgeAt($key($all[1]))), GrantRow::EDGE, 10, 'role');

        self::assertSame(
            \array_map(static fn (GrantRow $edge): string => $edge->key(), \array_slice($all, 2)),
            \array_map(static fn (GrantRow $edge): string => $edge->key(), $after),
        );
        self::assertCount(3, GrantRows::page(GrantRows::afterEdge($ordered(), GrantRows::edgeAt($key($all[1])), true), GrantRow::EDGE, 10, 'role'));
    }

    /**
     * Two grants that differ only in their application come every application
     * first, then the one named, on every database.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryApplicationComesBeforeANamedOne(): void
    {
        $role  = self::role('one');
        $table = GrantTarget::ROLE->table();

        self::grants()->grantRole(new Reference('u', 'a'), $role, application: 'web');
        self::grants()->grantRole(new Reference('u', 'a'), $role, tenant: self::tenant('t'), application: 'web');
        self::grants()->grantRole(new Reference('u', 'a'), $role);
        self::grants()->grantRole(new Reference('u', 'a'), $role, tenant: self::tenant('t'));

        $read = \array_map(
            static fn (GrantRow $row): string => ($row->scope?->tenant->id ?? '-') . ' ' . ($row->scope->application ?? '-'),
            GrantRows::all(GrantRows::ordered(GrantRows::of(GrantTarget::ROLE), $table, 'role_id'), 'role'),
        );

        self::assertSame(['- -', '- web', 't -', 't web'], $read);
    }

    /**
     * The order compiles, on each driver's grammar, to the target, the
     * grantee's type and key, then the tenant's type and key and the
     * application, each of those three tagged for a null first, then the reach
     * and, for activations, their key; the target last when asked, and not at
     * all for a query of one target. A reference column is left as it is stored
     * where it compares its bytes already, as on MySQL, or only collated, as on
     * PostgreSQL; the target and the activation's key, each a UUID, are cast.
     *
     * @return void
     */
    public function testTheOrderCompilesForEachDriver(): void
    {
        $activations = 'break_glass_activations';

        foreach (self::drivers() as $driver) {
            $column = static fn (string $name, string $table = 'authorizable_roles'): string => self::wrappedOn($driver, $table . '.' . $name);
            $bytes  = static fn (string $name, string $table = 'authorizable_roles'): string => match (true) {
                $driver === 'sqlite'                        => $column($name, $table) . ' collate binary asc',
                $driver === 'pgsql' && !self::isCast($name) => $column($name, $table) . ' collate "C" asc',
                $driver === 'pgsql'                         => 'cast(' . $column($name, $table) . ' as text) collate "C" asc',
                $driver === 'mysql' && !self::isCast($name) => $column($name, $table) . ' asc',
                default                                     => 'cast(' . $column($name, $table) . ' as binary) asc',
            };
            $tagged = static fn (string $name): string => 'case when ' . $column($name) . ' is null then 0 else 1 end asc, ' . $bytes($name);
            $scope  = [
                $bytes('authorizable_type'),
                $bytes('authorizable_id'),
                $tagged('tenant_type'),
                $tagged('tenant_id'),
                $tagged('application'),
                $column('include_subtree') . ' asc',
            ];

            $first = GrantRows::ordered(self::queryOn($driver, 'authorizable_roles'), 'authorizable_roles', 'role_id')->toSql();
            $last  = GrantRows::ordered(self::queryOn($driver, 'authorizable_roles'), 'authorizable_roles', 'role_id', false)->toSql();
            $one   = GrantRows::ordered(self::queryOn($driver, 'authorizable_roles'), 'authorizable_roles', 'role_id', null)->toSql();

            self::assertStringEndsWith(' order by ' . \implode(', ', [$bytes('role_id'), ...$scope]), $first, $driver);
            self::assertStringEndsWith(' order by ' . \implode(', ', [...$scope, $bytes('role_id')]), $last, $driver);
            self::assertStringEndsWith(' order by ' . \implode(', ', $scope), $one, $driver);
            self::assertStringEndsWith(
                ' order by ' . \implode(', ', [...\str_replace('authorizable_roles', $activations, $scope), $bytes('id', $activations), $bytes('role_id', $activations)]),
                GrantRows::ordered(self::queryOn($driver, $activations), $activations, 'role_id', false)->toSql(),
                $driver,
            );
        }
    }

    /**
     * Determine whether the column is cast to be ordered: the role's key and
     * the activation's, which are no reference columns.
     *
     * @param  string  $name
     * @return bool
     */
    private static function isCast(string $name): bool
    {
        return \in_array($name, ['role_id', 'id'], true);
    }

    /**
     * Return the queries of the role grants and the unexpired activations a
     * review of everywhere made now reads, each built by the callback.
     *
     * @param  \Closure(\Illuminate\Database\Query\Builder, string): \Illuminate\Database\Query\Builder  $build
     * @return non-empty-array<string, \Illuminate\Database\Query\Builder>
     */
    private static function held(\Closure $build): array
    {
        return GrantRows::held(ReviewRun::of(ReviewScope::everywhere()), GrantTarget::ROLE, $build);
    }

    /**
     * Read a page of the ordered role queries together: after the position, or
     * from it when asked, or from the start given none.
     *
     * @param  non-empty-array<string, \Illuminate\Database\Query\Builder>  $queries
     * @param  bool|null  $isTargetFirst
     * @param  list<bool|int|string|null>|null  $position
     * @param  bool  $isInclusive
     * @param  int  $limit
     * @return list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>
     */
    private static function pageFrom(array $queries, ?bool $isTargetFirst, ?array $position = null, bool $isInclusive = false, int $limit = 10): array
    {
        $from = static fn (Builder $query, string $table): Builder => $position === null
            ? $query
            : GrantRows::after($query, $table, 'role_id', $isTargetFirst, $position, $isInclusive);

        return GrantRows::pageOf($queries, $from, 'role', $limit, $isTargetFirst);
    }

    /**
     * Read the ordered role queries together one row at a time, each page by
     * keyset after the row the page before read, until none is left.
     *
     * @param  non-empty-array<string, \Illuminate\Database\Query\Builder>  $queries
     * @param  bool|null  $isTargetFirst
     * @return list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>
     */
    private static function pagedByOne(array $queries, ?bool $isTargetFirst): array
    {
        $read = [];
        $last = null;

        do {
            $page = self::pageFrom($queries, $isTargetFirst, $last === null ? null : GrantRows::positionOf($last, $isTargetFirst), false, 1);
            $last = $page[0] ?? null;

            \array_push($read, ...$page);
        } while ($last !== null);

        return $read;
    }
}
