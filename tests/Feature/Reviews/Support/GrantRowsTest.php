<?php

declare(strict_types = 1);

namespace Tests\Feature\Reviews\Support;

use Illuminate\Database\Query\Builder;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Reviews\Support\Definitions;
use SineMacula\Laravel\Authorization\Reviews\Support\GrantRow;
use SineMacula\Laravel\Authorization\Reviews\Support\GrantRows;
use SineMacula\Laravel\Authorization\Support\Reference;
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
    use CompilesQueries, ReviewsAccess;

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

        $read = static fn (array $grantees): array => \array_map(
            static fn (GrantRow $row): string => $row->grantee->type . ':' . $row->grantee->id,
            GrantRows::all(GrantRows::ordered(GrantRows::grantedTo(GrantRows::of(GrantTarget::ROLE), $table, $grantees), $table, 'role_id'), 'role'),
        );

        self::assertSame(['a:1', 'b:1'], $read([new Reference('a', '1'), new Reference('b', '1')]));
        self::assertSame(['a:2'], $read([new Reference('a', '2')]));
        self::assertSame([], $read([new Reference('b', '2')]));
        self::assertSame([], $read([]));
    }

    /**
     * Rows are ordered by their target first, or by it last, or, for one
     * target, not by it, then by grantee and scope, and read a page at a time
     * by keyset: each page after the row the page before ended at, or from it
     * too when asked, never at an offset.
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

        $describe = static fn (array $rows): array => \array_map(
            static fn (GrantRow $row): string => ($row->targetId === $roles[0]->getKey() ? 'r0' : 'r1') . ' ' . $row->grantee->id . ' ' . ($row->scope?->tenant->id ?? '-'),
            $rows,
        );

        // A query of one target is ordered, and resumed, by the grantee and the
        // scope alone.
        $ordered = static fn (?bool $isTargetFirst): Builder => GrantRows::ordered(
            $isTargetFirst === null ? GrantRows::of(GrantTarget::ROLE)->where($table . '.role_id', $roles[0]->getKey()) : GrantRows::of(GrantTarget::ROLE),
            $table,
            'role_id',
            $isTargetFirst,
        );

        self::assertSame(['r0 a -', 'r0 a t', 'r0 b -', 'r1 a -'], $describe(GrantRows::page($ordered(true), 'role', 10)));
        self::assertSame(['r0 a -', 'r1 a -', 'r0 a t', 'r0 b -'], $describe(GrantRows::page($ordered(false), 'role', 10)));
        self::assertSame(['r0 a -', 'r0 a t', 'r0 b -'], $describe(GrantRows::page($ordered(null), 'role', 10)));

        foreach ([true, false, null] as $isTargetFirst) {
            $all = GrantRows::page($ordered($isTargetFirst), 'role', 10);

            self::assertSame($describe($all), $describe(self::pagedByOne(static fn (): Builder => $ordered($isTargetFirst), $isTargetFirst)));

            $from = GrantRows::after($ordered($isTargetFirst), $table, 'role_id', $isTargetFirst, GrantRows::positionOf($all[1], $isTargetFirst), true);

            self::assertSame($describe(\array_slice($all, 1)), $describe(GrantRows::page($from, 'role', 10)));
        }
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
        $key = [3, 'permission', 'p', 'u', 'a', 1, 'tenant', 1, 't', 0, '', true, 'r', 'edge'];

        self::assertSame(['p', 'u', 'a', 1, 'tenant', 1, 't', 0, '', true], GrantRows::positionAt($key, true));
        self::assertSame(['u', 'a', 1, 'tenant', 1, 't', 0, '', true, 'r'], GrantRows::positionAt($key, false));
        self::assertSame(['u', 'a', 1, 'tenant', 1, 't', 0, '', true], GrantRows::positionAt($key, null));
        self::assertSame(['p', 'a'], GrantRows::edgeAt($key));
        self::assertSame([null, null], GrantRows::edgeAt([6]));
        self::assertSame([null], \array_slice(GrantRows::positionAt([0], true), 0, 1));
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
     * application, each of those three tagged for a null first, then the reach;
     * the target last when asked, and not at all for a query of one target. A
     * reference column is left as it is stored where it compares its bytes
     * already, as on MySQL, or only collated, as on PostgreSQL; the target, a
     * UUID, is cast.
     *
     * @return void
     */
    public function testTheOrderCompilesForEachDriver(): void
    {
        foreach (self::drivers() as $driver) {
            $column = static fn (string $name): string => self::wrappedOn($driver, 'authorizable_roles.' . $name);
            $bytes  = static fn (string $name): string => match (true) {
                $driver === 'sqlite'                       => $column($name) . ' collate binary asc',
                $driver === 'pgsql' && $name !== 'role_id' => $column($name) . ' collate "C" asc',
                $driver === 'pgsql'                        => 'cast(' . $column($name) . ' as text) collate "C" asc',
                $driver === 'mysql' && $name !== 'role_id' => $column($name) . ' asc',
                default                                    => 'cast(' . $column($name) . ' as binary) asc',
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
        }
    }

    /**
     * Read the ordered grants of the role table one at a time, each page by
     * keyset after the grant the page before read, until none is left.
     *
     * @param  \Closure(): \Illuminate\Database\Query\Builder  $ordered
     * @param  bool|null  $isTargetFirst
     * @return list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>
     *
     * @throws \UnexpectedValueException
     */
    private static function pagedByOne(\Closure $ordered, ?bool $isTargetFirst): array
    {
        $table = GrantTarget::ROLE->table();
        $read  = [];
        $last  = null;

        do {
            $query = $last === null ? $ordered() : GrantRows::after($ordered(), $table, 'role_id', $isTargetFirst, GrantRows::positionOf($last, $isTargetFirst));
            $page  = GrantRows::page($query, 'role', 1);
            $last  = $page[0] ?? null;

            \array_push($read, ...$page);
        } while ($last !== null);

        return $read;
    }
}
