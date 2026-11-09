<?php

declare(strict_types = 1);

namespace Tests\Feature\Reviews\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
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

        $edge = GrantRows::page(GrantRows::edges(), GrantRow::EDGE, 0, 10, 'role')[0];

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
     * Rows are ordered by their target first, or by it last, then by grantee
     * and scope, and read a page at a time.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRowsAreOrderedAndPaged(): void
    {
        $roles = [self::role('one'), self::role('two')];
        $table = GrantTarget::ROLE->table();

        \usort($roles, static fn ($one, $other): int => \strcmp(Reference::of($one)->id, Reference::of($other)->id));

        self::grants()->grantRole(new Reference('u', 'b'), $roles[0]);
        self::grants()->grantRole(new Reference('u', 'a'), $roles[1]);
        self::grants()->grantRole(new Reference('u', 'a'), $roles[0], tenant: self::tenant('t'));
        self::grants()->grantRole(new Reference('u', 'a'), $roles[0]);

        $first = static fn (bool $isTargetFirst, int $offset = 0, int $limit = 10): array => \array_map(
            static fn (GrantRow $row): string => ($row->targetId === $roles[0]->getKey() ? 'r0' : 'r1') . ' ' . $row->grantee->id . ' ' . ($row->scope?->tenant->id ?? '-'),
            GrantRows::page(GrantRows::ordered(GrantRows::of(GrantTarget::ROLE), $table, 'role_id', $isTargetFirst), 'role', $offset, $limit),
        );

        self::assertSame(['r0 a -', 'r0 a t', 'r0 b -', 'r1 a -'], $first(true));
        self::assertSame(['r0 a -', 'r1 a -', 'r0 a t', 'r0 b -'], $first(false));
        self::assertSame(['r0 a t', 'r0 b -'], $first(true, 1, 2));
        self::assertSame(['r1 a -'], $first(true, 3, 2));
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
     * the target last when asked.
     *
     * @return void
     */
    public function testTheOrderCompilesForEachDriver(): void
    {
        foreach (self::drivers() as $driver) {
            $column = static fn (string $name): string => self::wrappedOn($driver, 'authorizable_roles.' . $name);
            $bytes  = static fn (string $name): string => match ($driver) {
                'sqlite' => $column($name) . ' collate binary',
                'pgsql'  => 'cast(' . $column($name) . ' as text) collate "C"',
                default  => 'cast(' . $column($name) . ' as binary)',
            };
            $tagged = static fn (string $name): string => 'case when ' . $column($name) . ' is null then 0 else 1 end, ' . $bytes($name);
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

            self::assertStringEndsWith(' order by ' . \implode(', ', [$bytes('role_id'), ...$scope]), $first, $driver);
            self::assertStringEndsWith(' order by ' . \implode(', ', [...$scope, $bytes('role_id')]), $last, $driver);
        }
    }
}
