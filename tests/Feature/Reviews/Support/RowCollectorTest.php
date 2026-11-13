<?php

declare(strict_types = 1);

namespace Tests\Feature\Reviews\Support;

use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Reviews\Enums\GrantState;
use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
use SineMacula\Laravel\Authorization\Reviews\Enums\SubjectState;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Reviews\Support\GrantRow;
use SineMacula\Laravel\Authorization\Reviews\Support\ReviewOrder;
use SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun;
use SineMacula\Laravel\Authorization\Reviews\Support\RowCollector;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\TestCase;

/**
 * Feature tests for the rows one run of a review collects: each built from the
 * row its route starts from and those it rests on, bounded by the limit and one
 * more, ordered as collected or sorted into the review's order.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(RowCollector::class)]
final class RowCollectorTest extends TestCase
{
    /**
     * A route's row names its subject, grantee, target, start, scope, path, the
     * rows it rests on, the earliest of their expiries and its start's state,
     * and its key is the same for the same route.
     *
     * @return void
     */
    public function testARoutesRowIsBuiltFromItsRows(): void
    {
        Carbon::setTestNow(new Carbon('2030-01-01 00:00:00', 'UTC'));

        try {
            $run   = ReviewRun::of(ReviewScope::everywhere());
            $rows  = new RowCollector($run, 5);
            $start = self::grant('ann', 'role-1', '2031-01-01 00:00:00');
            $edge  = GrantRow::from((object) ['target_id' => 'perm', 'grantee_id' => 'role-2', 'expires_at' => '2030-06-01 00:00:00'], GrantRow::EDGE, 'role');

            $rows->route(
                SourceKind::ROLE_PERMISSION,
                new Reference('u', 'ann'),
                $start,
                new Reference('permission', 'perm'),
                ['role-1', 'role-2'],
                [$edge],
                new Reference('person', 'p'),
            );
            $rows->route(
                SourceKind::ROLE_PERMISSION,
                new Reference('u', 'ann'),
                $start,
                new Reference('permission', 'perm'),
                ['role-1', 'role-2'],
                [$edge],
                new Reference('person', 'p'),
            );
            $rows->route(SourceKind::ROLE_GRANT, new Reference('u', 'ann'), self::grant('ann', 'role-1', '2029-01-01 00:00:00'), new Reference('role', 'role-1'), ['role-1']);

            [$row, $same, $expired] = $rows->rows();

            $supporting = $row->toArray()['supporting_grants'];

            self::assertIsArray($supporting);
            self::assertSame([
                'ann',
                'ann',
                'perm',
                SourceKind::ROLE_PERMISSION,
                $start->key(),
                $start->originScope(),
                'p',
                [(new Role)->getMorphClass(), (new Role)->getMorphClass()],
                ['role-1', 'role-2'],
                [$start->key(), $edge->key()],
                '2030-06-01T00:00:00Z',
                '2031-01-01T00:00:00Z',
                null,
                GrantState::LIVE,
            ], [
                $row->subject->id,
                $row->grantee->id,
                $row->target->id,
                $row->sourceKind,
                $row->sourceKey,
                $row->originScope,
                $row->viaIdentity?->id,
                \array_map(static fn (Reference $role): string => $role->type, $row->rolePath),
                \array_map(static fn (Reference $role): string => $role->id, $row->rolePath),
                \array_column($supporting, 'source_key'),
                $row->toArray()['route_expires_at'],
                $row->toArray()['expires_at'],
                $row->grantedBy,
                $row->grantState,
            ]);

            self::assertSame(
                \hash('sha256', ReviewOrder::key(['role_permission', 'u', 'ann', 'permission', 'perm', $start->key(), $edge->key(), 'role-1', 'role-2'])),
                $row->rowKey,
            );
            self::assertSame($row->rowKey, $same->rowKey);
            self::assertNotSame($row->rowKey, $expired->rowKey);
            self::assertSame(GrantState::EXPIRED, $expired->grantState);
            self::assertCount(1, $expired->supportingGrants);
            self::assertNull(self::route(self::grant('ann', 'r', null))->routeExpiresAt());
        } finally {
            Carbon::setTestNow();
        }
    }

    /**
     * A route starting from a break-glass activation is marked with its key and
     * justification code, and is a row of its own after the route of a grant of
     * the same role in the same scope.
     *
     * @return void
     */
    public function testARouteFromAnActivationIsMarkedAndKeptApart(): void
    {
        $rows       = new RowCollector(ReviewRun::of(ReviewScope::everywhere()), 5);
        $columns    = ['target_id' => 'r', 'grantee_type' => 'u', 'grantee_id' => 'ann', 'include_subtree' => true, 'justification' => 'incident'];
        $activation = GrantRow::from((object) [...$columns, 'break_glass_id' => 'a1'], 'role');

        $rows->route(SourceKind::ROLE_GRANT, new Reference('u', 'ann'), $activation, new Reference('role', 'r'), ['r']);
        $rows->route(SourceKind::ROLE_GRANT, new Reference('u', 'ann'), self::grant('ann', 'r', null), new Reference('role', 'r'), ['r']);

        [$grant, $activated] = $rows->rows(true);

        self::assertNull($grant->breakGlass);
        self::assertSame(['activation' => 'a1', 'justification' => 'incident'], $activated->breakGlass);
        self::assertSame($activation->key(), $activated->sourceKey);
        self::assertNotSame($grant->rowKey, $activated->rowKey);
    }

    /**
     * A route resting on a row that never expires and one that does expires
     * when that one does, the never-expiring row passed over rather than taken
     * as the earliest.
     *
     * @return void
     */
    public function testARouteOverRowsWithAndWithoutAnExpiryEndsAtTheDatedOne(): void
    {
        $rows  = new RowCollector(ReviewRun::of(ReviewScope::everywhere()), 5);
        $start = self::grant('ann', 'role-1', null);
        $edge  = GrantRow::from((object) ['target_id' => 'perm', 'grantee_id' => 'role-1', 'expires_at' => '2030-06-01 00:00:00'], GrantRow::EDGE, 'role');

        $rows->route(SourceKind::ROLE_PERMISSION, new Reference('u', 'ann'), $start, new Reference('permission', 'perm'), ['role-1'], [$edge]);

        $row = $rows->rows()[0];

        self::assertSame('2030-06-01T00:00:00Z', $row->toArray()['route_expires_at']);
        self::assertNull($row->toArray()['expires_at']);
    }

    /**
     * The run needs one more row than the limit, so the room left counts down
     * to none, the rows are truncated only when more were collected than the
     * limit, and only the limit's worth is returned.
     *
     * @return void
     */
    public function testTheRowsAreBoundedByTheLimitAndOneMore(): void
    {
        $rows = new RowCollector(ReviewRun::of(ReviewScope::everywhere()), 2);

        self::assertSame([3, false, false], [$rows->room(), $rows->isFull(), $rows->isTruncated()]);

        foreach (['a', 'b'] as $grantee) {
            $rows->route(SourceKind::ROLE_GRANT, new Reference('u', $grantee), self::grant($grantee, 'r', null), new Reference('role', 'r'));
        }

        self::assertSame([1, false, false], [$rows->room(), $rows->isFull(), $rows->isTruncated()]);

        $rows->route(SourceKind::ROLE_GRANT, new Reference('u', 'c'), self::grant('c', 'r', null), new Reference('role', 'r'));

        self::assertSame([0, true, true], [$rows->room(), $rows->isFull(), $rows->isTruncated()]);

        $rows->route(SourceKind::ROLE_GRANT, new Reference('u', 'd'), self::grant('d', 'r', null), new Reference('role', 'r'));

        self::assertSame(0, $rows->room());
        self::assertSame(['a', 'b'], \array_map(static fn (ReviewRow $row): string => $row->subject->id, $rows->rows()));
    }

    /**
     * A collector with a filter keeps only the rows it keeps, and counts only
     * those against its limit and truncation.
     *
     * @return void
     */
    public function testAFilterKeepsOnlyTheRowsItKeeps(): void
    {
        $rows = new RowCollector(ReviewRun::of(ReviewScope::everywhere()), 1, null, static fn (ReviewRow $row): bool => $row->subject->id !== 'b');

        foreach (['a', 'b'] as $grantee) {
            $rows->route(SourceKind::ROLE_GRANT, new Reference('u', $grantee), self::grant($grantee, 'r', null), new Reference('role', 'r'));
        }

        self::assertSame([1, false, false], [$rows->room(), $rows->isFull(), $rows->isTruncated()]);

        $rows->route(SourceKind::ROLE_GRANT, new Reference('u', 'c'), self::grant('c', 'r', null), new Reference('role', 'r'));

        self::assertSame([0, true, true], [$rows->room(), $rows->isFull(), $rows->isTruncated()]);
        self::assertSame(['a'], \array_map(static fn (ReviewRow $row): string => $row->subject->id, $rows->rows()));
    }

    /**
     * Narrowing keeps only the rows the narrowing returns, by their index among
     * every row collected, each as it gives it, with its sort key and place, so
     * the limit, the truncation and where the next page starts count the rows
     * kept alone; narrowing to none leaves nothing.
     *
     * @return void
     */
    public function testNarrowingKeepsOnlyTheRowsItReturns(): void
    {
        $rows = new RowCollector(ReviewRun::of(ReviewScope::everywhere()), 2);

        foreach (['e', 'd', 'c', 'b', 'a'] as $grantee) {
            $rows->route(SourceKind::ROLE_GRANT, new Reference('u', $grantee), self::grant($grantee, 'r', null), new Reference('role', 'r'), ['r']);
        }

        $given = [];

        $rows->narrow(static function (array $read) use (&$given): array {
            $given = \array_map(static fn (ReviewRow $row): string => $row->subject->id, $read);

            return [3 => $read[3]->withSubjectState(SubjectState::ACTIVE), 1 => $read[1], 4 => $read[4]];
        });

        self::assertSame(['e', 'd', 'c', 'b', 'a'], $given);
        self::assertSame([true, 0], [$rows->isTruncated(), $rows->room()]);
        self::assertSame(['d', 'b'], \array_map(static fn (ReviewRow $row): string => $row->subject->id, $rows->rows()));
        self::assertSame(SubjectState::ACTIVE, $rows->rows()[1]->subjectState);
        self::assertSame(['a', 'b'], \array_map(static fn (ReviewRow $row): string => $row->subject->id, $rows->rows(true)));
        self::assertSame([0, 'role', 'r', 'u', 'b', 0, '', 0, '', 0, '', true, 0, '', 'r', 1], $rows->next());

        $rows->narrow(static fn (array $read): array => []);

        self::assertSame([[], false, null, 3], [$rows->rows(), $rows->isTruncated(), $rows->next(), $rows->room()]);
    }

    /**
     * Rows come in the order collected, or sorted by kind, target, grantee,
     * scope and route when asked.
     *
     * @return void
     */
    public function testRowsAreSortedIntoTheReviewsOrderWhenAsked(): void
    {
        $rows = new RowCollector(ReviewRun::of(ReviewScope::everywhere()), 10);

        $rows->route(SourceKind::PERMISSION_GRANT, new Reference('u', 'a'), self::grant('a', 'p', null), new Reference('permission', 'p'));
        $rows->route(SourceKind::ROLE_GRANT, new Reference('u', 'b'), self::grant('b', 'r2', null), new Reference('role', 'r2'), ['r2']);
        $rows->route(SourceKind::ROLE_GRANT, new Reference('u', 'b'), self::grant('b', 'r1', null), new Reference('role', 'r1'), ['r1']);
        $rows->route(SourceKind::ROLE_GRANT, new Reference('u', 'a'), self::grant('a', 'r1', null), new Reference('role', 'r1'), ['r1']);

        $order = static fn (array $read): array => \array_map(
            static fn (ReviewRow $row): string => $row->sourceKind->value . ' ' . $row->target->id . ' ' . $row->grantee->id,
            $read,
        );

        self::assertSame(['permission_grant p a', 'role_grant r2 b', 'role_grant r1 b', 'role_grant r1 a'], $order($rows->rows()));
        self::assertSame(['role_grant r1 a', 'role_grant r1 b', 'role_grant r2 b', 'permission_grant p a'], $order($rows->rows(true)));
    }

    /**
     * A later page collects only the rows after the last row of the page
     * before: one at or before it is passed over, a kind before it is past, and
     * the kind it is of resumes from it; a first page reads everything.
     *
     * @return void
     */
    public function testALaterPageCollectsOnlyTheRowsAfterTheLastOne(): void
    {
        $run   = ReviewRun::of(ReviewScope::everywhere());
        $first = new RowCollector($run, 10);

        foreach (SourceKind::cases() as $kind) {
            self::assertSame([false, null], [$first->isPast($kind), $first->resumeAt($kind)]);
        }

        $first->route(SourceKind::ROLE_INHERITED, new Reference('u', 'b'), self::grant('b', 'r', null), new Reference('role', 'r'), ['r']);

        $last  = self::lastKeyOf($first);
        $later = new RowCollector($run, 10, $last);

        self::assertSame([true, null], [$later->isPast(SourceKind::ROLE_GRANT), $later->resumeAt(SourceKind::ROLE_GRANT)]);
        self::assertSame([false, $last], [$later->isPast(SourceKind::ROLE_INHERITED), $later->resumeAt(SourceKind::ROLE_INHERITED)]);
        self::assertSame([false, null], [$later->isPast(SourceKind::PERMISSION_GRANT), $later->resumeAt(SourceKind::PERMISSION_GRANT)]);

        foreach (['a', 'b', 'c'] as $grantee) {
            $later->route(SourceKind::ROLE_INHERITED, new Reference('u', $grantee), self::grant($grantee, 'r', null), new Reference('role', 'r'), ['r']);
        }

        $later->route(SourceKind::ROLE_GRANT, new Reference('u', 'z'), self::grant('z', 'r', null), new Reference('role', 'r'), ['r']);
        $later->route(SourceKind::PERMISSION_GRANT, new Reference('u', 'a'), self::grant('a', 'p', null), new Reference('permission', 'p'));

        self::assertSame(['c', 'a'], \array_map(static fn (ReviewRow $row): string => $row->subject->id, $later->rows()));
        self::assertSame(9, $later->room());
    }

    /**
     * A route is keyed among those of its stored row by the first role of its
     * chain and how many roles the chain runs through, then the keys of the
     * rows it rests on, so its key, and a row's sort key, stays the same size
     * however deep the chain runs; a route with no chain is keyed by its rows
     * alone.
     *
     * @return void
     */
    public function testARouteIsKeyedByItsFirstRoleAndItsLength(): void
    {
        $edge  = self::grant('r', 'p', null);
        $chain = \array_map(static fn (int $level): string => 'role-' . $level, \range(1, 300));

        self::assertSame([], RowCollector::routeKey([], []));
        self::assertSame([$edge->key()], RowCollector::routeKey([], [$edge]));
        self::assertSame(['a', 1], RowCollector::routeKey(['a'], []));
        self::assertSame(['a', 3, $edge->key()], RowCollector::routeKey(['a', 'b', 'c'], [$edge]));
        self::assertSame(['role-1', 300], RowCollector::routeKey($chain, []));

        $rows = new RowCollector(ReviewRun::of(ReviewScope::everywhere()), 2);

        $rows->route(SourceKind::ROLE_INHERITED, new Reference('u', 'a'), self::grant('a', 'role-1', null), new Reference('role', 'role-300'), $chain);
        $rows->route(SourceKind::ROLE_INHERITED, new Reference('u', 'b'), self::grant('b', 'role-1', null), new Reference('role', 'role-300'), $chain);
        $rows->route(SourceKind::ROLE_INHERITED, new Reference('u', 'c'), self::grant('c', 'role-1', null), new Reference('role', 'role-300'), $chain);

        self::assertSame([1, 'role', 'role-300', 'u', 'b', 0, '', 0, '', 0, '', true, 0, '', 'role-1', 300], $rows->next());
        self::assertSame(['role-1', 300], \array_slice($rows->next(), RowCollector::ROUTE));
    }

    /**
     * The next page starts after the last row returned, in the order the rows
     * were last returned in, and there is none when no row was left out.
     *
     * @return void
     */
    public function testTheNextPageStartsAfterTheLastRowReturned(): void
    {
        $rows = new RowCollector(ReviewRun::of(ReviewScope::everywhere()), 2);

        foreach (['c', 'a', 'b'] as $grantee) {
            $rows->route(SourceKind::ROLE_GRANT, new Reference('u', $grantee), self::grant($grantee, 'r', null), new Reference('role', 'r'), ['r']);
        }

        $rows->rows();

        self::assertSame('a', $rows->next()[4] ?? null);

        $rows->rows(true);

        self::assertSame([0, 'role', 'r', 'u', 'b', 0, '', 0, '', 0, '', true, 0, '', 'r', 1], $rows->next());

        $short = new RowCollector(ReviewRun::of(ReviewScope::everywhere()), 2);

        $short->route(SourceKind::ROLE_GRANT, new Reference('u', 'a'), self::grant('a', 'r', null), new Reference('role', 'r'), ['r']);

        self::assertNull($short->next());
    }

    /**
     * Return the sort key of the only row collected, read as the next page
     * would start after it.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\RowCollector  $rows
     * @return list<bool|int|string|null>
     */
    private static function lastKeyOf(RowCollector $rows): array
    {
        $row = $rows->rows()[0];

        return [SourceKind::ROLE_INHERITED->position(), $row->target->type, $row->target->id, 'u', $row->subject->id, 0, '', 0, '', 0, '', true, 'r', 1];
    }

    /**
     * Return the row of a direct route from the grant.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\GrantRow  $grant
     * @return \SineMacula\Laravel\Authorization\Reviews\ReviewRow
     */
    private static function route(GrantRow $grant): ReviewRow
    {
        $rows = new RowCollector(ReviewRun::of(ReviewScope::everywhere()), 1);

        $rows->route(SourceKind::ROLE_GRANT, $grant->grantee, $grant, new Reference('role', $grant->targetId));

        return $rows->rows()[0];
    }

    /**
     * Return a platform-wide grant of the role to the grantee, expiring when
     * given.
     *
     * @param  string  $grantee
     * @param  string  $role
     * @param  string|null  $expiresAt
     * @return \SineMacula\Laravel\Authorization\Reviews\Support\GrantRow
     */
    private static function grant(string $grantee, string $role, ?string $expiresAt): GrantRow
    {
        return GrantRow::from((object) ['target_id' => $role, 'grantee_type' => 'u', 'grantee_id' => $grantee, 'expires_at' => $expiresAt, 'include_subtree' => true], 'role');
    }
}
