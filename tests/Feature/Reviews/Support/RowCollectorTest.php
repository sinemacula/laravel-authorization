<?php

declare(strict_types = 1);

namespace Tests\Feature\Reviews\Support;

use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Reviews\Enums\GrantState;
use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
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

            self::assertSame([
                'ann',
                'ann',
                'perm',
                SourceKind::ROLE_PERMISSION,
                $start->key(),
                $start->scope,
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
                \array_column($row->toArray()['supporting_grants'], 'source_key'),
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
