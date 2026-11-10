<?php

declare(strict_types = 1);

namespace Tests\Feature\Reviews\Support;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Reviews\ApplicationSelector;
use SineMacula\Laravel\Authorization\Reviews\Enums\GrantState;
use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Reviews\Support\GrantRow;
use SineMacula\Laravel\Authorization\Reviews\Support\StoredRows;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsAdministrator;
use Tests\Concerns\ReviewsAccess;
use Tests\TestCase;

/**
 * Feature tests for the stored rows a review of expiries or of an actor lists:
 * grants, attachments and role edges whose expiry falls in the UTC half-open
 * window, and grants whose `granted_by` pair is the actor's, the last writer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(StoredRows::class)]
final class StoredRowsTest extends TestCase
{
    use ActsAsAdministrator, ReviewsAccess;

    /**
     * Freeze the clock at the start of 2030, in UTC.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(new Carbon('2030-01-01 00:00:00', 'UTC'));
    }

    /**
     * Unfreeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * Every kind of stored row expiring in the window is listed, kind by kind:
     * a role grant, a permission grant, a policy attachment, a role's policy
     * attachment, and a role's permission edge.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryKindOfRowExpiringInTheWindowIsListed(): void
    {
        $at   = new Carbon('2030-06-01 00:00:00', 'UTC');
        $ann  = self::identity('ann');
        $role = self::role('editor');

        self::grants()->grantRole($ann, $role, $at);
        self::grants()->grantPermission($ann, self::permission('posts:read'), $at);
        self::grants()->attachPolicy($ann, self::policy('deny-own'), $at);
        self::grants()->attachPolicy($role, self::policy('deny-role'), $at);
        self::roles()->grantPermission($role, self::permission('posts:edit'), $at);

        self::grants()->grantPermission($ann, self::permission('forever:read'));

        $rows = self::trusted(ReviewQuery::expiring(ReviewScope::everywhere(), $at->copy()->subDay(), $at->copy()->addDay()))->rows;

        self::assertSame([
            SourceKind::ROLE_GRANT,
            SourceKind::PERMISSION_GRANT,
            SourceKind::POLICY_ATTACHMENT,
            SourceKind::ROLE_PERMISSION_EDGE,
            SourceKind::ROLE_POLICY_ATTACHMENT,
        ], \array_map(static fn (ReviewRow $row): SourceKind => $row->sourceKind, $rows));

        self::assertSame($role->getKey(), $rows[3]->subject->id);
        self::assertNull($rows[3]->originScope);
        self::assertSame($role->getKey(), $rows[4]->subject->id);
        self::assertSame('2030-06-01T00:00:00Z', $rows[0]->toArray()['expires_at']);

        // A role's grant, its permission edge and its policy attachment name
        // the role as their path; a grant of a permission or a policy none.
        self::assertSame(
            [[$role->getKey()], [], [], [$role->getKey()], [$role->getKey()]],
            \array_map(static fn (ReviewRow $row): array => \array_map(static fn (Reference $path): string => $path->id, $row->rolePath), $rows),
        );

        // Each row's key names the table it is stored in, and the row it rests
        // on is that same stored row.
        $sources = [GrantTarget::ROLE->value, GrantTarget::PERMISSION->value, GrantTarget::POLICY->value, GrantRow::EDGE, GrantTarget::POLICY->value];

        foreach ($rows as $index => $row) {
            self::assertStringStartsWith(\strlen($sources[$index]) . ':' . $sources[$index] . '|', $row->sourceKey);
            self::assertSame([$row->sourceKey], \array_column($row->toArray()['supporting_grants'], 'source_key'));
        }
    }

    /**
     * Stored rows are read a page at a time by keyset, each page after the
     * stored row its last row is, and a kind of row before that row's is not
     * read again: the pages together are the whole review, expiries and an
     * actor's grants alike, whatever the page size.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testStoredRowsResumeAfterTheLastRowOfThePageBefore(): void
    {
        self::keyCursors();

        $at    = new Carbon('2030-06-01 00:00:00', 'UTC');
        $actor = new Reference('user', 'writer');

        foreach (['ann', 'bob'] as $index => $id) {
            $grantee = self::identity($id);
            $role    = self::role('editor-' . $index);

            self::grants()->grantRole($grantee, $role, $at);
            self::grants()->grantPermission($grantee, self::permission('posts:read-' . $index), $at);
            self::grants()->attachPolicy($grantee, self::policy('deny-own-' . $index), $at);
            self::grants()->attachPolicy($role, self::policy('deny-role-' . $index), $at);
            self::roles()->grantPermission($role, self::permission('posts:edit-' . $index), $at);
        }

        foreach (['authorizable_roles', 'authorizable_permissions', 'authorizable_policies'] as $table) {
            DB::table($table)->update(['granted_by_type' => $actor->type, 'granted_by_id' => $actor->id]);
        }

        $queries = [
            ReviewQuery::expiring(ReviewScope::everywhere(), $at->copy()->subDay(), $at->copy()->addDay()),
            ReviewQuery::grantedBy($actor, ReviewScope::everywhere()),
        ];

        foreach ($queries as $query) {
            $whole = self::described(self::trusted($query->withLimit(1000)));

            self::assertGreaterThanOrEqual(8, \count($whole));

            foreach ([1, 2, 3] as $size) {
                self::assertSame($whole, \array_map(self::describe(...), self::pagedThrough($query, $size)['rows']), "by {$size}");
            }

            $readsRoleGrants = static fn (string $sql): bool => \str_contains(\str_replace(['"', '`'], '', $sql), 'from authorizable_roles');
            $roleGrants      = \array_map(static fn (array $page): int => \count(\array_filter($page, $readsRoleGrants)), self::pagedThrough($query, 1)['queries']);

            self::assertSame([1, 1, 1, ...\array_fill(0, \count($whole) - 3, 0)], $roleGrants);
        }
    }

    /**
     * A review of unused grants lists the live grants of each kind to grantees,
     * never an expired one, a role's edge or a role's attachment; with tracking
     * off each reads unknown, so every one is listed, and paging through them
     * returns each once, in the order of a whole read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testUnusedGrantsResumeAfterTheLastRowOfThePageBefore(): void
    {
        self::keyCursors();

        foreach (['ann', 'bob'] as $index => $id) {
            $grantee = self::identity($id);
            $role    = self::role('editor-' . $index);

            self::grants()->grantRole($grantee, $role);
            self::grants()->grantPermission($grantee, self::permission('posts:read-' . $index));
            self::grants()->attachPolicy($grantee, self::policy('deny-own-' . $index));
            self::grants()->attachPolicy($role, self::policy('deny-role-' . $index));
            self::grants()->grantPermission($grantee, self::permission('posts:gone-' . $index), new Carbon('2030-01-01 00:00:01', 'UTC'));
            self::roles()->grantPermission($role, self::permission('posts:edit-' . $index));
        }

        Carbon::setTestNow(new Carbon('2030-01-02 00:00:00', 'UTC'));

        $query = ReviewQuery::unused(ReviewScope::everywhere(), new Carbon('2029-01-01 00:00:00', 'UTC'));
        $whole = self::described(self::trusted($query));

        self::assertSame([
            'role_grant ann [editor-0] editor-0',
            'role_grant bob [editor-1] editor-1',
            'permission_grant ann posts:read-0',
            'permission_grant bob posts:read-1',
            'policy_attachment ann deny-own-0',
            'policy_attachment bob deny-own-1',
        ], $whole);

        foreach ([1, 2, 4] as $size) {
            self::assertSame($whole, \array_map(self::describe(...), self::pagedThrough($query, $size)['rows']), "by {$size}");
        }
    }

    /**
     * Role permission edges expiring in the window come in the review's order:
     * by their permission first, then by their role.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testExpiringEdgesAreOrderedByPermissionThenRole(): void
    {
        $at    = new Carbon('2030-06-01 00:00:00', 'UTC');
        $roles = [self::role('first'), self::role('second')];
        $perms = [self::permission('first:read'), self::permission('second:read')];

        $byKey = static fn ($one, $other): int => \strcmp((string) $one->getKey(), (string) $other->getKey());

        \usort($roles, $byKey);
        \usort($perms, $byKey);

        self::roles()->grantPermission($roles[0], $perms[1], $at);
        self::roles()->grantPermission($roles[1], $perms[0], $at);
        self::roles()->grantPermission($roles[0], $perms[0], $at);

        $rows = self::trusted(ReviewQuery::expiring(ReviewScope::everywhere(), $at->copy()->subDay(), $at->copy()->addDay()))->rows;

        self::assertSame(
            [
                [$perms[0]->getKey(), $roles[0]->getKey()],
                [$perms[0]->getKey(), $roles[1]->getKey()],
                [$perms[1]->getKey(), $roles[0]->getKey()],
            ],
            \array_map(static fn (ReviewRow $row): array => [$row->target->id, $row->subject->id], $rows),
        );
    }

    /**
     * The window keeps the fractions of its bounds: a row expiring on the
     * second before a start with a fraction is not in it, one expiring on the
     * next second is, and one expiring on the second before an end with a
     * fraction is in it too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheWindowKeepsTheFractionsOfItsBounds(): void
    {
        $at = static fn (string $time): Carbon => new Carbon('2030-06-01 ' . $time, 'UTC');

        self::grants()->grantPermission(self::identity('before'), self::permission('before:read'), $at('10:00:00'));
        self::grants()->grantPermission(self::identity('first'), self::permission('first:read'), $at('10:00:01'));
        self::grants()->grantPermission(self::identity('last'), self::permission('last:read'), $at('11:00:00'));
        self::grants()->grantPermission(self::identity('after'), self::permission('after:read'), $at('11:00:01'));

        $listed = static fn (Carbon $from, Carbon $until): array => \array_map(
            static fn (ReviewRow $row): string => $row->subject->id,
            self::trusted(ReviewQuery::expiring(ReviewScope::everywhere(), $from, $until))->rows,
        );

        self::assertEqualsCanonicalizing(['first', 'last'], $listed($at('10:00:00.700000'), $at('11:00:00.500000')));
        self::assertEqualsCanonicalizing(['before', 'first', 'last'], $listed($at('10:00:00'), $at('11:00:01')));
        self::assertEqualsCanonicalizing(['first', 'last', 'after'], $listed($at('10:00:00.000001'), $at('11:00:01.000001')));

        // A window within one second holds no whole second, so no expiry.
        self::assertSame([], $listed($at('10:00:00.200000'), $at('10:00:00.800000')));
    }

    /**
     * The window is half-open: a row expiring at its start is in it, one
     * expiring at its end is not, whatever zone the bounds are given in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheWindowIsHalfOpenInUtc(): void
    {
        $start = new Carbon('2030-06-01 00:00:00', 'UTC');
        $end   = new Carbon('2030-06-02 00:00:00', 'UTC');

        self::grants()->grantPermission(self::identity('start'), self::permission('start:read'), $start);
        self::grants()->grantPermission(self::identity('end'), self::permission('end:read'), $end);
        self::grants()->grantPermission(self::identity('before'), self::permission('before:read'), $start->copy()->subSecond());

        $zoned = ReviewQuery::expiring(ReviewScope::everywhere(), $start->copy()->setTimezone('America/New_York'), $end->copy()->setTimezone('Asia/Tokyo'));

        self::assertSame(['start'], \array_map(static fn (ReviewRow $row): string => $row->subject->id, self::trusted($zoned)->rows));
    }

    /**
     * An expiry beyond 2038 is read and listed as any other.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExpiryBeyond2038IsListed(): void
    {
        $far = new Carbon('2099-12-31 23:59:59', 'UTC');

        self::grants()->grantRole(self::identity('ann'), self::role('distant'), $far);

        $rows = self::trusted(ReviewQuery::expiring(ReviewScope::everywhere(), $far->copy()->subYear(), $far->copy()->addYear()))->rows;

        self::assertCount(1, $rows);
        self::assertSame('2099-12-31T23:59:59Z', $rows[0]->toArray()['expires_at']);
        self::assertSame(GrantState::LIVE, $rows[0]->grantState);
    }

    /**
     * A row that has already expired at the review's instant is listed, marked
     * expired; one expiring exactly now has expired.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARowAlreadyExpiredIsMarkedExpired(): void
    {
        $now = Carbon::now('UTC');

        self::grants()->grantPermission(self::identity('soon'), self::permission('soon:read'), $now->copy()->addMinute());

        Carbon::setTestNow($now->copy()->addMinute());

        $rows = self::trusted(ReviewQuery::expiring(ReviewScope::everywhere(), $now, $now->copy()->addDay()))->rows;

        self::assertCount(1, $rows);
        self::assertSame(GrantState::EXPIRED, $rows[0]->grantState);
    }

    /**
     * A review of what applies in a tenant lists the expiring rows that apply
     * there, and a role edge only when the tenant sees its role and permission;
     * a review rooted within a tenant lists the edges of the roles owned there
     * or below.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testExpiringRowsFollowTheScope(): void
    {
        $this->tree();

        $at     = new Carbon('2030-06-01 00:00:00', 'UTC');
        $owned  = self::role('owned', null, self::tenant('acct1'));
        $shared = self::role('shared');

        self::roles()->grantPermission($owned, self::permission('owned:read'), $at);
        self::roles()->grantPermission($shared, self::permission('shared:read'), $at);

        self::grants()->grantPermission(self::identity('in'), self::permission('in:read'), $at, tenant: self::tenant('acct1'));
        self::grants()->grantPermission(self::identity('out'), self::permission('out:read'), $at, tenant: self::tenant('acct2'));

        $window = static fn (ReviewScope $scope): array => \array_map(
            static fn (ReviewRow $row): string => $row->sourceKind->value . ' ' . $row->subject->id,
            self::trusted(ReviewQuery::expiring($scope, $at->copy()->subDay(), $at->copy()->addDay()))->rows,
        );

        self::assertEqualsCanonicalizing(
            ['permission_grant in', 'role_permission_edge ' . Reference::of($owned)->id, 'role_permission_edge ' . Reference::of($shared)->id],
            $window(ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::none())),
        );

        self::assertEqualsCanonicalizing(
            ['permission_grant out', 'role_permission_edge ' . Reference::of($shared)->id],
            $window(ReviewScope::appliesIn(self::tenant('acct2'), ApplicationSelector::none())),
        );
        self::assertEqualsCanonicalizing(['permission_grant in', 'role_permission_edge ' . Reference::of($owned)->id], $window(ReviewScope::rootedWithin(self::tenant('acct1'))));
    }

    /**
     * In a review of what applies in a tenant, a role's policy attachment is
     * listed only when the tenant sees the role, as a check reaches it only
     * through that role, whether the review lists expiries or an actor's
     * grants; a review rooted within a tenant lists the attachments made there.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolesPolicyAttachmentNeedsTheRoleSeen(): void
    {
        $this->tree();

        $at    = new Carbon('2030-06-01 00:00:00', 'UTC');
        $actor = new Reference('user', 'writer');
        $owned = self::role('owned', null, self::tenant('acct1'));

        self::grants()->attachPolicy($owned, self::policy('deny-owned'), $at);
        self::grants()->attachPolicy(self::role('shared'), self::policy('deny-shared'), $at);

        DB::table(GrantTarget::POLICY->table())->update(['granted_by_type' => $actor->type, 'granted_by_id' => $actor->id]);

        $listed = static fn (ReviewQuery $query): array => \array_map(static fn (ReviewRow $row): string => $row->target->id, self::trusted($query)->rows);
        $policy = static fn (string $name): string => Reference::of(Policy::query()->where('name', $name)->firstOrFail())->id;

        foreach (['acct1' => ['deny-owned', 'deny-shared'], 'acct2' => ['deny-shared']] as $tenant => $names) {
            $scope    = ReviewScope::appliesIn(self::tenant($tenant), ApplicationSelector::none());
            $expected = \array_map($policy, $names);

            self::assertEqualsCanonicalizing($expected, $listed(ReviewQuery::expiring($scope, $at->copy()->subDay(), $at->copy()->addDay())));
            self::assertEqualsCanonicalizing($expected, $listed(ReviewQuery::grantedBy($actor, $scope)));
        }

        self::assertSame([], $listed(ReviewQuery::grantedBy($actor, ReviewScope::rootedWithin(self::tenant('acct1')))));
        self::assertCount(2, $listed(ReviewQuery::grantedBy($actor, ReviewScope::everywhere())));
    }

    /**
     * A review of an actor's grants lists the rows whose `granted_by` pair is
     * the actor's: the last writer, so a regrant by another actor moves the row
     * to that actor, and a trusted write names no actor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testGrantedByListsTheLastWriter(): void
    {
        $first  = self::administrator(id: 'first');
        $second = self::administrator(id: 'second');
        $ann    = self::identity('ann');
        $role   = self::role('reviewed');

        self::grants()->grantRole($ann, $role, actor: $first);
        self::grants()->grantRole(self::identity('bob'), $role);

        $byFirst = static fn (): array => \array_map(
            static fn (ReviewRow $row): string => $row->subject->id,
            self::trusted(ReviewQuery::grantedBy(new Reference($first->principal()->type, 'first'), ReviewScope::everywhere()))->rows,
        );

        self::assertSame(['ann'], $byFirst());
        self::assertSame('first', self::trusted(ReviewQuery::grantedBy($first->principal(), ReviewScope::everywhere()))->rows[0]->grantedBy?->id);

        self::grants()->grantRole($ann, $role, new Carbon('2031-01-01 00:00:00', 'UTC'), $second);

        self::assertSame([], $byFirst());
        self::assertSame(
            ['ann'],
            \array_map(static fn (ReviewRow $row): string => $row->subject->id, self::trusted(ReviewQuery::grantedBy($second->principal(), ReviewScope::everywhere()))->rows),
        );
        self::assertSame([], self::trusted(ReviewQuery::grantedBy(new Reference($first->principal()->type, 'nobody'), ReviewScope::everywhere()))->rows);
    }
}
