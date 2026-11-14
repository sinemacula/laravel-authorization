<?php

declare(strict_types = 1);

namespace Tests\Feature\Usage;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\GrantUsageStore;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Reviews\Enums\GrantState;
use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
use SineMacula\Laravel\Authorization\Reviews\Enums\UsageStatus;
use SineMacula\Laravel\Authorization\Reviews\OriginScope;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Reviews\Support\ReviewUsage;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Usage\DatabaseGrantUsageStore;
use SineMacula\Laravel\Authorization\Usage\GrantUsageKey;
use SineMacula\Laravel\Authorization\Usage\UsageBatch;
use Tests\Feature\Stubs\CodedPoliciesIdentity;
use Tests\Feature\Stubs\CustomGrantsIdentity;
use Tests\Feature\Stubs\FailingPermissionsIdentity;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Fixtures\Usage\CountingUsageStore;
use Tests\TestCase;

/**
 * Feature tests for what one read of an access review knows of its rows' use:
 * `used` when observed in the window through the grant as it stands, `unused`
 * only over a window coverage reaches whole, each period taken to reach two
 * intervals past its end, `unknown` otherwise, and for every row whose source
 * cannot report; each route looked up once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReviewUsage::class)]
final class ReviewUsageTest extends TestCase
{
    /** @var string The review's instant. */
    private const string AT = '2026-11-09 12:00:00';

    /**
     * With tracking off every row is unknown and nothing is read.
     *
     * @return void
     */
    public function testWithTrackingOffEveryRowIsUnknown(): void
    {
        $store = new CountingUsageStore(new DatabaseGrantUsageStore);

        $this->app?->instance(GrantUsageStore::class, $store);

        $usage = ReviewUsage::forQuery(ReviewQuery::unused(ReviewScope::everywhere(), self::at('2026-11-09 08:00:00')), self::at(self::AT));
        $rows  = $usage->annotate([self::row(SourceKind::PERMISSION_GRANT, '2026-11-09 08:10:00')]);

        self::assertSame(UsageStatus::UNKNOWN, $rows[0]->usage?->status);
        self::assertTrue($usage->isUnobserved($rows[0]));
        self::assertSame([0, 0], [$store->lookups, $store->coverageReads]);
    }

    /**
     * A route observed in a bucket ending after the window starts is used; one
     * whose last bucket ended before it, or observed through a grant replaced
     * since, is unused over a covered window; each route is looked up once.
     *
     * @return void
     */
    public function testUseIsReadFromTheWindowAndTheGrantAsItStands(): void
    {
        $store = $this->store(['2026-11-09 07:00:00', '2026-11-09 09:00:00', '2026-11-09 11:00:00']);
        $used  = self::row(SourceKind::PERMISSION_GRANT, '2026-11-09 07:30:00', 'used');
        $old   = self::row(SourceKind::PERMISSION_GRANT, '2026-11-09 07:30:00', 'old');
        $again = self::row(SourceKind::PERMISSION_GRANT, '2026-11-09 08:30:00', 'again');

        self::observe($store, $used, '2026-11-09 09:00:00');
        self::observe($store, $old, '2026-11-09 07:00:00');
        self::observe($store, $again, '2026-11-09 09:00:00', '2026-11-09 07:30:00');

        $usage = $this->usage(ReviewQuery::unused(ReviewScope::everywhere(), self::at('2026-11-09 08:00:00')));
        $rows  = $usage->annotate([$used, $old, $again]);

        self::assertSame([UsageStatus::USED, UsageStatus::UNUSED, UsageStatus::UNUSED], \array_map(static fn (ReviewRow $row): ?UsageStatus => $row->usage?->status, $rows));
        self::assertSame('2026-11-09T09:00:00Z', ReviewRow::instant($rows[0]->usage?->lastObservedAt));
        self::assertSame('2026-11-09T07:00:00Z', ReviewRow::instant($rows[1]->usage?->lastObservedAt));
        self::assertNull($rows[2]->usage?->lastObservedAt);
        $coverage = [ReviewRow::instant($rows[1]->usage?->coverageFrom), ReviewRow::instant($rows[1]->usage?->coverageUntil)];

        self::assertSame(['2026-11-09T07:00:00Z', '2026-11-09T11:00:00Z'], $coverage);
        self::assertFalse($usage->isUnobserved($rows[0]));

        $usage->annotate([$used, $old]);

        self::assertSame([1, 1], [$store->lookups, $store->coverageReads]);
    }

    /**
     * A route starting from a break-glass activation is unknown, though a
     * grant's route of the same role in the same scope was observed, since an
     * activation's use is never tracked.
     *
     * @return void
     */
    public function testARouteFromAnActivationIsUnknown(): void
    {
        $store      = $this->store(['2026-11-09 07:00:00', '2026-11-09 09:00:00', '2026-11-09 11:00:00']);
        $grant      = self::row(SourceKind::PERMISSION_GRANT, '2026-11-09 07:30:00');
        $activation = self::row(SourceKind::PERMISSION_GRANT, '2026-11-09 07:30:00', breakGlass: ['activation' => 'a1', 'justification' => 'incident']);

        self::observe($store, $grant, '2026-11-09 09:00:00');

        $rows = $this->usage(ReviewQuery::unused(ReviewScope::everywhere(), self::at('2026-11-09 08:00:00')))->annotate([$grant, $activation]);

        self::assertSame(GrantUsageKey::ofRow($grant), GrantUsageKey::ofRow($activation));
        self::assertSame([UsageStatus::USED, UsageStatus::UNKNOWN], \array_map(static fn (ReviewRow $row): ?UsageStatus => $row->usage?->status, $rows));
    }

    /**
     * A window coverage does not reach whole is unknown: one starting before
     * tracking began, one a gap of more than two intervals interrupts, one
     * ending more than two intervals past the last period, and an empty one.
     *
     * @return void
     */
    public function testAnIncompletelyCoveredWindowIsUnknown(): void
    {
        $this->store(['2026-11-09 08:00:00', '2026-11-09 09:00:00']);

        $row = self::row(SourceKind::PERMISSION_GRANT, '2026-11-09 07:30:00');

        self::assertSame(UsageStatus::UNKNOWN, $this->statusOf($row, null, self::AT));
        self::assertSame(UsageStatus::UNKNOWN, $this->statusOf($row, '2026-11-09 08:00:00', '2026-11-09 11:00:01'));
        self::assertSame(UsageStatus::UNUSED, $this->statusOf($row, '2026-11-09 08:00:00', '2026-11-09 11:00:00'));
        self::assertSame(UsageStatus::UNKNOWN, $this->statusOf($row, '2026-11-09 13:00:00', '2026-11-09 12:00:00'));
        self::assertSame(UsageStatus::UNKNOWN, $this->statusOf(self::row(SourceKind::PERMISSION_GRANT, null), null, '2026-11-09 09:00:00'));

        $this->store(['2026-11-09 13:00:00', '2026-11-09 14:00:00']);

        self::assertSame(UsageStatus::UNKNOWN, $this->statusOf($row, '2026-11-09 08:00:00', '2026-11-09 14:00:00'));
        self::assertSame(UsageStatus::UNUSED, $this->statusOf($row, '2026-11-09 13:00:00', '2026-11-09 14:00:00'));
    }

    /**
     * A row whose source cannot report its use is unknown: a role's edge or
     * attachment, a grantee whose grants the package does not resolve or of no
     * class, and, for a policy or a role, while the application's own policy
     * resolver is bound.
     *
     * @return void
     */
    public function testARowWhoseSourceCannotReportIsUnknown(): void
    {
        $this->store(['2026-11-09 07:00:00', '2026-11-09 08:00:00', '2026-11-09 10:00:00', '2026-11-09 11:00:00']);

        self::assertSame(UsageStatus::UNUSED, $this->statusOf(self::row(SourceKind::ROLE_GRANT, '2026-11-09 07:30:00'), '2026-11-09 08:00:00', self::AT));
        self::assertSame(UsageStatus::UNUSED, $this->statusOf(self::row(SourceKind::ROLE_POLICY, '2026-11-09 07:30:00'), '2026-11-09 08:00:00', self::AT));
        self::assertSame(UsageStatus::UNKNOWN, $this->statusOf(self::row(SourceKind::ROLE_PERMISSION_EDGE, '2026-11-09 07:30:00'), '2026-11-09 08:00:00', self::AT));
        self::assertSame(UsageStatus::UNKNOWN, $this->statusOf(self::row(SourceKind::ROLE_POLICY_ATTACHMENT, '2026-11-09 07:30:00'), '2026-11-09 08:00:00', self::AT));
        $custom  = self::row(SourceKind::PERMISSION_GRANT, '2026-11-09 07:30:00', 'a', CustomGrantsIdentity::class);
        $unknown = self::row(SourceKind::PERMISSION_GRANT, '2026-11-09 07:30:00', 'a', 'no-such-class');

        self::assertSame(UsageStatus::UNKNOWN, $this->statusOf($custom, '2026-11-09 08:00:00', self::AT));
        self::assertSame(UsageStatus::UNKNOWN, $this->statusOf($unknown, '2026-11-09 08:00:00', self::AT));

        $this->app?->instance(PolicyResolver::class, \Mockery::mock(PolicyResolver::class));

        self::assertSame(UsageStatus::UNKNOWN, $this->statusOf(self::row(SourceKind::POLICY_ATTACHMENT, '2026-11-09 07:30:00'), '2026-11-09 08:00:00', self::AT));
        self::assertSame(UsageStatus::UNKNOWN, $this->statusOf(self::row(SourceKind::ROLE_INHERITED, '2026-11-09 07:30:00'), '2026-11-09 08:00:00', self::AT));
        self::assertSame(UsageStatus::UNUSED, $this->statusOf(self::row(SourceKind::ROLE_PERMISSION, '2026-11-09 07:30:00'), '2026-11-09 08:00:00', self::AT));
    }

    /**
     * Each kind of route is reported only as its grantee resolves the grants it
     * rests on: a permission's by the package's permissions, a policy's by its
     * policies, and a role's grant, or the ancestor it reaches, by both; a
     * grantee type a morph map names is read as its class.
     *
     * @return void
     */
    public function testEachKindIsReportedAsItsGranteeResolvesIt(): void
    {
        $this->store(['2026-11-09 07:00:00', '2026-11-09 08:00:00', '2026-11-09 10:00:00', '2026-11-09 11:00:00']);

        $statuses = fn (string $grantee): array => \array_map(
            fn (SourceKind $kind): ?UsageStatus => $this->statusOf(self::row($kind, '2026-11-09 07:30:00', 'p', $grantee), '2026-11-09 08:00:00', self::AT),
            [SourceKind::PERMISSION_GRANT, SourceKind::POLICY_ATTACHMENT, SourceKind::ROLE_GRANT, SourceKind::ROLE_INHERITED],
        );

        $unused  = UsageStatus::UNUSED;
        $unknown = UsageStatus::UNKNOWN;

        self::assertSame([$unused, $unused, $unused, $unused], $statuses(StubIdentity::class));
        self::assertSame([$unknown, $unused, $unknown, $unknown], $statuses(FailingPermissionsIdentity::class));
        self::assertSame([$unused, $unknown, $unknown, $unknown], $statuses(CodedPoliciesIdentity::class));

        $morphs = Relation::morphMap();

        try {
            Relation::morphMap(['stub_identity' => StubIdentity::class]);

            self::assertSame([$unused, $unused, $unused, $unused], $statuses('stub_identity'));
        } finally {
            Relation::morphMap($morphs, false);
        }
    }

    /**
     * Every row's window is read against the periods from the earliest window
     * on the page, the review's `since` before any row's creation: a row
     * created after a period's reach names no coverage, a row that records no
     * creation is read from the review's `since` and leaves the others read
     * from their own, and a period that ended before a later row's window still
     * names its coverage for a row whose window it reaches.
     *
     * @return void
     */
    public function testEachRowsWindowIsReadFromItsOwnStart(): void
    {
        $this->store(['2026-11-09 03:00:00', '2026-11-09 04:00:00']);

        $rows = $this->usage(ReviewQuery::holdings(new Reference('user', 'ann'), ReviewScope::everywhere()))->annotate([
            self::row(SourceKind::PERMISSION_GRANT, '2026-11-09 03:30:00', 'early'),
            self::row(SourceKind::PERMISSION_GRANT, '2026-11-09 10:00:00', 'late'),
        ]);

        self::assertSame(['2026-11-09T03:00:00Z', '2026-11-09T04:00:00Z'], self::coverageOf($rows[0]));
        self::assertSame([null, null], self::coverageOf($rows[1]));

        $this->store(['2026-11-09 07:00:00', '2026-11-09 08:00:00', '2026-11-09 09:00:00', '2026-11-09 10:00:00', '2026-11-09 11:00:00']);

        $rows = $this->usage(ReviewQuery::holdings(new Reference('user', 'ann'), ReviewScope::everywhere()))->annotate([
            self::row(SourceKind::PERMISSION_GRANT, null, 'none'),
            self::row(SourceKind::PERMISSION_GRANT, '2026-11-09 07:30:00', 'made'),
        ]);

        self::assertSame([UsageStatus::UNKNOWN, UsageStatus::UNUSED], [$rows[0]->usage?->status, $rows[1]->usage?->status]);

        DB::table('usage_coverage')->delete();

        $this->store(['2026-11-09 06:00:00', '2026-11-09 07:00:00', '2026-11-09 08:00:00']);

        $rows = $this->usage(ReviewQuery::unused(ReviewScope::everywhere(), self::at('2026-11-09 07:00:00')))->annotate([
            self::row(SourceKind::PERMISSION_GRANT, null, 'none'),
            self::row(SourceKind::PERMISSION_GRANT, '2026-11-09 11:00:00', 'made'),
        ]);

        self::assertSame(['2026-11-09T06:00:00Z', '2026-11-09T08:00:00Z'], self::coverageOf($rows[0]));
        self::assertSame(UsageStatus::UNKNOWN, $rows[0]->usage?->status);
    }

    /**
     * Bind a counting store over the package's, its coverage extended by a
     * flush at each instant.
     *
     * @param  list<string>  $flushes
     * @return \Tests\Fixtures\Usage\CountingUsageStore
     */
    private function store(array $flushes): CountingUsageStore
    {
        config(['authorization.usage.enabled' => true, 'authorization.usage.interval' => 3600]);

        $store = new CountingUsageStore(new DatabaseGrantUsageStore);

        foreach ($flushes as $flush) {
            $store->record(UsageBatch::of([], self::at($flush)->getTimestamp()));
        }

        $this->app?->instance(GrantUsageStore::class, $store);

        return $store;
    }

    /**
     * Return what a read of the query at the review's instant knows.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  string  $at
     * @return \SineMacula\Laravel\Authorization\Reviews\Support\ReviewUsage
     */
    private function usage(ReviewQuery $query, string $at = self::AT): ReviewUsage
    {
        return ReviewUsage::forQuery($query, self::at($at));
    }

    /**
     * Return the row's status in a review since the instant, or of holdings for
     * none, read at the instant given.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewRow  $row
     * @param  string|null  $since
     * @param  string  $at
     * @return \SineMacula\Laravel\Authorization\Reviews\Enums\UsageStatus|null
     */
    private function statusOf(ReviewRow $row, ?string $since, string $at): ?UsageStatus
    {
        $query = $since === null
            ? ReviewQuery::holdings(new Reference('user', 'ann'), ReviewScope::everywhere())
            : ReviewQuery::unused(ReviewScope::everywhere(), self::at($since));

        return $this->usage($query, $at)->annotate([$row])[0]->usage?->status;
    }

    /**
     * Record the row's route as observed in the bucket starting at the instant,
     * through a grant created as the row's, or as given.
     *
     * @param  \Tests\Fixtures\Usage\CountingUsageStore  $store
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewRow  $row
     * @param  string  $bucket
     * @param  string|null  $created
     * @return void
     */
    private static function observe(CountingUsageStore $store, ReviewRow $row, string $bucket, ?string $created = null): void
    {
        $store->record(UsageBatch::of([[
            'grant_key'         => GrantUsageKey::ofRow($row),
            'grant_source'      => 'permission',
            'grant_id'          => $row->target->id,
            'authorizable_type' => $row->grantee->type,
            'authorizable_id'   => $row->grantee->id,
            'tenant_type'       => null,
            'tenant_id'         => null,
            'application'       => null,
            'grant_created_at'  => ($created === null ? $row->createdAt() : self::at($created))?->getTimestamp(),
            'last_observed_at'  => self::at($bucket)->getTimestamp(),
        ]], self::at($bucket)->getTimestamp()));
    }

    /**
     * Return a row of the kind, created at the instant, to the target, its
     * grantee of the class given, starting from the activation given.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind  $kind
     * @param  string|null  $created
     * @param  string  $target
     * @param  string  $grantee
     * @param  array{activation: string, justification: string}|null  $breakGlass
     * @return \SineMacula\Laravel\Authorization\Reviews\ReviewRow
     */
    private static function row(SourceKind $kind, ?string $created, string $target = 'p', string $grantee = StubIdentity::class, ?array $breakGlass = null): ReviewRow
    {
        return new ReviewRow(
            'row-' . $target,
            new Reference($grantee, 'ann'),
            new Reference($grantee, 'ann'),
            new Reference('permission', $target),
            $kind,
            'source',
            new OriginScope(null, null, null, true),
            null,
            [],
            [],
            ['created_at' => $created === null ? null : self::at($created), 'updated_at' => null, 'expires_at' => null, 'route_expires_at' => null],
            null,
            GrantState::LIVE,
            breakGlass: $breakGlass,
        );
    }

    /**
     * Return the start and end of the row's coverage, as the row writes them.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewRow  $row
     * @return array{string|null, string|null}
     */
    private static function coverageOf(ReviewRow $row): array
    {
        return [ReviewRow::instant($row->usage?->coverageFrom), ReviewRow::instant($row->usage?->coverageUntil)];
    }

    /**
     * Return the instant in UTC.
     *
     * @param  string  $instant
     * @return \Carbon\CarbonImmutable
     */
    private static function at(string $instant): CarbonImmutable
    {
        return CarbonImmutable::parse($instant, 'UTC');
    }
}
