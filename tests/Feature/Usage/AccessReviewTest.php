<?php

declare(strict_types = 1);

namespace Tests\Feature\Usage;

use Carbon\CarbonImmutable;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\GrantUsageStore;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Reviews\AccessReview;
use SineMacula\Laravel\Authorization\Reviews\Enums\UsageStatus;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewResult;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Usage\DatabaseGrantUsageStore;
use SineMacula\Laravel\Authorization\Usage\GrantUsageKey;
use SineMacula\Laravel\Authorization\Usage\UsageBatch;
use Tests\Concerns\ReviewsAccess;
use Tests\Concerns\TracksGrantUsage;
use Tests\Feature\Stubs\CustomGrantsIdentity;
use Tests\Fixtures\Usage\CountingUsageStore;
use Tests\TestCase;

/**
 * Feature tests for what an access review says of each row's use (N94): `used`,
 * `unused` only over a fully covered window, `unknown` otherwise, a regrant
 * never inheriting the old grant's use while an expiry or reach rewrite keeps
 * it, the unused review listing only the grants with no observed use, paged,
 * streamed and exported with their `usage`, in one batched lookup a page, from
 * a store the application may rebind.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AccessReview::class)]
final class AccessReviewTest extends TestCase
{
    use ReviewsAccess, TracksGrantUsage;

    /**
     * Over a window tracking covered whole, a route observed reads `used` and
     * one never observed `unused`; each says when its period of coverage ran.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACoveredWindowReadsUsedOrUnused(): void
    {
        $this->heartbeatAt('2026-11-09 08:00:00');

        Carbon::setTestNow('2026-11-09 08:10:00');

        $ann = self::identity('ann');

        self::grants()->grantPermission($ann, self::permission('posts:read'));
        self::grants()->grantPermission($ann, self::permission('posts:write'));

        $this->heartbeatAt('2026-11-09 09:30:00');

        Carbon::setTestNow('2026-11-09 09:45:00');

        self::assertTrue($this->actAs($ann)->check('posts:read')->isAllowed());
        self::assertSame(1, $this->recordObserved());

        Carbon::setTestNow('2026-11-09 10:20:00');

        $usage = self::usageOf(self::holdings($ann));

        self::assertSame('used', $usage['posts:read']['status']);
        self::assertSame('2026-11-09T09:00:00Z', $usage['posts:read']['last_observed_at']);
        self::assertSame('unused', $usage['posts:write']['status']);
        self::assertNull($usage['posts:write']['last_observed_at']);
        self::assertSame(['2026-11-09T08:00:00Z', '2026-11-09T09:45:00Z'], [$usage['posts:write']['coverage_from'], $usage['posts:write']['coverage_until']]);
    }

    /**
     * A window that starts before tracking began, or that a gap of more than
     * two intervals interrupts, reads `unknown`; a missing observation is never
     * taken as proof of non-use.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIncompletelyCoveredWindowReadsUnknown(): void
    {
        Carbon::setTestNow('2026-11-09 07:00:00');

        $ann = self::identity('ann');

        self::grants()->grantPermission($ann, self::permission('posts:write'));

        $this->heartbeatAt('2026-11-09 08:00:00');
        $this->heartbeatAt('2026-11-09 09:00:00');

        Carbon::setTestNow('2026-11-09 09:30:00');

        self::assertSame('unknown', self::usageOf(self::holdings($ann))['posts:write']['status']);
        self::assertSame('unused', self::usageOf(self::unused('2026-11-09 08:00:00'))['posts:write']['status']);

        $this->heartbeatAt('2026-11-09 14:00:00');

        Carbon::setTestNow('2026-11-09 14:10:00');

        self::assertSame('unknown', self::usageOf(self::unused('2026-11-09 08:00:00'))['posts:write']['status']);
        self::assertSame('unused', self::usageOf(self::unused('2026-11-09 14:00:00'))['posts:write']['status']);
    }

    /**
     * A grant revoked and made again never inherits the old grant's use, while
     * a grant whose expiry or reach is rewritten in place keeps its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARegrantDoesNotInheritUseButARewriteKeepsIt(): void
    {
        $this->heartbeatAt('2026-11-09 08:00:00');

        Carbon::setTestNow('2026-11-09 08:10:00');

        $ann  = self::identity('ann');
        $read = self::permission('posts:read');

        self::grants()->grantPermission($ann, $read);

        Carbon::setTestNow('2026-11-09 08:20:00');

        $this->actAs($ann)->check('posts:read');
        $this->recordObserved();

        Carbon::setTestNow('2026-11-09 08:30:00');

        $this->tree();

        $write  = self::permission('posts:write');
        $tenant = self::tenant('org1');

        self::grants()->grantPermission($ann, $write, null, null, $tenant);
        self::observe(self::rowOf(self::holdings($ann), 'posts:write'));

        self::assertSame(GrantOutcome::EXPIRY_CHANGED, self::grants()->grantPermission($ann, $read, CarbonImmutable::parse('2027-01-01 00:00:00')));
        self::assertSame(GrantOutcome::REACH_CHANGED, self::grants()->grantPermission($ann, $write, null, null, $tenant, false));

        $usage = self::usageOf(self::holdings($ann));

        self::assertSame(['used', 'used'], [$usage['posts:read']['status'], $usage['posts:write']['status']]);

        Carbon::setTestNow('2026-11-09 08:40:00');

        self::grants()->revokePermission($ann, $read);
        self::grants()->grantPermission($ann, $read);

        Carbon::setTestNow('2026-11-09 08:50:00');

        $usage = self::usageOf(self::holdings($ann));

        self::assertSame('unused', $usage['posts:read']['status']);
        self::assertNull($usage['posts:read']['last_observed_at']);
    }

    /**
     * The unused review lists the live grants with no observed use since its
     * instant, unused or unknown, and leaves out the used; with tracking
     * reporting nothing for a grantee that resolves its own grants.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheUnusedReviewListsGrantsWithNoObservedUse(): void
    {
        $this->heartbeatAt('2026-11-09 08:00:00');

        Carbon::setTestNow('2026-11-09 08:10:00');

        $ann    = self::identity('ann');
        $custom = CustomGrantsIdentity::query()->create(['id' => 'custom']);
        $role   = self::role('editor');

        $role->givePermissionTo(self::permission('posts:edit'));

        self::grants()->grantRole($ann, $role);
        self::grants()->grantPermission($ann, self::permission('posts:read'));
        self::grants()->grantPermission($custom, self::permission('reports:write'));
        self::grants()->attachPolicy($ann, self::policy('no-delete'));

        Carbon::setTestNow('2026-11-09 08:20:00');

        $this->actAs($ann)->check('posts:edit');
        $this->recordObserved();

        Carbon::setTestNow('2026-11-09 08:30:00');

        $result = self::unused('2026-11-09 08:00:00');
        $usage  = self::usageOf($result);

        self::assertSame(['no-delete', 'posts:read', 'reports:write'], self::sortedKeys($usage));
        self::assertSame('unused', $usage['posts:read']['status']);
        self::assertSame('unused', $usage['no-delete']['status']);
        self::assertSame('unknown', $usage['reports:write']['status']);
        self::assertFalse($result->isTruncated);
    }

    /**
     * Paging, streaming and exporting the unused review carry each row's
     * `usage`, and each page reads its routes in one batched lookup from the
     * store bound, which an application may replace.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPagesStreamsAndExportsCarryUsageFromOneLookupAPage(): void
    {
        $store = new CountingUsageStore(new DatabaseGrantUsageStore);

        $this->app?->instance(GrantUsageStore::class, $store);
        $this->heartbeatAt('2026-11-09 08:00:00');

        Carbon::setTestNow('2026-11-09 08:10:00');

        foreach (['a', 'b', 'c', 'd', 'e'] as $id) {
            self::grants()->grantPermission(self::identity('user-' . $id), self::permission('posts:' . $id));
        }

        Carbon::setTestNow('2026-11-09 08:30:00');
        self::keyCursors();

        $store->lookups = 0;

        $paged = self::pagedThrough(ReviewQuery::unused(ReviewScope::everywhere(), CarbonImmutable::parse('2026-11-09 08:00:00')), 2);

        self::assertCount(5, $paged['rows']);
        self::assertSame(3, $store->lookups);
        self::assertSame(['unused'], \array_values(\array_unique(\array_map(static fn (ReviewRow $row): string => $row->usage?->status->value ?? 'unknown', $paged['rows']))));

        $store->lookups = 0;

        $unused   = ReviewQuery::unused(ReviewScope::everywhere(), CarbonImmutable::parse('2026-11-09 08:00:00'));
        $streamed = \iterator_to_array(app(AccessReview::class)->trustedStream($unused, 2), false);

        self::assertCount(5, $streamed);
        self::assertSame(3, $store->lookups);
        self::assertSame(UsageStatus::UNUSED, $streamed[4]->usage?->status);

        $lines = [];

        app(AccessReview::class)->trustedExport($unused, static function (string $line) use (&$lines): void {
            $lines[] = \json_decode($line, true, 512, \JSON_THROW_ON_ERROR);
        }, 2);

        $rows = \array_values(\array_filter($lines, static fn (array $line): bool => isset($line['usage'])));

        self::assertCount(5, $rows);
        self::assertSame('unused', $rows[0]['usage']['status']);
    }

    /**
     * Return the row of the result whose target has the name.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewResult  $result
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Reviews\ReviewRow
     */
    private static function rowOf(ReviewResult $result, string $name): ReviewRow
    {
        foreach ($result->rows as $row) {
            if (self::nameOf($row->target) === $name) {
                return $row;
            }
        }

        self::fail("No row targets {$name}.");
    }

    /**
     * Record the row's route as observed now, through its grant as it stands.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewRow  $row
     * @return void
     */
    private static function observe(ReviewRow $row): void
    {
        $origin = $row->originScope;

        app(GrantUsageStore::class)->record(new UsageBatch([[
            'grant_key'         => GrantUsageKey::ofRow($row),
            'grant_source'      => 'permission',
            'grant_id'          => $row->target->id,
            'authorizable_type' => $row->grantee->type,
            'authorizable_id'   => $row->grantee->id,
            'tenant_type'       => $origin?->tenantType,
            'tenant_id'         => $origin?->tenantId,
            'application'       => $origin?->application,
            'grant_created_at'  => $row->createdAt()?->getTimestamp(),
            'last_observed_at'  => Carbon::now()->startOfHour()->getTimestamp(),
        ]], Carbon::now()->getTimestamp()));
    }

    /**
     * Return the review of the subject's holdings everywhere.
     *
     * @param  object  $subject
     * @return \SineMacula\Laravel\Authorization\Reviews\ReviewResult
     */
    private static function holdings(object $subject): ReviewResult
    {
        return self::trusted(ReviewQuery::holdings(new Subject($subject, $subject), ReviewScope::everywhere()));
    }

    /**
     * Return the unused review everywhere since the instant.
     *
     * @param  string  $since
     * @return \SineMacula\Laravel\Authorization\Reviews\ReviewResult
     */
    private static function unused(string $since): ReviewResult
    {
        return self::trusted(ReviewQuery::unused(ReviewScope::everywhere(), CarbonImmutable::parse($since)));
    }

    /**
     * Return each row's `usage`, by its target's name.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewResult  $result
     * @return array<string, array{status: string, last_observed_at: string|null, coverage_from: string|null, coverage_until: string|null}>
     */
    private static function usageOf(ReviewResult $result): array
    {
        $usage = [];

        foreach ($result->rows as $row) {
            /** @var array{status: string, last_observed_at: string|null, coverage_from: string|null, coverage_until: string|null} $field */
            $field = $row->toArray()['usage'];

            $usage[self::nameOf($row->target)] = $field;
        }

        return $usage;
    }

    /**
     * Return the keys of the map, sorted.
     *
     * @param  array<string, mixed>  $map
     * @return list<string>
     */
    private static function sortedKeys(array $map): array
    {
        $keys = \array_keys($map);

        \sort($keys);

        return $keys;
    }
}
