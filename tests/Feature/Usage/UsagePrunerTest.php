<?php

declare(strict_types = 1);

namespace Tests\Feature\Usage;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Usage\DatabaseGrantUsageStore;
use SineMacula\Laravel\Authorization\Usage\UsageBatch;
use SineMacula\Laravel\Authorization\Usage\UsagePruner;
use Tests\Concerns\ReviewsAccess;
use Tests\TestCase;

/**
 * Feature tests for the usage pruner: the usage of a route whose stored grant
 * no longer exists is removed, matched on every column that makes the grant
 * unique, a null matching a null, while a grant that exists keeps its use; and
 * coverage that ended before the retention is removed.
 *
 * @phpstan-import-type Observation from \SineMacula\Laravel\Authorization\Usage\UsageBatch
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UsagePruner::class)]
final class UsagePrunerTest extends TestCase
{
    use ReviewsAccess;

    /**
     * Reset the clock.
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
     * Usage of a grant that exists is kept, of every kind; usage whose grant is
     * gone, or differs in any column, is removed; pretending removes nothing
     * but counts the same.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheUsageOfAGrantThatIsGoneIsRemoved(): void
    {
        $ann        = self::identity('ann');
        $role       = self::role('editor');
        $permission = self::permission('posts:read');
        $policy     = self::policy('no-delete');
        $tenant     = self::tenant('org1');

        $this->tree();

        self::grants()->grantRole($ann, $role, tenant: $tenant, application: 'web');
        self::grants()->grantPermission($ann, $permission);
        self::grants()->attachPolicy($ann, $policy);

        $type = $ann->getMorphClass();
        $kept = [
            self::observation('role', Reference::of($role)->id, $type, 'ann', 'tenant', 'org1', 'web'),
            self::observation('permission', Reference::of($permission)->id, $type, 'ann'),
            self::observation('policy', Reference::of($policy)->id, $type, 'ann'),
        ];
        $gone = [
            self::observation('role', Reference::of($role)->id, $type, 'ann'),
            self::observation('role', Reference::of($role)->id, $type, 'ann', 'tenant', 'org1'),
            self::observation('permission', Reference::of($permission)->id, $type, 'bob'),
            self::observation('policy', 'no-such-policy', $type, 'ann'),
        ];

        (new DatabaseGrantUsageStore)->record(new UsageBatch([...$kept, ...$gone], Carbon::now()->getTimestamp()));

        self::assertSame([4, 0], UsagePruner::prune(400, true));
        self::assertSame(7, DB::table('authorization_grant_usage')->count());
        self::assertSame([4, 0], UsagePruner::prune(400));
        self::assertEqualsCanonicalizing(\array_column($kept, 'grant_key'), DB::table('authorization_grant_usage')->pluck('grant_key')->all());
    }

    /**
     * Coverage that ended before the retention is removed; coverage within it
     * is kept.
     *
     * @return void
     */
    public function testCoverageOlderThanTheRetentionIsRemoved(): void
    {
        $store = new DatabaseGrantUsageStore;

        $store->record(new UsageBatch([], Carbon::parse('2026-01-01 00:00:00')->getTimestamp()));
        $store->record(new UsageBatch([], Carbon::parse('2026-11-01 00:00:00')->getTimestamp()));

        Carbon::setTestNow('2026-11-09 00:00:00');

        self::assertSame([0, 1], UsagePruner::prune(30, true));
        self::assertSame([0, 1], UsagePruner::prune(30));
        $from = DB::table('authorization_usage_coverage')->pluck('covered_from')->all();

        self::assertSame(['2026-11-01 00:00:00'], \array_map(static fn (mixed $value): string => \substr(\is_string($value) ? $value : '', 0, 19), $from));
    }

    /**
     * Return an observation of a route starting from the stored grant named.
     *
     * @param  string  $source
     * @param  string  $grantId
     * @param  string  $granteeType
     * @param  string  $granteeId
     * @param  string|null  $tenantType
     * @param  string|null  $tenantId
     * @param  string|null  $application
     * @return Observation
     */
    private static function observation(
        string $source,
        string $grantId,
        string $granteeType,
        string $granteeId,
        ?string $tenantType = null,
        ?string $tenantId = null,
        ?string $application = null,
    ): array {
        return [
            'grant_key'         => \hash('sha256', \implode('|', [$source, $grantId, $granteeType, $granteeId, $tenantType, $tenantId, $application])),
            'grant_source'      => $source,
            'grant_id'          => $grantId,
            'authorizable_type' => $granteeType,
            'authorizable_id'   => $granteeId,
            'tenant_type'       => $tenantType,
            'tenant_id'         => $tenantId,
            'application'       => $application,
            'grant_created_at'  => null,
            'last_observed_at'  => Carbon::now()->getTimestamp(),
        ];
    }
}
