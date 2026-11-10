<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Usage\GrantUsageRecorder;
use SineMacula\Laravel\Authorization\Usage\RecordGrantUsage;
use Tests\Concerns\ReviewsAccess;
use Tests\Concerns\TracksGrantUsage;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\TestCase;

/**
 * Performance budget for a check while grant usage is tracked (N94): a cold
 * check reads what it reads with tracking off, the routes behind its grants
 * read from the same rows; a warm check reads nothing, and its routes come from
 * what the resolution cache keeps beside its grants, so 1,000 warm tracked
 * checks stay within the budget an untracked check is held to (see
 * `SingleCheckBudgetTest`), at a constant extra cost.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationManager::class)]
final class GrantUsageBudgetTest extends TestCase
{
    use ReviewsAccess, TracksGrantUsage;

    /**
     * A tracked check reads, cold, exactly the queries an untracked one reads,
     * and, warm, none; 1,000 warm tracked checks complete in under 500ms and
     * are recorded once a bucket.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATrackedWarmCheckCostsConstantExtraAndNoQuery(): void
    {
        $admin  = self::role('admin');
        $editor = self::role('editor', $admin);
        $ann    = self::identity('ann');

        $admin->givePermissionTo(self::permission('posts:read'));
        self::grants()->grantRole($ann, $editor);
        self::grants()->attachPolicy($ann, self::policy('no-delete'));

        $tracked = $this->queriesOf(fn (): bool => $this->actAs($ann)->check('posts:read')->isAllowed());

        config(['authorization.usage.enabled' => false]);

        $untracked = $this->queriesOf(fn (): bool => $this->actAs($ann)->check('posts:read')->isAllowed());

        self::assertSame($untracked, $tracked);
        self::assertGreaterThan(0, $tracked);

        config(['authorization.usage.enabled' => true]);

        $manager = $this->actAs($ann);

        self::assertTrue($manager->check('posts:read')->isAllowed());

        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        $start = \microtime(true);

        for ($index = 0; $index < 1000; $index++) {
            $manager->check('posts:read');
        }

        $elapsed = \microtime(true) - $start;

        self::assertSame(0, $queries);
        self::assertLessThan(0.5, $elapsed, "Tracked check budget exceeded ({$elapsed}s for 1,000 checks).");
        self::assertCount(3, $this->keysObserved());
    }

    /**
     * A subject whose identity grants to it, allowed by its own permission,
     * reads cold exactly the queries it reads untracked: the identity's
     * permissions, which the check never needed, are never resolved for
     * tracking.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATrackedColdCheckNeverResolvesWhatTheCheckDidNot(): void
    {
        $person = self::identity('person');
        $ann    = StubSecondIdentity::query()->create(['id' => 'ann']);
        $admin  = self::role('admin');

        $admin->givePermissionTo(self::permission('posts:write'));

        self::grants()->grantPermission($ann, self::permission('posts:read'));
        self::grants()->grantRole($person, $admin);

        $tracked = $this->queriesOf(fn (): bool => $this->actAs($ann, $person)->check('posts:read')->isAllowed());

        config(['authorization.usage.enabled' => false]);

        $untracked = $this->queriesOf(fn (): bool => $this->actAs($ann, $person)->check('posts:read')->isAllowed());

        self::assertSame($untracked, $tracked);
    }

    /**
     * With tracking off a check sends no job, builds no recorder and reads
     * nothing more than before.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUntrackedCheckSendsNothing(): void
    {
        config(['authorization.usage.enabled' => false]);

        $ann = self::identity('ann');

        self::grants()->grantPermission($ann, self::permission('posts:read'));

        $manager = $this->actAs($ann);

        self::assertTrue($manager->check('posts:read')->isAllowed());
        self::assertFalse(app()->resolved(GrantUsageRecorder::class));

        app()->terminate();

        Bus::assertNotDispatched(RecordGrantUsage::class);
    }

    /**
     * Return how many queries the callback runs, on a cold cache built for the
     * tracking configured now.
     *
     * @param  \Closure(): bool  $callback
     * @return int
     */
    private function queriesOf(\Closure $callback): int
    {
        $this->app?->forgetInstance(ResolutionCache::class);

        DB::flushQueryLog();
        DB::enableQueryLog();

        self::assertTrue($callback());

        $queries = \count(DB::getQueryLog());

        DB::disableQueryLog();

        return $queries;
    }
}
