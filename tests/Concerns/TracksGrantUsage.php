<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Bus;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\GrantUsageStore;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Reviews\AccessReview;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use SineMacula\Laravel\Authorization\Usage\GrantUsageKey;
use SineMacula\Laravel\Authorization\Usage\GrantUsageRecorder;
use SineMacula\Laravel\Authorization\Usage\RecordGrantUsage;
use SineMacula\Laravel\Authorization\Usage\UsageBatch;
use Tests\Feature\Stubs\FixedSubjectResolver;

/**
 * Turns grant usage tracking on for a test, catches the recording jobs the
 * recorder sends, and reads back which routes were observed, so a test can
 * compare them with the routes an access review lists.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 *
 * @phpstan-import-type Observation from \SineMacula\Laravel\Authorization\Usage\UsageBatch
 */
trait TracksGrantUsage
{
    /** @var int How many recording jobs were read back already, so each read returns those sent since. */
    private int $jobsRead = 0;

    /**
     * Turn grant usage tracking on before the package boots.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        self::assertInstanceOf(Application::class, $app);

        $app['config']->set('authorization.usage.enabled', true);
    }

    /**
     * Catch the recording jobs, and build the recorder afresh so it sends them
     * to the fake.
     *
     * @return void
     */
    protected function setUpTracksGrantUsage(): void
    {
        Bus::fake([RecordGrantUsage::class]);

        $this->app?->forgetInstance(GrantUsageRecorder::class);
    }

    /**
     * Decide as the subject from here on: the principal, with its identity when
     * one is given.
     *
     * @param  object  $principal
     * @param  object|null  $identity
     * @return \SineMacula\Laravel\Authorization\AuthorizationManager
     */
    protected function actAs(object $principal, ?object $identity = null): AuthorizationManager
    {
        $this->app?->instance(SubjectResolver::class, new FixedSubjectResolver(new Subject($principal, $identity ?? $principal)));

        foreach (['authorization', AuthorizationManager::class, CheckContextFactory::class, ResolvedTenant::class] as $abstract) {
            $this->app?->forgetInstance($abstract);
        }

        Authorization::clearResolvedInstance('authorization');

        $manager = app(AuthorizationManager::class);

        self::assertInstanceOf(AuthorizationManager::class, $manager);

        return $manager;
    }

    /**
     * Flush the recorder and return every observation the recording jobs sent
     * since the last read carry, in the order sent.
     *
     * @return list<Observation>
     */
    protected function observed(): array
    {
        $this->recorder()->flush();

        $jobs         = Bus::dispatched(RecordGrantUsage::class)->values()->all();
        $observations = [];

        foreach (\array_slice($jobs, $this->jobsRead) as $job) {
            self::assertInstanceOf(RecordGrantUsage::class, $job);

            \array_push($observations, ...$job->batch->observations());
        }

        $this->jobsRead = \count($jobs);

        return $observations;
    }

    /**
     * Flush the recorder and return the key of each route observed since the
     * last read, each once, sorted.
     *
     * @return list<string>
     */
    protected function keysObserved(): array
    {
        $keys = \array_values(\array_unique(\array_map(static fn (array $observation): string => $observation['grant_key'], $this->observed())));

        \sort($keys);

        return $keys;
    }

    /**
     * Flush the recorder and record what it sent since the last read in the
     * bound usage store, as the queue would, returning how many observations
     * were recorded.
     *
     * @return int
     */
    protected function recordObserved(): int
    {
        $observations = $this->observed();

        $store = app(GrantUsageStore::class);

        self::assertInstanceOf(GrantUsageStore::class, $store);

        $store->record(UsageBatch::of($observations, Carbon::now()->getTimestamp()));

        return \count($observations);
    }

    /**
     * Run the heartbeat at the instant, extending the coverage to it.
     *
     * @param  string  $at
     * @return void
     */
    protected function heartbeatAt(string $at): void
    {
        Carbon::setTestNow($at);

        self::assertSame(0, Artisan::call('authorization:usage-heartbeat'));
    }

    /**
     * Return the key of each route the review of the subject's holdings lists
     * whose row the filter keeps, each once, sorted.
     *
     * @param  object  $principal
     * @param  object|null  $identity
     * @param  (\Closure(\SineMacula\Laravel\Authorization\Reviews\ReviewRow): bool)|null  $keeps
     * @return list<string>
     */
    protected static function keysHeld(object $principal, ?object $identity = null, ?\Closure $keeps = null): array
    {
        /** @var \SineMacula\Laravel\Authorization\Reviews\AccessReview $reviews */
        $reviews = app(AccessReview::class);
        $rows    = $reviews->trusted(ReviewQuery::holdings(new Subject($principal, $identity ?? $principal), ReviewScope::everywhere()))->rows;
        $keys    = [];

        foreach ($rows as $row) {
            if ($keeps !== null && !$keeps($row)) {
                continue;
            }

            $keys[] = GrantUsageKey::ofRow($row);
        }

        $keys = \array_values(\array_unique($keys));

        \sort($keys);

        return $keys;
    }

    /**
     * Return a filter keeping the rows whose target is one of the named
     * definitions, by name.
     *
     * @param  string  ...$names
     * @return \Closure(\SineMacula\Laravel\Authorization\Reviews\ReviewRow): bool
     */
    protected static function targeting(string ...$names): \Closure
    {
        return static fn (ReviewRow $row): bool => \in_array(self::nameOf($row->target), $names, true);
    }

    /**
     * Return the recorder.
     *
     * @return \SineMacula\Laravel\Authorization\Usage\GrantUsageRecorder
     */
    protected function recorder(): GrantUsageRecorder
    {
        $recorder = app(GrantUsageRecorder::class);

        self::assertInstanceOf(GrantUsageRecorder::class, $recorder);

        return $recorder;
    }
}
