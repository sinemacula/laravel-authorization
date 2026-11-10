<?php

declare(strict_types = 1);

namespace Tests\Feature\Usage;

use Illuminate\Contracts\Bus\Dispatcher;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Evaluation\DecisionPipeline;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Usage\DecisionRoutes;
use SineMacula\Laravel\Authorization\Usage\GrantUsageRecorder;
use Tests\Concerns\ActsAsAdministrator;
use Tests\Concerns\ReviewsAccess;
use Tests\Concerns\TracksGrantUsage;
use Tests\Feature\Stubs\FailingPermissionsIdentity;
use Tests\Feature\Stubs\RecordingLogger;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\TestCase;

/**
 * Feature tests for the decision pipeline while grant usage is tracked: an
 * administration action allowed and kept by its administration stage counts the
 * routes behind it, one the stage refuses counts none, and neither do the
 * further checks the stage makes; a check never sends what it noted, and no
 * step tracking adds ever changes or breaks a decision.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DecisionPipeline::class)]
final class DecisionPipelineTest extends TestCase
{
    use ActsAsAdministrator, ReviewsAccess, TracksGrantUsage;

    /**
     * A delegated grant the administration stage keeps counts the right behind
     * it; one the stage refuses, a grant to the actor itself, counts nothing,
     * its further checks included.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAdministrationStageDecidesWhetherAnAllowCounts(): void
    {
        $context = self::administrator([PackagePermissions::PERMISSION_GRANT, 'posts:*'], 'admin');
        $admin   = $context->subject->subject;

        self::assertIsObject($admin);

        $this->actAs($admin);

        try {
            self::grants()->grantPermission($admin, self::permission('posts:edit'), actor: ActingContext::current());
            self::fail('A grant to the actor itself was allowed.');
        } catch (AuthorizationException $exception) {
            self::assertSame(DecisionReason::ADMINISTRATION_SELF, $exception->getReason());
        }

        self::assertSame([], $this->keysObserved());

        self::grants()->grantPermission(self::identity('bob'), self::permission('posts:read'), actor: ActingContext::current());

        self::assertSame(self::keysHeld($admin, null, self::targeting(PackagePermissions::PERMISSION_GRANT)), $this->keysObserved());
    }

    /**
     * A check never sends what it noted, however full the batch, so it never
     * waits on the queue or the store; a queue that refuses the job as the
     * recorder flushes is written to the log channel and never reaches the
     * decision.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAQueueFailureNeverAffectsADecision(): void
    {
        $logger = new RecordingLogger;
        $bus    = \Mockery::mock(Dispatcher::class);

        $bus->shouldReceive('dispatch')->once()->andThrow(new \RuntimeException('queue down'));

        $this->app?->instance('log', $logger);
        $this->app?->instance(GrantUsageRecorder::class, new GrantUsageRecorder($bus));

        config(['authorization.usage.batch' => 1]);

        $ann = self::identity('ann');

        self::grants()->grantPermission($ann, self::permission('posts:read'));

        self::assertTrue($this->actAs($ann)->check('posts:read')->isAllowed());
        self::assertSame([], $logger->messages());
        self::assertSame(1, $this->recorder()->pending());

        $this->recorder()->flush();

        self::assertSame(['Authorization: grant usage could not be sent to be recorded — queue down'], $logger->messages());
    }

    /**
     * Return the ways a step tracking adds can fail, each with the start of
     * every message it writes to the log channel.
     *
     * @return iterable<string, array{\Closure(\Illuminate\Foundation\Application): void, list<string>}>
     */
    public static function sabotages(): iterable
    {
        $routes = 'Authorization: the grants a check used could not be found';
        $noted  = 'Authorization: the grants a check used could not be noted';
        $sent   = 'Authorization: grant usage could not be sent to be recorded';

        $cache = static function (Application $app): void {
            $cache = $app->make(ResolutionCache::class);

            $app->bind(ResolutionCache::class, static function () use ($cache): ResolutionCache {
                $callers = \array_column(\debug_backtrace(\DEBUG_BACKTRACE_IGNORE_ARGS), 'class');

                return \in_array(DecisionRoutes::class, $callers, true) ? throw new \RuntimeException('cache down') : $cache;
            });
        };

        $interval = static function (): void {
            config(['authorization.usage.interval' => 'hourly']);
        };

        $queue = static function (Application $app): void {
            $bus = \Mockery::mock(Dispatcher::class);

            $bus->shouldReceive('dispatch')->andThrow(new \RuntimeException('queue down'));

            $app->instance(GrantUsageRecorder::class, new GrantUsageRecorder($bus));
        };

        $connection = static function (): void {
            config(['authorization.usage.connection' => '']);
        };

        yield 'nothing fails but the identity' => [static function (): void {}, []];
        yield 'the routes cannot be read' => [$cache, [$routes]];
        yield 'the interval is no longer valid' => [$interval, [$noted]];
        yield 'the queue refuses the job' => [$queue, [$sent]];
        yield 'the queue connection is no longer valid' => [$connection, [$sent]];
        yield 'everything fails' => [static function (Application $app) use ($cache, $interval, $queue, $connection): void {
            $queue($app);
            $cache($app);
            $interval();
            $connection();
        }, [$routes]];
    }

    /**
     * Tracking never changes or breaks a check: one that is allowed with
     * tracking off is allowed, the same way and without throwing, with tracking
     * on, whichever of the steps tracking adds fails, and every failure is
     * written to the log channel. The subject's own permission allows it, so
     * its identity's, which cannot be read, is never asked for.
     *
     * @param  \Closure(\Illuminate\Foundation\Application): void  $sabotage
     * @param  list<string>  $logged
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('sabotages')]
    public function testTrackingNeverChangesOrBreaksACheck(\Closure $sabotage, array $logged): void
    {
        $ann      = StubSecondIdentity::query()->create(['id' => 'ann']);
        $identity = FailingPermissionsIdentity::query()->create(['id' => 'person']);

        self::grants()->grantPermission($ann, self::permission('posts:read'));
        self::grants()->attachPolicy($ann, self::policy('no-delete'));

        config(['authorization.usage.enabled' => false]);

        $off = $this->actAs($ann, $identity)->check('posts:read');

        config(['authorization.usage.enabled' => true]);

        $logger = new RecordingLogger;

        $this->app?->instance('log', $logger);

        self::assertNotNull($this->app);

        $sabotage($this->app);

        $on = $this->actAs($ann, $identity)->check('posts:read');

        self::assertTrue($off->isAllowed());
        self::assertSame([$off->effect, $off->reason, $off->stage], [$on->effect, $on->reason, $on->stage]);

        $this->recorder()->flush();

        self::assertSame($logged, \array_map(static fn (string $message): string => \strstr($message, ' — ', true) ?: $message, $logger->messages()));
    }
}
