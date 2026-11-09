<?php

declare(strict_types = 1);

namespace Tests\Feature\Usage;

use Illuminate\Contracts\Bus\Dispatcher;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Evaluation\DecisionPipeline;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Usage\GrantUsageRecorder;
use Tests\Concerns\ActsAsAdministrator;
use Tests\Concerns\ReviewsAccess;
use Tests\Concerns\TracksGrantUsage;
use Tests\Feature\Stubs\RecordingLogger;
use Tests\TestCase;

/**
 * Feature tests for the decision pipeline while grant usage is tracked: an
 * administration action allowed and kept by its administration stage counts the
 * routes behind it, one the stage refuses counts none, and neither do the
 * further checks the stage makes; a queue that refuses the recording job never
 * reaches the decision.
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
     * A queue that refuses the recording job, sent as the batch fills during a
     * check, never reaches the check: the decision is made and returned, and
     * the refusal written to the log channel.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAQueueFailureNeverAffectsADecision(): void
    {
        $logger = new RecordingLogger;
        $bus    = \Mockery::mock(Dispatcher::class);

        $bus->shouldReceive('dispatch')->andThrow(new \RuntimeException('queue down'));

        $this->app?->instance('log', $logger);
        $this->app?->instance(GrantUsageRecorder::class, new GrantUsageRecorder($bus));

        config(['authorization.usage.batch' => 1]);

        $ann = self::identity('ann');

        self::grants()->grantPermission($ann, self::permission('posts:read'));

        self::assertTrue($this->actAs($ann)->check('posts:read')->isAllowed());
        self::assertSame(['Authorization: grant usage could not be sent to be recorded — queue down'], $logger->messages());
    }
}
