<?php

declare(strict_types = 1);

namespace Tests\Feature\Usage;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Console\UsagePruneCommand;
use SineMacula\Laravel\Authorization\Usage\DatabaseGrantUsageStore;
use SineMacula\Laravel\Authorization\Usage\UsageBatch;
use Tests\TestCase;

/**
 * Feature tests for `authorization:usage-prune`: it prunes the usage of grants
 * that are gone and the coverage past the configured retention, and only
 * reports what it would remove with `--pretend`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UsagePruneCommand::class)]
final class UsagePruneCommandTest extends TestCase
{
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
     * The command reports what it would remove with `--pretend`, then removes
     * it, under the configured retention.
     *
     * @return void
     */
    public function testTheCommandPrunesUnderTheRetention(): void
    {
        config(['authorization.usage.retention' => 30]);

        $observation = [
            'grant_key'         => 'gone',
            'grant_source'      => 'permission',
            'grant_id'          => 'no-such-permission',
            'authorizable_type' => 'user',
            'authorizable_id'   => 'ann',
            'tenant_type'       => null,
            'tenant_id'         => null,
            'application'       => null,
            'grant_created_at'  => null,
            'last_observed_at'  => Carbon::parse('2026-01-01 00:00:00')->getTimestamp(),
        ];

        (new DatabaseGrantUsageStore)->record(UsageBatch::of([$observation], Carbon::parse('2026-01-01 00:00:00')->getTimestamp()));

        Carbon::setTestNow('2026-11-09 00:00:00');

        self::assertSame(0, Artisan::call('authorization:usage-prune', ['--pretend' => true]));
        self::assertSame('Would prune the usage of 1 grant route(s) whose grant no longer exists and 1 coverage period(s) older than 30 day(s).', \trim(Artisan::output()));

        self::assertSame([1, 1], [DB::table('authorization_grant_usage')->count(), DB::table('authorization_usage_coverage')->count()]);

        self::assertSame(0, Artisan::call('authorization:usage-prune'));
        self::assertSame('Pruned the usage of 1 grant route(s) whose grant no longer exists and 1 coverage period(s) older than 30 day(s).', \trim(Artisan::output()));

        self::assertSame([0, 0], [DB::table('authorization_grant_usage')->count(), DB::table('authorization_usage_coverage')->count()]);
    }

    /**
     * The command is registered under the name its constant holds.
     *
     * @return void
     */
    public function testTheCommandsNameIsItsConstant(): void
    {
        self::assertSame('authorization:usage-prune', UsagePruneCommand::NAME);
        self::assertInstanceOf(UsagePruneCommand::class, Artisan::all()[UsagePruneCommand::NAME] ?? null);
        self::assertSame(UsagePruneCommand::NAME, Artisan::all()[UsagePruneCommand::NAME]->getName());
    }
}
