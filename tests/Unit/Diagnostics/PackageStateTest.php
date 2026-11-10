<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\BootCheck;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\PackageStatus;
use SineMacula\Laravel\Authorization\Diagnostics\PackageState;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Unit tests for where the package stands in the application that registered
 * it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PackageState::class)]
final class PackageStateTest extends TestCase
{
    /**
     * A container the package never registered in holds no state, so nothing
     * refuses there; starting holds one, pending.
     *
     * @return void
     */
    public function testAContainerWithoutThePackageRefusesNothing(): void
    {
        $container = new Container;

        self::assertNull(PackageState::of($container));

        PackageState::guard($container);

        $state = PackageState::start($container);

        self::assertSame($state, PackageState::of($container));
        self::assertSame(PackageStatus::PENDING, $state->status());
        self::assertFalse($state->isHealthy());
        self::assertFalse($state->isDecided());
    }

    /**
     * Starting again, as registering again does, keeps the same state where it
     * stands, with what it holds, so an object that holds it sees no change,
     * and leaves the mode to be decided afresh; each container holds its own.
     *
     * @return void
     */
    public function testStartingAgainKeepsTheStateAndDecidesTheModeAfresh(): void
    {
        $container = new Container;
        $state     = PackageState::start($container);
        $findings  = new ConfigFindings([], []);
        $checks    = [BootCheck::notRun('authorization.cache.store')];

        $state->decide(true);
        $state->recordBootChecks($checks);
        $state->healthy($findings);

        self::assertSame($state, PackageState::start($container));
        self::assertSame(PackageStatus::HEALTHY, $state->status());
        self::assertTrue($state->isHealthy());
        self::assertFalse($state->isDecided());
        self::assertSame($findings, $state->findings());
        self::assertSame($checks, $state->bootChecks());
        self::assertNotSame($state, PackageState::start(new Container));
    }

    /**
     * A pending state refuses, with a fixed reason under the `internal` code at
     * the configuration's root; a healthy one does not.
     *
     * @return void
     */
    public function testAPendingStateRefusesUntilHealthy(): void
    {
        $container = new Container;
        $state     = PackageState::start($container);

        $refusal = self::refusalOf(static fn () => PackageState::guard($container));

        self::assertSame('authorization', $refusal->getConfigKey());
        self::assertSame(IssueCode::INTERNAL, $refusal->getIssue());
        self::assertStringContainsString('has not been validated', $refusal->getMessage());

        $state->healthy();

        PackageState::guard($container);
        $state->ensureHealthy();

        self::assertSame(PackageStatus::HEALTHY, $state->status());
        self::assertTrue($state->isHealthy());
        self::assertNull($state->findings());
    }

    /**
     * The current container's state is looked up on each call, never
     * remembered: nothing refuses while the current container holds none, a
     * container registering the package later refuses from then on, and the
     * guard hands back the state it checked.
     *
     * @return void
     */
    public function testTheCurrentContainerIsGuardedAsItStandsNow(): void
    {
        $previous  = Container::getInstance();
        $container = new Container;

        try {
            Container::setInstance($container);

            PackageState::guardCurrent();

            $state = PackageState::start($container);

            self::assertSame(IssueCode::INTERNAL, self::refusalOf(PackageState::guardCurrent(...))->getIssue());

            $state->healthy();

            PackageState::guardCurrent();

            self::assertSame($state, PackageState::guard($container));
            self::assertNull(PackageState::guard(new Container));
        } finally {
            Container::setInstance($previous);
        }
    }

    /**
     * A refusing state names the first refusal by its path and code, with what
     * the setting expects and the type found, never the value; the findings are
     * kept.
     *
     * @return void
     */
    public function testARefusingStateNamesTheFirstRefusal(): void
    {
        $state    = PackageState::start(new Container);
        $findings = new ConfigFindings([
            ConfigIssue::internal('authorization.context.sources', new \RuntimeException('secret')),
            new ConfigIssue('authorization.tenant_tree', IssueCode::UNKNOWN_CLASS, 'a class implementing TenantTree', 'string'),
            new ConfigIssue('authorization.cache.ttl', IssueCode::OUT_OF_RANGE),
        ], []);

        $state->refuse($findings);

        $refusal = self::refusalOf($state->ensureHealthy(...));

        self::assertTrue($state->isRefusing());
        self::assertSame($findings, $state->findings());
        self::assertSame('authorization.tenant_tree', $refusal->getConfigKey());
        self::assertSame(IssueCode::UNKNOWN_CLASS, $refusal->getIssue());
        self::assertSame('a class implementing TenantTree', $refusal->getExpected());
        self::assertSame('string', $refusal->getGotType());
        self::assertStringContainsString('unknown_class', $refusal->getMessage());
        self::assertStringNotContainsString('secret', $refusal->getMessage());
    }

    /**
     * A state refusing for a check that could not be completed alone names it
     * under the `internal` code, with a fixed reason, never what was thrown.
     *
     * @return void
     */
    public function testAnIncompleteValidationRefusesWithAFixedReason(): void
    {
        $state = PackageState::start(new Container);

        $state->refuse(new ConfigFindings([ConfigIssue::internal('authorization.context.sources', new \RuntimeException('secret'))], []));

        $refusal = $state->refusal();

        self::assertSame('authorization.context.sources', $refusal->getConfigKey());
        self::assertSame(IssueCode::INTERNAL, $refusal->getIssue());
        self::assertStringContainsString('could not be checked completely', $refusal->getMessage());
        self::assertStringNotContainsString('secret', $refusal->getMessage());
    }

    /**
     * What the diagnostic boot found so far is kept without changing where the
     * package stands, and the mode and outcomes are kept as decided.
     *
     * @return void
     */
    public function testFindingsModeAndOutcomesAreKept(): void
    {
        $state    = PackageState::start(new Container);
        $findings = new ConfigFindings([], ['authorization.cache.store']);
        $checks   = [BootCheck::ran('authorization.cache.store', null)];

        $state->found($findings);
        $state->decide(false);
        $state->recordBootChecks($checks);

        self::assertSame(PackageStatus::PENDING, $state->status());
        self::assertSame($findings, $state->findings());
        self::assertTrue($state->isDecided());
        self::assertFalse($state->isDiagnostic());
        self::assertSame($checks, $state->bootChecks());

        $state->decide(true);
        $state->healthy();

        self::assertTrue($state->isDiagnostic());
        self::assertSame($findings, $state->findings());

        $state->pending();

        self::assertSame(PackageStatus::PENDING, $state->status());
        self::assertFalse($state->isHealthy());
        self::assertSame($findings, $state->findings());
    }

    /**
     * Return the refusal the operation throws.
     *
     * @param  \Closure(): mixed  $operation
     * @return \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function refusalOf(\Closure $operation): InvalidAuthorizationConfigException
    {
        try {
            $operation();
        } catch (InvalidAuthorizationConfigException $refusal) {
            return $refusal;
        }

        self::fail('The operation was not refused.');
    }
}
