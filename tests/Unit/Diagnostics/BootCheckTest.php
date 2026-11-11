<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\BootCheck;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\BootCheckOutcome;

/**
 * Unit tests for the outcome of one check the diagnostic boot runs by building
 * what a setting names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BootCheck::class)]
final class BootCheckTest extends TestCase
{
    /**
     * A check that did not run keeps its path alone; one that ran passed when
     * it threw nothing, and failed with the class of what it threw otherwise.
     *
     * @return void
     */
    public function testEachOutcomeKeepsItsPathAndAnyExceptionClass(): void
    {
        $notRun = BootCheck::notRun('authorization.cache.store');
        $passed = BootCheck::ran('authorization.context.sources', null);
        $failed = BootCheck::ran('authorization.session.scopes', \LogicException::class);

        self::assertSame(['authorization.cache.store', BootCheckOutcome::NOT_RUN, null], [$notRun->path, $notRun->outcome, $notRun->exception]);
        self::assertSame(['authorization.context.sources', BootCheckOutcome::PASSED, null], [$passed->path, $passed->outcome, $passed->exception]);
        self::assertSame(['authorization.session.scopes', BootCheckOutcome::FAILED, \LogicException::class], [$failed->path, $failed->outcome, $failed->exception]);
    }
}
