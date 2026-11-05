<?php

declare(strict_types = 1);

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestWith;
use SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException;
use SineMacula\Laravel\Authorization\Support\CheckArguments;
use Tests\TestCase;

/**
 * Feature coverage for `CheckArguments`, which reads the names and the guard a
 * route middleware or a Blade directive is given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckArguments::class)]
final class CheckArgumentsTest extends TestCase
{
    /**
     * Every entry of a string or a list is split on `|`, trimmed, and its empty
     * names dropped, in order.
     *
     * @param  array<int, string>|string  $value
     * @param  list<string>  $expected
     * @return void
     */
    #[TestWith(['admin', ['admin']])]
    #[TestWith([' admin ', ['admin']])]
    #[TestWith(['admin|editor', ['admin', 'editor']])]
    #[TestWith([' admin | | editor |', ['admin', 'editor']])]
    #[TestWith([['admin', 'editor|auditor'], ['admin', 'editor', 'auditor']])]
    #[TestWith([['', ' | ', 'admin'], ['admin']])]
    #[TestWith(['', []])]
    #[TestWith([[], []])]
    public function testNamesSplitEveryEntry(array|string $value, array $expected): void
    {
        self::assertSame($expected, CheckArguments::names($value));
    }

    /**
     * No guard is no guard, and an authentication guard is returned as given.
     *
     * @return void
     */
    public function testGuardReturnsAnAuthenticationGuard(): void
    {
        self::assertNull(CheckArguments::guard(null));
        self::assertSame('web', CheckArguments::guard('web'));
    }

    /**
     * A guard that is not an authentication guard is refused.
     *
     * @return void
     */
    public function testGuardRefusesAnUnknownGuard(): void
    {
        $this->expectException(InvalidCheckArgumentException::class);
        $this->expectExceptionMessage('\'editor\' is not an authentication guard.');

        CheckArguments::guard('editor');
    }

    /**
     * Without any authentication guard configured, every guard is refused.
     *
     * @return void
     */
    public function testGuardRefusesEveryGuardWithoutAuthenticationGuards(): void
    {
        config(['auth.guards' => null]);

        $this->expectException(InvalidCheckArgumentException::class);

        CheckArguments::guard('web');
    }

    /**
     * No guard passes, and any guard is refused for the named check.
     *
     * @return void
     */
    public function testRefuseGuardRefusesAnyGuard(): void
    {
        CheckArguments::refuseGuard('permission', null);

        $this->expectException(InvalidCheckArgumentException::class);
        $this->expectExceptionMessage('A permission check takes no guard: it is decided on the full authorization decision, which no guard changes. Remove the guard \'web\'.');

        CheckArguments::refuseGuard('permission', 'web');
    }
}
