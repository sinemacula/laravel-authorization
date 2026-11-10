<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Config\GrantHookConfigValidator;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Hooks\GrantHooks;
use Tests\Concerns\ReadsRefusedSettings;
use Tests\Fixtures\GrantHooks\RecordingGrantHook;
use Tests\Fixtures\GrantHooks\RefusingGrantHook;

/**
 * Unit tests for the boot-time validation of `authorization.grant_hooks`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantHookConfigValidator::class)]
final class GrantHookConfigValidatorTest extends TestCase
{
    use ReadsRefusedSettings;

    /**
     * An empty list, and a list of hooks each listed once, are accepted.
     *
     * @return void
     */
    public function testAListOfHooksIsAccepted(): void
    {
        $hooks = [RecordingGrantHook::class, RefusingGrantHook::class, GrantHooks::class];

        self::assertSame([], GrantHookConfigValidator::validate([]));
        self::assertSame($hooks, GrantHookConfigValidator::validate($hooks));
    }

    /**
     * Provide values that are refused, with the key and the reason each is
     * refused under.
     *
     * @return iterable<string, array{mixed, string, string}>
     */
    public static function refusedProvider(): iterable
    {
        $contract = GrantHook::class;

        yield 'not an array' => [RecordingGrantHook::class, 'authorization.grant_hooks', 'expected a list of class names, got string.'];
        yield 'null' => [null, 'authorization.grant_hooks', 'expected a list of class names, got null.'];
        yield 'a map' => [['first' => RecordingGrantHook::class], 'authorization.grant_hooks', 'expected a list of class names, got array.'];
        yield 'a null entry' => [[null], 'authorization.grant_hooks.0', 'expected a class-string, got null.'];
        yield 'an empty entry' => [[RecordingGrantHook::class, ''], 'authorization.grant_hooks.1', 'expected a class-string, got string.'];
        yield 'a missing class' => [['App\Missing\Hook'], 'authorization.grant_hooks.0', 'class \'App\Missing\Hook\' does not exist.'];
        yield 'another class' => [[\stdClass::class], 'authorization.grant_hooks.0', "class 'stdClass' does not implement {$contract}."];
        yield 'a hook listed twice' => [
            [RecordingGrantHook::class, RefusingGrantHook::class, RecordingGrantHook::class],
            'authorization.grant_hooks.2',
            'class \'' . RecordingGrantHook::class . '\' is listed more than once.',
        ];

        $lower = \strtolower(RecordingGrantHook::class);

        yield 'a hook listed twice in another case' => [
            [RecordingGrantHook::class, $lower],
            'authorization.grant_hooks.1',
            "class '{$lower}' is listed more than once.",
        ];
        yield 'a hook listed twice with a leading backslash' => [
            ['\\' . RecordingGrantHook::class, RefusingGrantHook::class, RecordingGrantHook::class],
            'authorization.grant_hooks.2',
            'class \'' . RecordingGrantHook::class . '\' is listed more than once.',
        ];
    }

    /**
     * A value that is not a list of hooks, each listed once, is refused under
     * the key of the entry at fault.
     *
     * @param  mixed  $value
     * @param  string  $key
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('refusedProvider')]
    public function testAValueThatIsNotAListOfHooksIsRefused(mixed $value, string $key, string $reason): void
    {
        $this->expectException(InvalidAuthorizationConfigException::class);
        $this->expectExceptionMessage("Invalid authorization config at '{$key}': {$reason}");

        GrantHookConfigValidator::validate($value);
    }

    /**
     * Each entry is checked on its own against the hooks seen before it, a hook
     * named again in another case refused as a duplicate.
     *
     * @return void
     */
    public function testEachEntryIsCheckedAgainstThoseSeen(): void
    {
        $seen = GrantHookConfigValidator::entry(0, RecordingGrantHook::class, []);

        self::assertSame([\strtolower(RecordingGrantHook::class) => true], $seen);
        self::assertSame(
            ['authorization.grant_hooks.1', 'duplicate', 'a class listed once', 'string'],
            self::refusedSetting(static fn (): array => GrantHookConfigValidator::entry(1, '\\' . \strtoupper(RecordingGrantHook::class), $seen)),
        );
        self::assertSame('invalid_type', self::refusedSetting(static fn (): array => GrantHookConfigValidator::validate('x'))[1]);
    }
}
