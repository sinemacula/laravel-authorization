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
    /**
     * An empty list, and a list of hooks each listed once, are accepted.
     *
     * @return void
     */
    public function testAListOfHooksIsAccepted(): void
    {
        GrantHookConfigValidator::validate([]);
        GrantHookConfigValidator::validate([RecordingGrantHook::class, RefusingGrantHook::class, GrantHooks::class]);

        $this->addToAssertionCount(2);
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
}
