<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\ConsoleInvocation;

/**
 * Unit tests for reading the name of the command the console runs from the
 * process's arguments, as the console reads it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConsoleInvocation::class)]
final class ConsoleInvocationTest extends TestCase
{
    /** @var string The command the arguments run in most cases. */
    private const string CHECK = 'authorization:check';

    /**
     * Provide arguments running the command, each with options the console
     * defines before it.
     *
     * @return iterable<string, array{list<string>}>
     */
    public static function runningProvider(): iterable
    {
        yield 'plain' => [['authorization:check']];
        yield 'its own options after it' => [['authorization:check', '--format=json', 'extra']];

        foreach (['-v', '-vv', '-vvv', '--verbose', '-q', '--quiet', '--silent', '-n', '--no-interaction', '--ansi', '--no-ansi', '-qn', '-vq'] as $option) {
            yield "{$option} before it" => [[$option, self::CHECK]];
        }

        yield '--env=x before it' => [['--env=testing', self::CHECK]];
        yield '--env x before it' => [['--env', 'testing', self::CHECK]];
        yield '--env= before it' => [['--env=', self::CHECK]];
        yield '--env followed by an option' => [['--env', '-v', self::CHECK]];
        yield 'several options before it' => [['-n', '--env', 'local', '--no-ansi', '-vv', self::CHECK]];
        yield '-- before it' => [['--', self::CHECK]];
        yield 'its own option before it' => [['--format=json', self::CHECK]];
        yield 'its own option among global ones before it' => [['-n', '--format=json', '-v', self::CHECK]];
        yield 'a global option the application adds before it' => [['--tenant=1', self::CHECK]];
        yield '--env followed by an option given a value' => [['--env', '--format=json', self::CHECK]];
        yield 'help after --' => [['-v', '--', self::CHECK, '--help']];
    }

    /**
     * The first argument that is no option names the command, each option the
     * console defines being skipped with the value it takes, and each long one
     * it does not define skipped when given its value after `=`, as the
     * command's own definition decides on it.
     *
     * @param  list<string>  $tokens
     * @return void
     */
    #[DataProvider('runningProvider')]
    public function testTheCommandIsReadPastTheConsolesOptions(array $tokens): void
    {
        self::assertSame(self::CHECK, ConsoleInvocation::commandName(['artisan', ...$tokens]));
    }

    /**
     * Provide arguments that run no command the console would run as named.
     *
     * @return iterable<string, array{list<mixed>}>
     */
    public static function notRunningProvider(): iterable
    {
        yield 'no command' => [[]];
        yield 'options alone' => [['-v', '--no-ansi']];
        yield '-- alone' => [['--']];
        yield '--env taking the only argument' => [['--env', self::CHECK]];

        foreach (['--help', '-h', '--version', '-V'] as $instead) {
            yield "{$instead} before it" => [[$instead, self::CHECK]];
            yield "{$instead} after it" => [[self::CHECK, $instead]];
        }

        yield 'an unknown long option' => [['--bogus', self::CHECK]];
        yield 'an unknown short option' => [['-x', self::CHECK]];
        yield 'an unknown option in a set' => [['-vx', self::CHECK]];
        yield '--verbose given a value' => [['--verbose=2', self::CHECK]];
        yield '--quiet given a value' => [['--quiet=1', self::CHECK]];
        yield '--no-ansi given a value' => [['--no-ansi=1', self::CHECK]];
        yield 'an unknown option given its value apart' => [['--format', 'json', self::CHECK]];
        yield 'an unknown short option given a value' => [['-x=1', self::CHECK]];
        yield '--env followed by an unknown option' => [['--env', '--bogus', self::CHECK]];
        yield '--env followed by an option given a value it does not take' => [['--env', '--no-ansi=1', self::CHECK]];
        yield 'an argument that is no string' => [[self::CHECK, 42]];
    }

    /**
     * No command is read when none is given, when help or the version is asked
     * for, when an option before it is one the console does not define, given
     * no value after `=` or a short one, or is given a value it does not take,
     * or when an argument is no string; `--env` never takes an option as its
     * value.
     *
     * @param  list<mixed>  $tokens
     * @return void
     */
    #[DataProvider('notRunningProvider')]
    public function testNoCommandIsReadWhenTheConsoleWouldRunNone(array $tokens): void
    {
        self::assertNull(ConsoleInvocation::commandName(['artisan', ...$tokens]));
    }

    /**
     * Another command, an abbreviation and an empty or lone dash argument are
     * read as given, never expanded, a lone dash never taken as `--env`'s
     * value, and a command a sibling declares found past an option of its own.
     *
     * @return void
     */
    public function testOtherCommandsAreReadAsGiven(): void
    {
        self::assertSame('list', ConsoleInvocation::commandName(['artisan', 'list']));
        self::assertSame('authorization:ch', ConsoleInvocation::commandName(['artisan', 'authorization:ch']));
        self::assertSame('-', ConsoleInvocation::commandName(['artisan', '-', self::CHECK]));
        self::assertSame('-', ConsoleInvocation::commandName(['artisan', '--env', '-', self::CHECK]));
        self::assertSame('acme:doctor', ConsoleInvocation::commandName(['artisan', '--strict=yes', 'acme:doctor']));
        self::assertSame('', ConsoleInvocation::commandName(['artisan', '', self::CHECK]));
    }

    /**
     * The definition is the console's own: the command argument, the options
     * Symfony defines and Laravel's `--env`, which takes an optional value,
     * while `--verbose` takes none.
     *
     * @return void
     */
    public function testTheDefinitionIsTheConsolesOwn(): void
    {
        $definition = ConsoleInvocation::definition();

        self::assertTrue($definition->hasArgument('command'));
        self::assertTrue($definition->getOption('env')->isValueOptional());
        self::assertFalse($definition->getOption('verbose')->acceptValue());
        self::assertTrue($definition->hasOption('silent'));
        self::assertTrue($definition->hasNegation('no-ansi'));
        self::assertSame('help', $definition->getOptionForShortcut('h')->getName());
        self::assertSame('version', $definition->getOptionForShortcut('V')->getName());
    }
}
