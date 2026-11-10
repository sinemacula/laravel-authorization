<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

use Illuminate\Console\Application as ConsoleApplication;
use Symfony\Component\Console\Exception\ExceptionInterface;
use Symfony\Component\Console\Exception\InvalidOptionException;
use Symfony\Component\Console\Input\ArgvInput;
use Symfony\Component\Console\Input\InputDefinition;
use Symfony\Component\Console\Input\InputOption;

/**
 * Read the name of the command the console runs from the process's arguments,
 * as the console reads it, before the console application is built.
 *
 * The arguments are read against the console's own global options, those
 * Symfony defines and Laravel's `--env`, read from the console application's
 * class without building it: an option that takes no value (`-v`, `-vv`,
 * `--verbose`, `-q`, `--quiet`, `--silent`, `-n`, `--no-interaction`, `--ansi`,
 * `--no-ansi`) is skipped, `--env` takes the value after `=` or, as the console
 * reads it, the next argument when that is no option, and `--` ends the
 * options, the argument after it being the command's name. The first argument
 * that is no option names the command, as it is given: an abbreviation the
 * console would expand is not expanded.
 *
 * No name is read when an option before the command is one the console does not
 * define or is given a value it does not take, as the console then refuses to
 * run the command, nor when help or the version is asked for anywhere before a
 * `--`, as the console then shows them instead of running the command.
 *
 * The console application's class is read without running its constructor,
 * which would resolve every command the providers registered (hence php:S3011).
 *
 * @SuppressWarnings("php:S3011")
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConsoleInvocation
{
    /** @var list<string> The options that show help or the version instead of running the command. */
    private const array INSTEAD = ['--help', '-h', '--version', '-V'];

    /**
     * Return the name of the command the arguments run, the script's name
     * first, or null when they run none the console would run as named.
     *
     * @param  array<array-key, mixed>  $argv
     * @return string|null
     */
    public static function commandName(array $argv): ?string
    {
        $given  = \array_slice($argv, 1);
        $tokens = \array_values(\array_filter($given, \is_string(...)));

        if (\count($tokens) !== \count($given) || self::asksInstead($tokens)) {
            return null;
        }

        try {
            return self::firstArgument($tokens, self::definition());
        } catch (ExceptionInterface) {
            return null;
        }
    }

    /**
     * Return the console's global options and its command argument, as the
     * console application defines them.
     *
     * @return \Symfony\Component\Console\Input\InputDefinition
     */
    public static function definition(): InputDefinition
    {
        $console = (new \ReflectionClass(ConsoleApplication::class))->newInstanceWithoutConstructor();

        // The help option's description names the default command, which the
        // constructor would have set.
        $console->setDefaultCommand('list');

        /** @var \Symfony\Component\Console\Input\InputDefinition */
        return \Closure::bind(static fn (ConsoleApplication $console): InputDefinition => $console->getDefaultInputDefinition(), null, ConsoleApplication::class)($console);
    }

    /**
     * Determine whether the arguments ask for help or the version anywhere
     * before a `--`, as the console reads them.
     *
     * @param  list<string>  $tokens
     * @return bool
     */
    private static function asksInstead(array $tokens): bool
    {
        return (new ArgvInput(['', ...$tokens]))->hasParameterOption(self::INSTEAD, true);
    }

    /**
     * Return the first argument that is no option, skipping each option before
     * it and the value it takes.
     *
     * @param  list<string>  $tokens
     * @param  \Symfony\Component\Console\Input\InputDefinition  $definition
     * @return string|null
     *
     * @throws \Symfony\Component\Console\Exception\ExceptionInterface
     */
    private static function firstArgument(array $tokens, InputDefinition $definition): ?string
    {
        while ($tokens !== []) {
            $token = \array_shift($tokens);

            if ($token === '--') {
                return $tokens[0] ?? null;
            }

            if ($token === '' || $token === '-' || $token[0] !== '-') {
                return $token;
            }

            $tokens = \str_starts_with($token, '--')
                ? self::longOption(\substr($token, 2), $tokens, $definition)
                : self::shortOptions(\substr($token, 1), $tokens, $definition);
        }

        return null;
    }

    /**
     * Read a long option, its value given after `=` when there is one, and
     * return the arguments left once it has taken any value it takes.
     *
     * @param  string  $token
     * @param  list<string>  $tokens
     * @param  \Symfony\Component\Console\Input\InputDefinition  $definition
     * @return list<string>
     *
     * @throws \Symfony\Component\Console\Exception\ExceptionInterface
     */
    private static function longOption(string $token, array $tokens, InputDefinition $definition): array
    {
        $parts = \explode('=', $token, 2);

        return self::option($parts[0], $parts[1] ?? null, $tokens, $definition);
    }

    /**
     * Read a set of short options, such as `-v` or `-vvq`, and return the
     * arguments left once they have taken any value they take: an option that
     * takes a value takes the rest of the set, or the next argument when it
     * ends the set.
     *
     * @param  string  $set
     * @param  list<string>  $tokens
     * @param  \Symfony\Component\Console\Input\InputDefinition  $definition
     * @return list<string>
     *
     * @throws \Symfony\Component\Console\Exception\ExceptionInterface
     */
    private static function shortOptions(string $set, array $tokens, InputDefinition $definition): array
    {
        $length = \strlen($set);

        for ($index = 0; $index < $length; $index++) {
            $option = $definition->getOptionForShortcut($set[$index]);
            $rest   = \substr($set, $index + 1);

            if ($option->acceptValue()) {
                return self::option($option->getName(), $rest === '' ? null : $rest, $tokens, $definition);
            }

            $tokens = self::option($option->getName(), null, $tokens, $definition);
        }

        return $tokens;
    }

    /**
     * Read the option of the name, given the value or none, refusing one the
     * console does not define or a value it does not take, and return the
     * arguments left once it has taken the next one as its value when it takes
     * a value and was given none.
     *
     * @param  string  $name
     * @param  string|null  $value
     * @param  list<string>  $tokens
     * @param  \Symfony\Component\Console\Input\InputDefinition  $definition
     * @return list<string>
     *
     * @throws \Symfony\Component\Console\Exception\ExceptionInterface
     * @throws \Symfony\Component\Console\Exception\InvalidOptionException
     */
    private static function option(string $name, ?string $value, array $tokens, InputDefinition $definition): array
    {
        $option = $definition->hasNegation($name) && $value === null ? null : $definition->getOption($name);

        if ($option === null || !$option->acceptValue()) {
            if ($value !== null) {
                throw new InvalidOptionException("The \"--{$name}\" option does not accept a value.");
            }

            return $tokens;
        }

        return $value === null ? self::takeValue($option, $tokens) : $tokens;
    }

    /**
     * Return the arguments left once the option, which takes a value and was
     * given none, has taken the next one as its value, as the console takes it:
     * when it is empty or no option. One that requires a value and finds none
     * is refused.
     *
     * @param  \Symfony\Component\Console\Input\InputOption  $option
     * @param  list<string>  $tokens
     * @return list<string>
     *
     * @throws \Symfony\Component\Console\Exception\InvalidOptionException
     */
    private static function takeValue(InputOption $option, array $tokens): array
    {
        $next = $tokens[0] ?? null;

        if ($next !== null && ($next === '' || $next[0] !== '-')) {
            return \array_slice($tokens, 1);
        }

        if ($option->isValueRequired()) {
            throw new InvalidOptionException("The \"--{$option->getName()}\" option requires a value.");
        }

        return $tokens;
    }
}
