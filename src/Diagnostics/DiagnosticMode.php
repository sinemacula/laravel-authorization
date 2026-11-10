<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Authorization\Console\CheckConfigurationCommand;

/**
 * Whether the application boots the package for diagnosis: to report what is
 * wrong with its configuration, every operation refusing while it is, rather
 * than refusing to boot (N113).
 *
 * It does only while the process runs a check command, which is decided as the
 * application boots, after every provider registered, from:
 *
 * - the switch, which a caller that boots an application itself to run the
 *   check, such as a script calling the console kernel's `call()`, turns on
 *   with `enable()` before the application boots, as `call()` boots it before
 *   running the command, so the command cannot catch what the boot throws;
 * - the process's arguments, in the console only: the command they run, read as
 *   the console reads it (see `ConsoleInvocation`), is `authorization:check` or
 *   a command a sibling package declared as running it in the same process (see
 *   `Declarations::composingCommand()`).
 *
 * The switch is held as an instance of the container, never statically nor in
 * the environment, so it reaches one application alone. A flag a sibling sets
 * once its own check is running, after the application booted, comes too late
 * to count.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class DiagnosticMode
{
    /**
     * Have the application boot the package for diagnosis, whatever command the
     * process runs. Turned on before the application boots.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     */
    public static function enable(Container $container): void
    {
        $container->instance(self::class, new self);
    }

    /**
     * Determine whether the switch is on in the container.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return bool
     */
    public static function isEnabled(Container $container): bool
    {
        return ContainerState::instance($container, self::class) instanceof self;
    }

    /**
     * Determine whether the application boots the package for diagnosis: the
     * switch is on, or the console runs a check command.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  array<array-key, mixed>|null  $argv
     * @return bool
     */
    public static function isOn(Application $app, ?array $argv = null): bool
    {
        if (self::isEnabled($app)) {
            return true;
        }

        $name = $app->runningInConsole() ? ConsoleInvocation::commandName($argv ?? self::argv()) : null;

        return $name !== null && ($name === CheckConfigurationCommand::NAME || self::declarations($app)?->isComposing($name) === true);
    }

    /**
     * Return the process's arguments, or none when it has none.
     *
     * @return array<array-key, mixed>
     */
    private static function argv(): array
    {
        $argv = $_SERVER['argv'] ?? [];

        return \is_array($argv) ? $argv : [];
    }

    /**
     * Return the declarations the application holds, without holding new ones
     * when it holds none.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return \SineMacula\Laravel\Authorization\Diagnostics\Declarations|null
     */
    private static function declarations(Container $container): ?Declarations
    {
        $declarations = ContainerState::instance($container, Declarations::class);

        return $declarations instanceof Declarations ? $declarations : null;
    }
}
