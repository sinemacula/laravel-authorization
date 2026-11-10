<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Foundation\Application as ApplicationContract;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Diagnostics\Declarations;
use SineMacula\Laravel\Authorization\Diagnostics\DiagnosticMode;
use SineMacula\Laravel\Authorization\Diagnostics\PackageState;
use Tests\Fixtures\Diagnostics\ComposingCommandProvider;

/**
 * Unit tests for whether the application boots the package for diagnosis: while
 * the console runs a check command, read from the process's arguments, or when
 * the switch is on.
 *
 * Each test sets the process's arguments itself and restores them after.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DiagnosticMode::class)]
final class DiagnosticModeTest extends TestCase
{
    /** @var \Illuminate\Container\Container|null The container that was the instance before the test. */
    private ?Container $instance = null;

    /**
     * Keep the container that is the instance, as each application built
     * becomes it.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->instance = Container::getInstance();
    }

    /**
     * Restore the container that was the instance and close the doubles.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Container::setInstance($this->instance);
        \Mockery::close();

        parent::tearDown();
    }

    /**
     * Provide the arguments of a console running the check command, with
     * options the console defines before it.
     *
     * @return iterable<string, array{list<string>}>
     */
    public static function checkProvider(): iterable
    {
        yield 'plain' => [['artisan', 'authorization:check']];
        yield 'verbose' => [['artisan', '-vvv', 'authorization:check']];
        yield 'quiet and without interaction' => [['artisan', '-q', '--no-interaction', 'authorization:check']];
        yield '--env x' => [['artisan', '--env', 'testing', 'authorization:check', '--format=json']];
        yield '--env=x' => [['artisan', '--env=testing', 'authorization:check']];
        yield 'after --' => [['artisan', '--no-ansi', '--', 'authorization:check']];
        yield 'its own option before it' => [['artisan', '--format=json', 'authorization:check']];
        yield 'its own option after a global one' => [['artisan', '-n', '--format=json', 'authorization:check']];
    }

    /**
     * The console running the check command boots the package for diagnosis,
     * whatever options the console defines come before it, and its own given a
     * value after `=`.
     *
     * @param  list<string>  $argv
     * @return void
     */
    #[DataProvider('checkProvider')]
    public function testTheCheckCommandTurnsItOn(array $argv): void
    {
        self::assertTrue(self::withArgv($argv, static fn (): bool => DiagnosticMode::isOn(self::application())));
    }

    /**
     * Provide the arguments of a console that runs no check command as named.
     *
     * @return iterable<string, array{list<string>}>
     */
    public static function otherProvider(): iterable
    {
        yield 'another command' => [['artisan', 'list']];
        yield 'no command' => [['artisan']];
        yield 'help on the check command' => [['artisan', 'authorization:check', '--help']];
        yield 'the version' => [['artisan', '-V', 'authorization:check']];
        yield 'an abbreviation' => [['artisan', 'authorization:ch']];
        yield 'an option the console does not define' => [['artisan', '--bogus', 'authorization:check']];
        yield '--verbose given a value' => [['artisan', '--verbose=2', 'authorization:check']];
        yield '--env taking the command as its value' => [['artisan', '--env', 'authorization:check']];
    }

    /**
     * Any other command, help or the version, an abbreviation and arguments the
     * console refuses leave the package booting as it always has.
     *
     * @param  list<string>  $argv
     * @return void
     */
    #[DataProvider('otherProvider')]
    public function testItIsOffForAnythingElse(array $argv): void
    {
        self::assertFalse(self::withArgv($argv, static fn (): bool => DiagnosticMode::isOn(self::application())));
    }

    /**
     * Outside the console the arguments are not read.
     *
     * @return void
     */
    public function testItIsOffOutsideTheConsole(): void
    {
        $app = \Mockery::mock(ApplicationContract::class);
        $app->shouldReceive('runningInConsole')->andReturnFalse(); // @phpstan-ignore method.notFound

        self::assertFalse(DiagnosticMode::isOn($app, ['artisan', 'authorization:check']));
    }

    /**
     * The arguments given are read in place of the process's own.
     *
     * @return void
     */
    public function testTheArgumentsGivenAreRead(): void
    {
        $isOn = self::withArgv(['artisan', 'list'], static fn (): bool => DiagnosticMode::isOn(self::application(), ['artisan', 'authorization:check']));

        self::assertTrue($isOn);
    }

    /**
     * A command a sibling declared as running the check in the same process
     * turns it on, by its exact name; undeclared, it does not.
     *
     * @return void
     */
    public function testADeclaredComposingCommandTurnsItOn(): void
    {
        $declared = self::application();

        Declarations::of($declared)->composingCommand(ComposingCommandProvider::COMMAND);

        self::withArgv(['artisan', '-v', ComposingCommandProvider::COMMAND], static function () use ($declared): void {
            self::assertTrue(DiagnosticMode::isOn($declared));
            self::assertFalse(DiagnosticMode::isOn(self::application()));
        });

        self::assertFalse(DiagnosticMode::isOn($declared, ['artisan', 'acme:doc']));
    }

    /**
     * A composing command a sibling registered after the package declares
     * counts, as the mode is decided as the application boots.
     *
     * @return void
     */
    public function testACompositionDeclaredAfterThePackageRegisteredCounts(): void
    {
        $app = self::application();

        (new AuthorizationServiceProvider($app))->register();

        $app->register(ComposingCommandProvider::class);

        self::withArgv(['artisan', ComposingCommandProvider::COMMAND], static function () use ($app): void {
            $app->boot();
        });

        self::assertTrue(PackageState::of($app)?->isDiagnostic());
    }

    /**
     * The switch turns it on whatever command runs, in the application it is
     * turned on in alone.
     *
     * @return void
     */
    public function testTheSwitchTurnsItOn(): void
    {
        $app = self::application();

        DiagnosticMode::enable($app);

        self::assertTrue(DiagnosticMode::isEnabled($app));
        self::assertTrue(DiagnosticMode::isOn($app, ['artisan', 'list']));
        self::assertFalse(DiagnosticMode::isEnabled(self::application()));
    }

    /**
     * The switch turned on once the application booted, as a sibling's own flag
     * set once its check runs would be, comes too late to count.
     *
     * @return void
     */
    public function testTheSwitchTurnedOnAfterTheBootIsTooLate(): void
    {
        $app = self::application();

        (new AuthorizationServiceProvider($app))->register();

        self::withArgv(['artisan', 'list'], static function () use ($app): void {
            $app->boot();
        });

        DiagnosticMode::enable($app);

        self::assertFalse(PackageState::of($app)?->isDiagnostic());
    }

    /**
     * Run the callback with the process's arguments set to those given,
     * restoring them after.
     *
     * @template TResult
     *
     * @param  list<string>  $argv
     * @param  \Closure(): TResult  $run
     * @return TResult
     */
    private static function withArgv(array $argv, \Closure $run): mixed
    {
        $saved = $_SERVER['argv'] ?? null;

        $_SERVER['argv'] = $argv;

        try {
            return $run();
        } finally {
            if ($saved === null) {
                unset($_SERVER['argv']);
            } else {
                $_SERVER['argv'] = $saved;
            }
        }
    }

    /**
     * Return a new application holding the package's configuration alone.
     *
     * @return \Illuminate\Foundation\Application
     */
    private static function application(): Application
    {
        $app = new Application(\dirname(__DIR__, 3));

        $app->instance('config', new Repository(['authorization' => []]));

        return $app;
    }
}
