<?php

declare(strict_types = 1);

namespace Tests\Feature\Diagnostics;

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as OrchestraTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Console\CheckConfigurationCommand;
use SineMacula\Laravel\Authorization\Diagnostics\BootChecks;
use SineMacula\Laravel\Authorization\Diagnostics\DiagnosticMode;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\PackageStatus;
use SineMacula\Laravel\Authorization\Diagnostics\Inspector;
use SineMacula\Laravel\Authorization\Diagnostics\PackageState;
use SineMacula\Laravel\Authorization\Diagnostics\Settings\SettingsReader;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use Symfony\Component\Console\Output\BufferedOutput;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\RecordingPermissionProvider;
use Tests\Fixtures\Diagnostics\ComposingCheckCommand;
use Tests\Fixtures\Diagnostics\ComposingCommandProvider;
use Tests\Fixtures\Diagnostics\ThrowingContextSource;

/**
 * Feature tests for `authorization:check` on an application booted for
 * diagnosis: the report holds what the boot found, every issue and what became
 * of each check it ran by building what a setting names, and the command exits
 * 1 for a refused configuration or 3 for one that could not be checked
 * completely, while every operation of the package refuses.
 *
 * Each application boots on an empty in-memory database with no package tables,
 * as before `migrate`, with a permission enum and a provider of permissions
 * configured, and a sibling registered after the package declaring a command of
 * its own that runs the check in the same process. The process's arguments, or
 * the switch, are set before the application is created, and every query is
 * recorded from then on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckConfigurationCommand::class)]
#[CoversClass(Inspector::class)]
#[CoversClass(SettingsReader::class)]
final class DiagnosticCheckTest extends OrchestraTestCase
{
    /** @var array<string, mixed> A refused configuration: an unknown key, a value out of range, and a context source left to the boot. */
    private const array REFUSED = [
        'nonsense' => true,
        'cache'    => ['ttl' => 0],
        'context'  => ['sources' => [ThrowingContextSource::class]],
    ];

    /** @var array<string, array{list<string>|null, array<string, mixed>}> Each test's process arguments, or null for the switch, and configuration. */
    private const array BOOTS = [
        'testARefusedConfigurationIsReportedWithEveryIssueAndExitsOne'        => [['artisan', '-n', CheckConfigurationCommand::NAME], self::REFUSED],
        'testAnUnforeseenFailureAloneExitsThreeAndEveryOperationStillRefuses' => [null, ['context' => ['sources' => [ThrowingContextSource::class]]]],
        'testASoundConfigurationReportsEachCheckTheBootRanAndExitsZero'       => [['artisan', CheckConfigurationCommand::NAME, '--format=json'], ['cache' => ['store' => 'array']]],
        'testAComposingCommandGetsTheExitCodeAndTheTextWithoutAThrow'         => [['artisan', ComposingCommandProvider::COMMAND], self::REFUSED],
    ];

    /** @var list<string> Every query run since the application was created. */
    private array $queries = [];

    /**
     * On a refused configuration the application boots for the check: the
     * command lists every issue, shows the check the boot left unrun as not
     * run, exits 1, runs no query and never reads the provider, and every
     * operation refuses, naming the first refusal.
     *
     * @return void
     */
    public function testARefusedConfigurationIsReportedWithEveryIssueAndExitsOne(): void
    {
        self::assertSame(PackageStatus::REFUSING, $this->state()->status());

        [$code, $text] = $this->check();

        self::assertSame(1, $code);
        self::assertStringStartsWith('[setting authorization.nonsense] unknown key', $text);
        self::assertStringContainsString("\n[setting authorization.cache.ttl] out of range", $text);
        self::assertStringContainsString("\n[setting " . BootChecks::CONTEXT . '] not run at boot; [' . ThrowingContextSource::class . ']', $text);
        self::assertStringEndsWith("A check failed.\n", $text);

        [$jsonCode, $statuses] = $this->statuses();

        self::assertSame(1, $jsonCode);
        self::assertSame('not_run', $statuses[BootChecks::CONTEXT] ?? null);
        self::assertSame('refused', $statuses['authorization.cache.ttl'] ?? null);

        $refusal = $this->refusal();

        self::assertSame(['authorization.nonsense', IssueCode::UNKNOWN_KEY], [$refusal->getConfigKey(), $refusal->getIssue()]);
        $this->assertNothingQueried();
    }

    /**
     * A check that builds what the configuration names and fails unforeseen,
     * with nothing refused, exits 3, shows the setting as failed at boot by the
     * exception's class alone, and every operation still refuses.
     *
     * @return void
     */
    public function testAnUnforeseenFailureAloneExitsThreeAndEveryOperationStillRefuses(): void
    {
        [$code, $text] = $this->check();

        self::assertSame(3, $code);
        self::assertStringStartsWith('[setting ' . BootChecks::CONTEXT . "] could not be completed (RuntimeException)\n", $text);
        self::assertStringContainsString("\n[setting " . BootChecks::CONTEXT . '] failed at boot; ', $text);
        self::assertStringEndsWith("The check could not be completed.\n", $text);
        self::assertStringNotContainsString(ThrowingContextSource::MESSAGE, $text);

        [$jsonCode, $statuses] = $this->statuses();

        self::assertSame(3, $jsonCode);
        self::assertSame('failed_at_boot', $statuses[BootChecks::CONTEXT] ?? null);
        self::assertSame(IssueCode::INTERNAL, $this->refusal()->getIssue());
        $this->assertNothingQueried();
    }

    /**
     * A sound configuration boots for the check as it boots otherwise: the
     * command shows each check the boot ran as checked at boot and exits 0, and
     * the operations run.
     *
     * @return void
     */
    public function testASoundConfigurationReportsEachCheckTheBootRanAndExitsZero(): void
    {
        self::assertSame(PackageStatus::HEALTHY, $this->state()->status());
        self::assertTrue($this->state()->isDiagnostic());

        [$code, $statuses] = $this->statuses();

        self::assertSame(0, $code);
        self::assertSame('checked_at_boot', $statuses[BootChecks::CACHE] ?? null);
        self::assertSame(0, $this->check()[0]);
        self::assertNotNull($this->app?->make('authorization'));
        $this->assertNothingQueried();
    }

    /**
     * A command a sibling registered after the package declares as running the
     * check boots the application for diagnosis; calling the check in the same
     * process through the console kernel, it gets exit code 1 and the text on
     * the output it passed, and nothing is thrown.
     *
     * @return void
     */
    public function testAComposingCommandGetsTheExitCodeAndTheTextWithoutAThrow(): void
    {
        self::assertTrue($this->state()->isDiagnostic());

        Artisan::registerCommand(new ComposingCheckCommand);

        $output = new BufferedOutput;
        $code   = $this->kernel()->call(ComposingCommandProvider::COMMAND, [], $output);
        $text   = $output->fetch();

        self::assertSame(1, $code);
        self::assertStringStartsWith('[setting authorization.nonsense] unknown key', $text);
        self::assertStringEndsWith("A check failed.\n", $text);
        $this->assertNothingQueried();
    }

    /**
     * Create the application with the process's arguments the test runs with,
     * restoring them once it booted, as the package decides whether it boots
     * for diagnosis as the application boots.
     *
     * @return void
     */
    #[\Override]
    protected function refreshApplication(): void
    {
        $argv = $_SERVER['argv'] ?? null;

        try {
            $_SERVER['argv'] = self::BOOTS[$this->name()][0] ?? $argv;

            parent::refreshApplication();
        } finally {
            $_SERVER['argv'] = $argv;
        }
    }

    /**
     * Register the package's provider, then a sibling's declaring a command
     * that runs the check.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return [AuthorizationServiceProvider::class, ComposingCommandProvider::class];
    }

    /**
     * Use an empty in-memory database, whatever the suite's driver, set the
     * configuration the test boots with, turn the switch on when the test uses
     * it, and record every query, before any provider registers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        [$argv, $authorization] = self::BOOTS[$this->name()] ?? [[], []];

        /** @var \Illuminate\Config\Repository $config */
        $config = $app['config'];

        $config->set('database.default', 'fresh');
        $config->set('database.connections.fresh', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        $config->set('authorization.permission_enums', [PermissionEnum::class]);
        $config->set('authorization.permission_providers', [RecordingPermissionProvider::class]);

        foreach ($authorization as $key => $value) {
            $config->set("authorization.{$key}", $value);
        }

        if ($argv === null) {
            DiagnosticMode::enable($app);
        }

        RecordingPermissionProvider::$reads = 0;

        $app['events']->listen(QueryExecuted::class, function (QueryExecuted $query): void {
            $this->queries[] = $query->sql;
        });
    }

    /**
     * Run the check as text through the console kernel, and return its exit
     * code and text.
     *
     * @return array{int, string}
     */
    private function check(): array
    {
        $output = new BufferedOutput;
        $code   = $this->kernel()->call(CheckConfigurationCommand::NAME, [], $output);

        return [$code, $output->fetch()];
    }

    /**
     * Run the check as JSON through the console kernel, and return its exit
     * code and the status of each setting, by path.
     *
     * @return array{int, array<array-key, mixed>}
     *
     * @throws \JsonException
     */
    private function statuses(): array
    {
        $output = new BufferedOutput;
        $code   = $this->kernel()->call(CheckConfigurationCommand::NAME, ['--format' => 'json'], $output);
        $report = \json_decode($output->fetch(), true, 512, \JSON_THROW_ON_ERROR);

        self::assertIsArray($report);
        self::assertIsArray($report['settings'] ?? null);

        return [$code, \array_column($report['settings'], 'status', 'path')];
    }

    /**
     * Return the refusal building the manager throws.
     *
     * @return \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private function refusal(): InvalidAuthorizationConfigException
    {
        return self::refusalOf(fn (): mixed => $this->app?->make('authorization'));
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

    /**
     * Assert that no query ran, no provider of permissions was read and no
     * package table exists, as before `migrate`.
     *
     * @return void
     */
    private function assertNothingQueried(): void
    {
        self::assertSame([], $this->queries);
        self::assertSame(0, RecordingPermissionProvider::$reads);
        self::assertFalse(Schema::hasTable('permissions'));
    }

    /**
     * Return the package's state.
     *
     * @return \SineMacula\Laravel\Authorization\Diagnostics\PackageState
     */
    private function state(): PackageState
    {
        $state = $this->app === null ? null : PackageState::of($this->app);

        self::assertNotNull($state);

        return $state;
    }

    /**
     * Return the console kernel.
     *
     * @return \Illuminate\Contracts\Console\Kernel
     */
    private function kernel(): Kernel
    {
        $kernel = $this->app?->make(Kernel::class);

        self::assertInstanceOf(Kernel::class, $kernel);

        return $kernel;
    }
}
