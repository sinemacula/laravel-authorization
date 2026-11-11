<?php

declare(strict_types = 1);

namespace Tests\Feature\Diagnostics;

use Illuminate\Config\Repository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Diagnostics\BootChecks;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigurationReport;
use SineMacula\Laravel\Authorization\Diagnostics\Declarations;
use SineMacula\Laravel\Authorization\Diagnostics\DiagnosticMode;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\PackageStatus;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\ReportStatus;
use SineMacula\Laravel\Authorization\Diagnostics\Inspector;
use SineMacula\Laravel\Authorization\Diagnostics\PackageState;
use SineMacula\Laravel\Authorization\Diagnostics\SeamRow;
use SineMacula\Laravel\Authorization\Diagnostics\Settings\SettingCatalogue;
use SineMacula\Laravel\Authorization\Diagnostics\Settings\SettingRow;
use Tests\Fixtures\Diagnostics\ExplodingTenantTree;
use Tests\Fixtures\Diagnostics\Explosions;
use Tests\Fixtures\Diagnostics\ThrowingContextSource;
use Tests\Fixtures\GrantHooks\RecordingGrantHook;
use Tests\Fixtures\GrantHooks\SecondGrantHook;
use Tests\TestCase;

/**
 * Feature tests for the configuration report of an application that booted: its
 * versioned shape, its status, that building it builds and queries nothing,
 * that an unknown factory never fails it, that it never shows a secret, and
 * that a part that cannot be read leaves it incomplete.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Inspector::class)]
final class InspectorTest extends TestCase
{
    /** @var string A secret that must never appear in the report. */
    private const string SECRET = 'Hunter2Secret';

    /**
     * Reset the count of seams built.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Explosions::$count = 0;
    }

    /**
     * The report of the application the suite boots passes, in the versioned
     * shape, with every setting, every seam, the grant hooks, the connection
     * and the integrations.
     *
     * @return void
     */
    public function testTheReportOfTheBootedApplicationPasses(): void
    {
        $report = $this->inspect();
        $shape  = $report->toArray();

        self::assertSame(ReportStatus::PASSED, $report->status);
        self::assertSame(['version', 'status', 'settings', 'seams', 'grant_hooks', 'connection', 'integrations', 'issues'], \array_keys($shape));
        self::assertSame(1, $shape['version']);
        self::assertSame('passed', $shape['status']);
        self::assertSame([], $shape['issues']);
        self::assertSame(\array_keys(SettingCatalogue::SETTINGS), \array_map(static fn (SettingRow $row): string => $row->path, $report->settings));
        $contracts = \array_map(static fn (SeamRow $row): string => $row->contract, $report->seams);

        self::assertSame(Inspector::SEAMS, \array_slice($contracts, 0, \count(Inspector::SEAMS)));
        self::assertSame(\array_values(\array_unique($contracts)), $contracts);
        self::assertSame('testing', $shape['connection']['database']['name']);
        self::assertSame('default', $shape['connection']['database']['chosen']);
        self::assertSame('not_tested', $shape['connection']['database']['connectivity']);
        self::assertSame([
            'gate'                  => 'enabled',
            'blade_directives'      => 'registered',
            'query_macro'           => 'registered',
            'grammar_macro'         => 'registered',
            'middleware.role'       => 'registered',
            'middleware.permission' => 'registered',
            'middleware.authorize'  => 'registered',
        ], \array_column($report->integrations, 'state', 'name'));
    }

    /**
     * A contract a sibling package declared that the package neither binds nor
     * reads follows the package's seams, and the seams stay a list.
     *
     * @return void
     */
    public function testADeclaredContractFollowsThePackagesSeams(): void
    {
        Declarations::of($this->container())->adapter('Acme\Thing', 'acme/thing', ExplodingTenantTree::class, Lifetime::SCOPED);

        $report = $this->inspect();
        $seams  = $report->toArray()['seams'];

        self::assertIsArray($seams);
        self::assertTrue(\array_is_list($seams));
        self::assertSame('Acme\Thing', $report->seams[\count($report->seams) - 1]->contract);
        self::assertSame(0, Explosions::$count);
    }

    /**
     * Building the report builds no seam, resolves nothing that was not
     * resolved before and runs no query.
     *
     * @return void
     */
    public function testInspectingBuildsNothingAndQueriesNothing(): void
    {
        $app = $this->container();

        $app->bind(TenantTree::class, ExplodingTenantTree::class);

        $queries  = [];
        $resolved = \array_map($app->resolved(...), Inspector::SEAMS);

        Event::listen(QueryExecuted::class, static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        $this->inspect();

        self::assertSame([], $queries);
        self::assertSame($resolved, \array_map($app->resolved(...), Inspector::SEAMS));
        self::assertSame(0, Explosions::$count);
    }

    /**
     * A setting changed after boot to one the check refuses refuses the report,
     * whose exit code is 1.
     *
     * @return void
     */
    public function testARefusedSettingRefusesTheReport(): void
    {
        \config(['authorization.models.rol' => 'X', 'authorization.bulk.chunk_size' => 0]);

        $report = $this->inspect();
        $rows   = \array_column(\array_map(static fn (SettingRow $row): array => $row->toArray(), $report->settings), null, 'path');

        self::assertSame(ReportStatus::REFUSED, $report->status);
        self::assertSame(1, $report->status->exitCode());
        self::assertSame('refused', $rows['authorization.models.rol']['status']);
        self::assertFalse($rows['authorization.models.rol']['known']);
        self::assertSame('refused', $rows['authorization.bulk.chunk_size']['status']);
        self::assertSame('ok', $rows['authorization.models.role']['status']);
    }

    /**
     * Booted for diagnosis, the report shows what the boot stored rather than
     * checking again: the very issues it found, the failure of a check that
     * builds what a setting names among them, which the structural check alone
     * cannot find, and that check's outcome on its setting.
     *
     * @return void
     */
    public function testBootedForDiagnosisWhatTheBootFoundIsReported(): void
    {
        $app = $this->container();

        DiagnosticMode::enable($app);
        $app['config']->set('authorization.context.sources', [ThrowingContextSource::class]);

        $state = PackageState::start($app);

        (new AuthorizationServiceProvider($app))->boot();

        $report = $this->inspect();
        $rows   = \array_column(\array_map(static fn (SettingRow $row): array => $row->toArray(), $report->settings), 'status', 'path');

        self::assertSame(PackageStatus::REFUSING, $state->status());
        self::assertNotSame([], $report->issues);
        self::assertSame($state->findings()?->issues, $report->issues);
        self::assertSame('failed_at_boot', $rows[BootChecks::CONTEXT]);
        self::assertSame(ReportStatus::INCOMPLETE, $report->status);
    }

    /**
     * A seam bound to custom code whose class is decided at first use is shown
     * by where the code is written, and the report still passes. The suite's
     * base path is Testbench's, so the file is shown whole.
     *
     * @return void
     */
    public function testAnUnknownFactoryNeverFailsTheReport(): void
    {
        $line = __LINE__ + 1;
        $this->container()->bind(TenantTree::class, static fn (): TenantTree => new ExplodingTenantTree);

        $report = $this->inspect();
        $rows   = \array_column(\array_map(static fn (SeamRow $row): array => $row->toArray(), $report->seams), null, 'contract');

        self::assertSame(ReportStatus::PASSED, $report->status);
        self::assertSame('later_binding', $rows[TenantTree::class]['origin']);
        self::assertNull($rows[TenantTree::class]['class']);
        self::assertSame(__FILE__ . ":{$line}", $rows[TenantTree::class]['factory'], 'A file outside the base path is shown whole.');
    }

    /**
     * The file custom code is written in is shown relative to the application's
     * base path when it lies under it.
     *
     * @return void
     */
    public function testTheFactoryIsShownRelativeToTheBasePath(): void
    {
        $app = $this->container();

        $app->setBasePath(\dirname(__DIR__, 3));

        $line = __LINE__ + 1;
        $app->bind(TenantTree::class, static fn (): TenantTree => new ExplodingTenantTree);

        $rows = \array_column(\array_map(static fn (SeamRow $row): array => $row->toArray(), $this->inspect()->seams), null, 'contract');

        self::assertSame("tests/Feature/Diagnostics/InspectorTest.php:{$line}", $rows[TenantTree::class]['factory']);
    }

    /**
     * The grant hooks are listed in the order they run: those the configuration
     * lists, then the bound hook.
     *
     * @return void
     */
    public function testTheGrantHooksAreListedInTheOrderTheyRun(): void
    {
        \config(['authorization.grant_hooks' => [RecordingGrantHook::class, SecondGrantHook::class]]);

        $hooks = $this->inspect()->grantHooks;

        self::assertSame([[1, 'configured', RecordingGrantHook::class], [2, 'configured', SecondGrantHook::class], [3, 'bound', null]], \array_map(
            static fn (array $hook): array => [$hook['position'], $hook['source'], $hook['source'] === 'bound' ? null : $hook['class']],
            $hooks,
        ));
        self::assertSame('package_default', $hooks[2]['origin']);
        self::assertFalse($hooks[2]['runs']);
    }

    /**
     * No secret is shown: neither a value under an unknown key, nor one of a
     * setting whose values are never shown, nor the credentials of the
     * connection, nor a value an issue is about.
     *
     * @return void
     */
    public function testTheReportShowsNoSecret(): void
    {
        \config([
            'authorization.password'                => self::SECRET,
            'authorization.cache.prefix'            => self::SECRET,
            'authorization.log_channel'             => 'p@ss ' . self::SECRET,
            'database.connections.testing.password' => self::SECRET,
            'database.connections.testing.url'      => 'pgsql://user:' . self::SECRET . '@localhost/db',
        ]);

        $report = $this->inspect();
        $shape  = (string) \json_encode($report->toArray());

        self::assertSame(ReportStatus::REFUSED, $report->status);
        self::assertStringNotContainsString(self::SECRET, $shape);
        self::assertStringContainsString('"authorization.password"', $shape);
    }

    /**
     * A part of the report that cannot be read is left empty and makes the
     * report incomplete, naming the part by its class alone, while the rest is
     * still reported.
     *
     * @return void
     */
    public function testAPartThatCannotBeReadMakesTheReportIncomplete(): void
    {
        $config = new class extends Repository {
            /**
             * Fail to read the configuration.
             *
             * @param  mixed  $key
             * @param  mixed  $default
             * @return mixed
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function get(mixed $key, mixed $default = null): mixed
            {
                throw new \RuntimeException('The configuration could not be read: ' . InspectorTest::secret());
            }
        };

        $report = (new Inspector($this->container(), $config))->inspect();
        $issues = \array_column(\array_map(static fn (ConfigIssue $issue): array => $issue->toArray(), $report->issues), null, 'path');

        self::assertSame(ReportStatus::INCOMPLETE, $report->status);
        self::assertSame(3, $report->status->exitCode());
        self::assertSame(\RuntimeException::class, $issues['report.configuration']['exception'] ?? null);
        self::assertArrayHasKey('report.connection', $issues);
        self::assertSame('{"database":null,"cache":null,"queue":null}', \json_encode($report->toArray()['connection']));
        self::assertNotSame([], $report->seams);
        self::assertStringNotContainsString(self::SECRET, (string) \json_encode($report->toArray()));
    }

    /**
     * Return the secret no part of the report may show.
     *
     * @return string
     */
    public static function secret(): string
    {
        return self::SECRET;
    }

    /**
     * Return the report of the suite's application.
     *
     * @return \SineMacula\Laravel\Authorization\Diagnostics\ConfigurationReport
     */
    private function inspect(): ConfigurationReport
    {
        $app = $this->container();

        return (new Inspector($app, $app->make('config')))->inspect();
    }
}
