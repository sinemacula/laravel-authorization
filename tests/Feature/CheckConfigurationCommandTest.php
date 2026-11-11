<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Console\CheckConfigurationCommand;
use SineMacula\Laravel\Authorization\Console\Support\ReportText;
use SineMacula\Laravel\Authorization\Console\Support\SeamText;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Diagnostics\Declarations;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Tester\CommandTester;
use Tests\Fixtures\Diagnostics\ExplodingTenantTree;
use Tests\Fixtures\Diagnostics\Explosions;
use Tests\TestCase;

/**
 * Feature tests for `authorization:check`: the text and the versioned JSON of
 * the configuration report, which hold the same issues, seams and status; the
 * exit codes; that neither shows a secret; that the command builds and queries
 * nothing; and that a command calling it in-process gets its exit code and
 * text, never a throw.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckConfigurationCommand::class)]
#[CoversClass(ReportText::class)]
#[CoversClass(SeamText::class)]
final class CheckConfigurationCommandTest extends TestCase
{
    /** @var string The line reporting the Gate hook enabled. */
    private const string ENABLED = '[integration gate] enabled (the package answers every ability it declares through Gate::before)';

    /** @var string The line reporting the Gate hook disabled. */
    private const string DISABLED = '[integration gate] disabled (authorization.gate.enabled is false; Laravel decides every ability)';

    /** @var string A secret that must never be printed. */
    private const string SECRET = 'Hunter2Secret';

    /** @var string The line that ends the report when every check passed. */
    private const string PASSED = 'Every check passed.';

    /** @var array<string, mixed> Several settings the checks refuse: two unknown keys in one block, and bad values beside them. */
    private const array REFUSED = [
        'authorization.models.rol'      => 'X',
        'authorization.models.perm'     => 'Y',
        'authorization.bulk.chunk_size' => 0,
        'authorization.tables.roles'    => 'not a table',
        'authorization.defaults.guard'  => 'missing-guard',
    ];

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
     * The command is registered under its `NAME` constant, the name its
     * signature declares.
     *
     * @return void
     */
    public function testTheCommandsNameIsItsConstant(): void
    {
        self::assertSame('authorization:check', CheckConfigurationCommand::NAME);
        self::assertInstanceOf(CheckConfigurationCommand::class, Artisan::all()[CheckConfigurationCommand::NAME] ?? null);
        self::assertSame(CheckConfigurationCommand::NAME, Artisan::all()[CheckConfigurationCommand::NAME]->getName());
    }

    /**
     * With the shipped configuration the command reports the Gate hook enabled
     * among the integrations, and succeeds.
     *
     * @return void
     */
    public function testReportsTheGateHookEnabledByDefault(): void
    {
        [$code, $lines] = self::text();

        self::assertSame(0, $code);
        self::assertContains(self::ENABLED, $lines);
    }

    /**
     * With the switch off the command reports the Gate hook disabled, and still
     * succeeds.
     *
     * @return void
     */
    public function testReportsTheGateHookDisabled(): void
    {
        \config(['authorization.gate.enabled' => false]);

        [$code, $lines] = self::text();

        self::assertSame(0, $code);
        self::assertContains(self::DISABLED, $lines);
        self::assertNotContains(self::ENABLED, $lines);
    }

    /**
     * A `gate` block without the switch reports the Gate hook enabled, as the
     * switch is on unless it is false.
     *
     * @return void
     */
    public function testReportsTheGateHookEnabledWithoutTheSwitch(): void
    {
        \config(['authorization.gate' => []]);

        [$code, $lines] = self::text();

        self::assertSame(0, $code);
        self::assertContains(self::ENABLED, $lines);
    }

    /**
     * The text of a configuration that passes lists no issue, then the
     * settings, the seams, the grant hooks, the connection and the
     * integrations, each in its section, and ends saying every check passed.
     *
     * @return void
     */
    public function testTheTextListsEachSectionInOrder(): void
    {
        [$code, $lines] = self::text();

        $headings = \array_values(\array_filter($lines, static fn (string $line): bool => !\str_starts_with($line, '[')));
        $driver   = \config('database.connections.testing.driver');

        self::assertSame(0, $code);
        self::assertSame(
            ['Settings', 'Tables', 'Seams', 'Grant hooks, in the order they run; the chain stops at the first refusal', 'Connection', 'Integrations', self::PASSED],
            $headings,
        );
        self::assertSame('Settings', $lines[0], 'No issue is listed before the settings.');
        self::assertContains('[setting authorization.models.role] ok; SineMacula\Laravel\Authorization\Models\Role', $lines);
        self::assertContains('[setting authorization.cache.prefix] ok; value not shown (string)', $lines);
        self::assertContains('[seam PolicyStore] not bound; none', $lines);
        self::assertContains('[seam SubjectResolver] package default; SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver; scoped', $lines);
        self::assertContains('[connection database] testing; chosen by database.default; driver ' . (\is_string($driver) ? $driver : '') . '; not connected to', $lines);
    }

    /**
     * The prefix is reported as a setting and in the tables' section, with the
     * name each table takes: a default name with the prefix before it, one set
     * explicitly as written; the JSON holds the same.
     *
     * @return void
     */
    public function testReportsThePrefixAndTheNameEachTableTakes(): void
    {
        [, $default] = self::text();

        self::assertContains('[setting authorization.tables.prefix] ok; empty', $default);
        self::assertContains('[table prefix] none', $default);
        self::assertContains('[table roles] roles; the default, with the prefix', $default);

        \config(['authorization.tables.prefix' => 'app_', 'authorization.tables.roles' => 'authz_roles']);

        [$code, $lines] = self::text();
        [, $json]       = self::report();

        self::assertSame(0, $code);
        self::assertContains('[setting authorization.tables.prefix] ok; app_', $lines);
        self::assertSame(
            ['[table prefix] app_', '[table roles] authz_roles; set explicitly, so used as written', '[table permissions] app_permissions; the default, with the prefix'],
            \array_slice(self::starting($lines, '[table '), 0, 3),
        );
        self::assertCount(13, self::starting($lines, '[table '));
        /** @var array{prefix: string|null, names: list<array<string, mixed>>} $tables */
        $tables = $json['tables'];

        self::assertSame('app_', $tables['prefix']);
        self::assertSame(
            [['key' => 'roles', 'name' => 'authz_roles', 'explicit' => true], ['key' => 'permissions', 'name' => 'app_permissions', 'explicit' => false]],
            \array_slice($tables['names'], 0, 2),
        );
    }

    /**
     * A refused prefix is listed as an issue, each name left at its default as
     * skipped, and neither the prefix nor those names is shown.
     *
     * @return void
     */
    public function testARefusedPrefixIsReportedWithTheNamesItHides(): void
    {
        \config(['authorization.tables.prefix' => 'App-']);

        [$code, $lines] = self::text();

        $issues = self::issueLines($lines);

        self::assertSame(1, $code);
        $expected = 'empty, or a lower-case letter, then lower-case letters, digits and underscores, of at most 16 characters';

        self::assertSame("[setting authorization.tables.prefix] invalid value; expected {$expected}; found string", $issues[0]);
        self::assertContains('[setting authorization.tables.roles] skipped; it depends on authorization.tables.prefix, which was refused', $issues);
        self::assertContains('[setting authorization.tables.prefix] refused; value not shown (string)', $lines);
        self::assertContains('[table prefix] not known, as the setting was refused', $lines);
        self::assertContains('[table roles] not known, as its setting or the prefix was refused; the default, with the prefix', $lines);
    }

    /**
     * Each issue is listed on a line of its own before every section, several
     * unknown keys in one block and the bad values beside them all listed, and
     * the text ends saying a check failed, with exit code 1.
     *
     * @return void
     */
    public function testEveryIssueIsListedFirst(): void
    {
        \config(self::REFUSED);

        [$code, $lines] = self::text();

        $issues = self::issueLines($lines);

        self::assertSame(1, $code);
        self::assertSame('A check failed.', $lines[\count($lines) - 1]);
        self::assertContains('[setting authorization.models.rol] unknown key; expected one of role, permission, policy', $issues);
        self::assertContains('[setting authorization.models.perm] unknown key; expected one of role, permission, policy', $issues);
        self::assertCount(\count(self::REFUSED), $issues);

        foreach (\array_keys(self::REFUSED) as $path) {
            self::assertCount(1, \array_filter($issues, static fn (string $line): bool => \str_starts_with($line, "[setting {$path}]")), $path);
        }

        self::assertContains('[setting authorization.models.rol] refused; unknown key; value not shown (string)', $lines);
        self::assertContains('[setting authorization.bulk.chunk_size] refused; 0', $lines);
    }

    /**
     * The text and the JSON hold the same issues, the same seams, the same
     * settings and the same status.
     *
     * @return void
     */
    public function testTheTextAndTheJsonAgree(): void
    {
        \config(self::REFUSED);

        [$textCode, $lines] = self::text();
        [$jsonCode, $json]  = self::report();

        $seams    = self::starting($lines, '[seam ');
        $settings = self::starting(\array_slice($lines, \count(self::issueLines($lines))), '[setting ');

        self::assertSame($textCode, $jsonCode);
        self::assertSame('refused', $json['status']);
        self::assertSame(ReportText::CONCLUSIONS['refused'], $lines[\count($lines) - 1]);
        self::assertSame(
            \array_map(static fn (array $issue): string => '[setting ' . self::string($issue['path'] ?? null) . ']', self::listed($json, 'issues')),
            \array_map(static fn (string $line): string => \substr($line, 0, (int) \strpos($line, ']') + 1), self::issueLines($lines)),
        );
        self::assertCount(\count(self::listed($json, 'settings')), $settings);
        self::assertCount(\count(self::listed($json, 'seams')), $seams);

        foreach (self::listed($json, 'seams') as $index => $seam) {
            $contract = self::string($seam['contract'] ?? null);

            self::assertStringStartsWith('[seam ' . \substr($contract, (int) \strrpos($contract, '\\') + 1) . ']', $seams[$index]);
        }
    }

    /**
     * The JSON is the report's versioned shape alone on the standard output,
     * with nothing on the standard error.
     *
     * @return void
     */
    public function testTheJsonIsTheVersionedShapeAlone(): void
    {
        $tester = new CommandTester(Artisan::all()[CheckConfigurationCommand::NAME]);

        self::assertSame(0, $tester->execute(['--format' => 'json'], ['capture_stderr_separately' => true]));
        self::assertSame('', $tester->getErrorOutput());

        $json = self::decoded($tester->getDisplay());

        self::assertSame(['version', 'status', 'settings', 'tables', 'seams', 'grant_hooks', 'connection', 'integrations', 'issues'], \array_keys($json));
        self::assertSame(1, $json['version']);
        self::assertSame('passed', $json['status']);
        self::assertSame(['path', 'known', 'set', 'value', 'redacted', 'type', 'source', 'status'], \array_keys(self::listed($json, 'settings')[0]));
        $seamKeys = \array_keys(self::listed($json, 'seams')[0]);

        self::assertSame(['contract', 'origin', 'class', 'classes', 'decides', 'factory', 'lifetime', 'extenders'], \array_slice($seamKeys, 0, 8));
        self::assertSame(['config_key', 'alias', 'deferred_provider', 'deferred_provider_at_registration', 'previously_resolved', 'declaration'], \array_slice($seamKeys, 8));
        self::assertSame(['position', 'source', 'class', 'type', 'origin', 'factory', 'runs'], \array_keys(self::listed($json, 'grant_hooks')[0]));
        self::assertSame(['name', 'state', 'detail'], \array_keys(self::listed($json, 'integrations')[0]));
        self::assertSame(['database', 'cache', 'queue'], \array_keys((array) $json['connection']));
    }

    /**
     * Return each invalid invocation, with the error it is refused with.
     *
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function invalidInvocations(): iterable
    {
        yield 'an unknown format' => [['--format' => 'xml'], 'The --format option must be text or json.'];
        yield 'a format given no value' => [['--format' => null], 'The --format option must be given a value.'];
        yield 'an unknown option' => [['--verbose-report' => true], 'The "--verbose-report" option does not exist.'];
    }

    /**
     * An invalid invocation exits 2, its error on the standard error alone, and
     * prints no report.
     *
     * @param  array<string, mixed>  $parameters
     * @param  string  $error
     * @return void
     */
    #[DataProvider('invalidInvocations')]
    public function testAnInvalidInvocationExitsTwo(array $parameters, string $error): void
    {
        $tester = new CommandTester(Artisan::all()[CheckConfigurationCommand::NAME]);

        self::assertSame(2, $tester->execute($parameters, ['capture_stderr_separately' => true]));
        self::assertSame('', $tester->getDisplay());
        self::assertSame("{$error}\n", $tester->getErrorOutput());
    }

    /**
     * A report that could not be completed exits 3, naming the part by the
     * exception's class alone, as text and as JSON.
     *
     * @return void
     */
    public function testAnIncompleteReportExitsThree(): void
    {
        $this->failToRead('authorization');

        [$code, $lines]    = self::text();
        [$jsonCode, $json] = self::report();

        self::assertSame(3, $code);
        self::assertSame(3, $jsonCode);
        self::assertSame('incomplete', $json['status']);
        self::assertSame('[check report.configuration] could not be completed (RuntimeException)', $lines[0]);
        self::assertSame('The check could not be completed.', $lines[\count($lines) - 1]);
        self::assertStringNotContainsString(self::SECRET, \implode("\n", $lines) . \json_encode($json));
    }

    /**
     * A refusal wins over a part of the report that could not be read: with
     * both, the command exits 1.
     *
     * @return void
     */
    public function testARefusalWinsOverAnIncompleteReport(): void
    {
        \config(['authorization.models.rol' => 'X']);

        $this->failToRead('authorization.usage.queue');

        [$code, $lines]    = self::text();
        [$jsonCode, $json] = self::report();
        $codes             = \array_column(self::listed($json, 'issues'), 'code');

        self::assertSame(1, $code);
        self::assertSame(1, $jsonCode);
        self::assertSame('refused', $json['status']);
        self::assertContains('internal', $codes);
        self::assertContains('unknown_key', $codes);
        self::assertContains('[check report.connection] could not be completed (RuntimeException)', $lines);
        self::assertStringNotContainsString(self::SECRET, \implode("\n", $lines) . \json_encode($json));
    }

    /**
     * A failure inside the command itself, here in writing the report, ends it
     * with exit code 3, or 1 for a refused configuration, naming the
     * exception's class alone, and is never thrown to a caller.
     *
     * @return void
     */
    public function testAFailureInsideTheCommandIsCaught(): void
    {
        $failures = [
            3 => [new \RuntimeException(self::SECRET), 'The check could not be completed (RuntimeException).'],
            1 => [new InvalidAuthorizationConfigException('authorization.models.role', self::SECRET), 'A check failed (' . InvalidAuthorizationConfigException::class . ').'],
        ];

        foreach ($failures as $expected => [$failure, $error]) {
            $output = self::failingOutput($failure);
            $code   = $this->kernel()->call(CheckConfigurationCommand::NAME, [], $output);
            $text   = $output->fetch();

            self::assertSame($expected, $code);
            self::assertStringContainsString($error, $text);
            self::assertStringNotContainsString(self::SECRET, $text);
        }
    }

    /**
     * Neither the text nor the JSON shows a credential, host or URL of the
     * connection, a value under an unknown key, a value whose setting is never
     * shown, or a configured value an issue is about.
     *
     * @return void
     */
    public function testNoSecretIsPrinted(): void
    {
        \config([
            'authorization.password'                => self::SECRET,
            'authorization.cache.password'          => self::SECRET,
            'authorization.cache.prefix'            => self::SECRET,
            'authorization.log_channel'             => 'p@ss ' . self::SECRET,
            'authorization.tables.roles'            => self::SECRET . ' x',
            'database.connections.testing.password' => self::SECRET,
            'database.connections.testing.username' => self::SECRET,
            'database.connections.testing.url'      => 'pgsql://user:' . self::SECRET . '@localhost/db',
            'database.connections.testing.host'     => self::SECRET . '.example.test',
        ]);

        [$code, $lines]    = self::text();
        [$jsonCode, $json] = self::report();
        $text              = \implode("\n", $lines);

        self::assertSame(1, $code);
        self::assertSame(1, $jsonCode);
        self::assertStringNotContainsString(self::SECRET, $text);
        self::assertStringNotContainsString(self::SECRET, (string) \json_encode($json));
        self::assertStringContainsString('[setting authorization.password] unknown key', $text);
        self::assertStringContainsString('[setting authorization.cache.password] unknown key', $text);
    }

    /**
     * A queue's URL set as the usage queue, which the check accepts, and a URL
     * set as the connection after boot are never printed: the connection
     * section withholds them as the settings section does.
     *
     * @return void
     */
    public function testNoUrlIsPrintedInTheConnection(): void
    {
        $queue = 'https://sqs.eu-west-1.amazonaws.com/123456789012/authz-usage';
        $url   = 'pgsql://user:' . self::SECRET . '@localhost/db';

        \config(['authorization.usage.queue' => $queue]);

        [$passed]       = self::text();
        [, $passedJson] = self::report();

        \config()->set('authorization.connection', $url);

        [$code, $lines]    = self::text();
        [$jsonCode, $json] = self::report();
        $printed           = \implode("\n", $lines) . (string) \json_encode($json) . (string) \json_encode($passedJson);
        $connection        = $passedJson['connection'] ?? null;

        self::assertSame(0, $passed);
        self::assertSame([1, 1], [$code, $jsonCode]);
        self::assertStringNotContainsString('123456789012', $printed);
        self::assertStringNotContainsString(self::SECRET, $printed);
        self::assertIsArray($connection);
        self::assertSame(['queue'], $connection['queue']['redacted'] ?? null);
        self::assertContains('[connection database] value not shown; chosen by authorization.connection; driver unknown; not connected to', $lines);
    }

    /**
     * The command runs no query, and builds and resolves no seam, even one that
     * explodes when built.
     *
     * @return void
     */
    public function testTheCommandQueriesAndBuildsNothing(): void
    {
        $app = $this->container();

        $app->bind(TenantTree::class, ExplodingTenantTree::class);

        $queries  = [];
        $resolved = $app->resolved(TenantTree::class);

        DB::listen(static function (object $query) use (&$queries): void {
            $queries[] = $query;
        });

        self::assertSame(0, self::text()[0]);
        self::assertSame(0, self::report()[0]);
        self::assertSame([], $queries);
        self::assertSame($resolved, $app->resolved(TenantTree::class));
        self::assertSame(0, Explosions::$count);
    }

    /**
     * A seam supplied by custom code is noted by where the code is written, its
     * class decided at first use, and every check still passes.
     *
     * @return void
     */
    public function testAnUnknownFactoryIsNotedWithoutFailing(): void
    {
        $line = __LINE__ + 1;
        $this->container()->bind(TenantTree::class, static fn (): TenantTree => new ExplodingTenantTree);

        [$code, $lines]    = self::text();
        [$jsonCode, $json] = self::report();

        self::assertSame(0, $code);
        self::assertSame(0, $jsonCode);
        self::assertSame(self::PASSED, $lines[\count($lines) - 1]);
        self::assertContains(
            '[seam TenantTree] bound after the package registered, over its binding; supplied by custom code (' . __FILE__ . ":{$line}); class decided at first use; transient",
            $lines,
        );
        self::assertSame(__FILE__ . ":{$line}", \array_column(self::listed($json, 'seams'), 'factory', 'contract')[TenantTree::class] ?? null);
        self::assertSame(0, Explosions::$count);
    }

    /**
     * A sibling's adapter, declared with the closure it bound, is shown by its
     * owner while it stands, and as overridden once a later binding replaces
     * it.
     *
     * @return void
     */
    public function testASiblingDeclarationIsShownByItsOwner(): void
    {
        $app     = $this->container();
        $binding = static fn (Application $app): mixed => $app->make('sibling.tenant_tree');

        $app->scoped('sibling.tenant_tree', ExplodingTenantTree::class);
        $app->bind(TenantTree::class, $binding);

        Declarations::of($app)->adapter(TenantTree::class, 'acme/sibling', ExplodingTenantTree::class, Lifetime::SCOPED, $binding);

        [$code, $lines] = self::text();
        [, $json]       = self::report();
        $declarations   = \array_column(self::listed($json, 'seams'), 'declaration', 'contract');

        self::assertSame(0, $code);
        self::assertContains('[seam TenantTree] declared by acme/sibling; ' . ExplodingTenantTree::class . '; scoped', $lines);
        self::assertIsArray($declarations[TenantTree::class] ?? null);
        self::assertSame('acme/sibling', $declarations[TenantTree::class]['owner'] ?? null);

        $app->singleton(TenantTree::class, ExplodingTenantTree::class);

        $overridden = '[seam TenantTree] bound after the package registered, over its binding; ' . ExplodingTenantTree::class . '; singleton; ';

        self::assertContains($overridden . 'declared by acme/sibling as ' . ExplodingTenantTree::class . ', but overridden later', self::text()[1]);
        self::assertSame(0, Explosions::$count);
    }

    /**
     * A command calling it in-process through the console kernel gets its exit
     * code, and its text on the output it gives, without a throw.
     *
     * @return void
     */
    public function testACallThroughTheKernelReturnsTheExitCodeAndText(): void
    {
        \config(['authorization.models.rol' => 'X']);

        $output = new BufferedOutput;
        $code   = $this->kernel()->call(CheckConfigurationCommand::NAME, [], $output);
        $text   = $output->fetch();

        self::assertSame(1, $code);
        self::assertStringStartsWith("[setting authorization.models.rol] unknown key; expected one of role, permission, policy\n", $text);
        self::assertStringEndsWith("A check failed.\n", $text);
    }

    /**
     * Return the secret nothing printed may show.
     *
     * @return string
     */
    public static function secret(): string
    {
        return self::SECRET;
    }

    /**
     * Return the console kernel.
     *
     * @return \Illuminate\Contracts\Console\Kernel
     */
    private function kernel(): Kernel
    {
        $kernel = $this->container()->make(Kernel::class);

        self::assertInstanceOf(Kernel::class, $kernel);

        return $kernel;
    }

    /**
     * Bind a configuration that throws, with the secret in its message, when
     * the key given is read.
     *
     * @param  string  $failing
     * @return void
     */
    private function failToRead(string $failing): void
    {
        $config = $this->container()->make('config');

        self::assertInstanceOf(Repository::class, $config);

        $this->container()->instance('config', new class ($config->all(), $failing) extends Repository {
            /**
             * Create a new configuration.
             *
             * @param  array<array-key, mixed>  $items
             * @param  string  $failing
             */
            public function __construct(

                // The configuration's items.
                array $items,

                /** The key whose read fails. */
                private readonly string $failing,
            ) {
                parent::__construct($items);
            }

            /**
             * Fail to read the failing key.
             *
             * @param  array<array-key, mixed>|string  $key
             * @param  mixed  $default
             * @return mixed
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function get(mixed $key, mixed $default = null): mixed
            {
                if ($key === $this->failing) {
                    throw new \RuntimeException('The configuration could not be read: ' . CheckConfigurationCommandTest::secret());
                }

                return parent::get($key, $default);
            }
        });
    }

    /**
     * Return an output that throws the failure when the report's sections are
     * written, and keeps what else is written.
     *
     * @param  \Throwable  $failure
     * @return \Symfony\Component\Console\Output\BufferedOutput
     */
    private static function failingOutput(\Throwable $failure): BufferedOutput
    {
        return new class ($failure) extends BufferedOutput {
            /**
             * Create a new output.
             *
             * @param  \Throwable  $failure
             */
            public function __construct(

                /** What writing the report's sections throws. */
                private readonly \Throwable $failure,
            ) {
                parent::__construct();
            }

            /**
             * Throw the failure when the report's sections are written, else
             * keep the message.
             *
             * @param  string  $message
             * @param  bool  $newline
             * @return void
             *
             * @throws \Throwable
             */
            #[\Override]
            protected function doWrite(string $message, bool $newline): void
            {
                if ($message === 'Settings') {
                    throw $this->failure;
                }

                parent::doWrite($message, $newline);
            }
        };
    }

    /**
     * Run the command as text, returning its exit code and each line it wrote
     * that is not empty.
     *
     * @return array{int, list<string>}
     */
    private static function text(): array
    {
        $code = Artisan::call(CheckConfigurationCommand::NAME);

        return [$code, \array_values(\array_filter(\explode("\n", Artisan::output()), static fn (string $line): bool => $line !== ''))];
    }

    /**
     * Run the command with `--format=json`, returning its exit code and the
     * JSON decoded.
     *
     * @return array{int, array<string, mixed>}
     */
    private static function report(): array
    {
        $code = Artisan::call(CheckConfigurationCommand::NAME, ['--format' => 'json']);

        return [$code, self::decoded(Artisan::output())];
    }

    /**
     * Return the lines of the text before its first section: its issues.
     *
     * @param  list<string>  $lines
     * @return list<string>
     */
    private static function issueLines(array $lines): array
    {
        return \array_slice($lines, 0, (int) \array_search('Settings', $lines, true));
    }

    /**
     * Return the lines that start with the prefix.
     *
     * @param  list<string>  $lines
     * @param  string  $prefix
     * @return list<string>
     */
    private static function starting(array $lines, string $prefix): array
    {
        return \array_values(\array_filter($lines, static fn (string $line): bool => \str_starts_with($line, $prefix)));
    }

    /**
     * Return the value, which must be a string.
     *
     * @param  mixed  $value
     * @return string
     */
    private static function string(mixed $value): string
    {
        self::assertIsString($value);

        return $value;
    }

    /**
     * Return a list of the JSON document, each entry an object.
     *
     * @param  array<string, mixed>  $json
     * @param  string  $key
     * @return list<array<string, mixed>>
     */
    private static function listed(array $json, string $key): array
    {
        $list = $json[$key] ?? null;

        self::assertIsList($list);

        /** @var list<array<string, mixed>> $list */
        return $list;
    }

    /**
     * Return the JSON document decoded.
     *
     * @param  string  $output
     * @return array<string, mixed>
     */
    private static function decoded(string $output): array
    {
        $document = \json_decode($output, true, 512, \JSON_THROW_ON_ERROR);

        self::assertIsArray($document);

        /** @var array<string, mixed> $document */
        return $document;
    }
}
