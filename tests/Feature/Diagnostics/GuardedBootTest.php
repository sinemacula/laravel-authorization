<?php

declare(strict_types = 1);

namespace Tests\Feature\Diagnostics;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Diagnostics\BindingRegistry;
use SineMacula\Laravel\Authorization\Diagnostics\BootCheck;
use SineMacula\Laravel\Authorization\Diagnostics\BootChecks;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue;
use SineMacula\Laravel\Authorization\Diagnostics\ContainerState;
use SineMacula\Laravel\Authorization\Diagnostics\DiagnosticMode;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\BootCheckOutcome;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\PackageStatus;
use SineMacula\Laravel\Authorization\Diagnostics\GuardedBoot;
use SineMacula\Laravel\Authorization\Diagnostics\PackageState;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Registrars\PendingRegistration;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Concerns\RefusesThePackage;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\Fixtures\Diagnostics\EarlyBootingProvider;
use Tests\Fixtures\Diagnostics\ExplodingTenantTree;
use Tests\Fixtures\Diagnostics\Explosions;
use Tests\Fixtures\Diagnostics\TenantAwareContextSource;
use Tests\Fixtures\Diagnostics\ThrowingContextSource;
use Tests\Fixtures\GrantHooks\RecordingGrantHook;
use Tests\Fixtures\GrantHooks\RefusingGrantHook;
use Tests\TestCase;

/**
 * Feature tests for validating the configuration as the application boots: for
 * diagnosis, every issue collected and every operation refused rather than the
 * boot throwing, the registration steps that may run code the configuration
 * names dropped when the configuration is refused; otherwise the first refusal
 * thrown as it always was, the package staying pending.
 *
 * The tests that boot the suite's application for diagnosis turn the switch on
 * and set the configuration they need before any provider registers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GuardedBoot::class)]
#[CoversClass(AuthorizationServiceProvider::class)]
final class GuardedBootTest extends TestCase
{
    use RefusesThePackage;

    /** @var array<string, array<string, mixed>> The configuration each test booting for diagnosis sets, by the test's name. */
    private const array DIAGNOSED = [
        'testABrokenConfigurationRefusesWithEveryIssueInsteadOfThrowing' => [
            'nonsense'    => true,
            'cache'       => ['ttl' => 0],
            'gate'        => ['enabled' => 'yes'],
            'tenant_tree' => ExplodingTenantTree::class,
            'grant_hooks' => [RecordingGrantHook::class],
            'usage'       => ['enabled' => 'yes'],
        ],
        'testAnUnforeseenFailureAloneRefusesAsIncomplete' => [
            'context' => ['sources' => [ThrowingContextSource::class]],
        ],
        'testASoundConfigurationBootsAsUsualForDiagnosis' => [
            'context' => ['sources' => [TenantAwareContextSource::class]],
            'usage'   => ['enabled' => true],
        ],
        'testAStepThatThrowsWhileDiagnosingRefusesAsIncomplete' => [
            'tenant_tree' => StubTenantTree::class,
            'grant_hooks' => [RecordingGrantHook::class],
        ],
    ];

    /** @var array<string, array<string, mixed>> The configuration each test booting outside diagnosis sets, by the test's name. */
    private const array CONFIGURED = [
        'testOutsideDiagnosisTheStepsRunAndThePackageIsHealthy' => [
            'tenant_tree' => StubTenantTree::class,
            'context'     => ['sources' => [TenantAwareContextSource::class]],
        ],
        'testTheStepsRunBeforeAnyProviderBoots' => [
            'tenant_tree' => StubTenantTree::class,
        ],
    ];

    /** @var \SineMacula\Laravel\Authorization\Contracts\GrantHook|null The grant hook held before the package registers, when a test holds one. */
    private ?GrantHook $held = null;

    /**
     * Forget the explosions counted.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Explosions::$count = 0;

        parent::tearDown();
    }

    /**
     * A refused configuration does not stop the application booting for
     * diagnosis: every issue is kept, the package refuses every operation,
     * naming the first refusal, `authorization:check` alone among its commands
     * is registered, and none of the registration steps ran, nor are any left
     * to run: the class configured was not bound or built, and the grant hook
     * held was not wrapped; the manager and the resolved tenant refuse as the
     * container builds them.
     *
     * @return void
     */
    public function testABrokenConfigurationRefusesWithEveryIssueInsteadOfThrowing(): void
    {
        $app   = $this->container();
        $state = PackageState::of($app);

        self::assertNotNull($state);
        self::assertSame(PackageStatus::REFUSING, $state->status());
        self::assertTrue($state->isDiagnostic());

        $paths = \array_map(static fn (ConfigIssue $issue): string => $issue->path, $state->findings()->issues ?? []);

        self::assertContains('authorization.nonsense', $paths);
        self::assertContains('authorization.cache.ttl', $paths);
        self::assertContains('authorization.gate.enabled', $paths);
        self::assertContains('authorization.usage.enabled', $paths);
        self::assertSame($paths[0], $state->refusal()->getConfigKey());
        self::assertSame(\array_fill(0, 5, BootCheckOutcome::NOT_RUN), \array_map(static fn (BootCheck $check): BootCheckOutcome => $check->outcome, $state->bootChecks()));

        self::assertSame(0, Explosions::$count);
        self::assertFalse(BindingRegistry::of($app)->get(TenantTree::class)?->configured);
        self::assertSame($this->held, ContainerState::instance($app, GrantHook::class));
        self::assertFalse(PendingRegistration::find($app)?->isPending());

        $app->forgetInstance(ResolvedTenant::class);
        $app->forgetInstance('authorization');

        foreach (['authorization', ResolvedTenant::class] as $built) {
            $refusal = self::packageRefusalOf(static fn () => $app->make($built));

            self::assertSame([$state->refusal()->getConfigKey(), '{closure}'], [$refusal->getConfigKey(), self::guardedBy($refusal)], $built);
        }

        $commands = \array_values(\array_filter(\array_keys(Artisan::all()), static fn (string $name): bool => \str_starts_with($name, 'authorization:')));

        self::assertSame(['authorization:check'], $commands);
    }

    /**
     * A check that builds what the configuration names and fails in a way the
     * package did not foresee refuses every operation, under the `internal`
     * code with a fixed reason, never what was thrown, though nothing is
     * refused; its outcome keeps the exception's class.
     *
     * @return void
     */
    public function testAnUnforeseenFailureAloneRefusesAsIncomplete(): void
    {
        $state = PackageState::of($this->container());

        self::assertNotNull($state);
        self::assertSame(PackageStatus::REFUSING, $state->status());
        self::assertTrue($state->findings()?->isIncomplete());
        self::assertFalse($state->findings()->isRefused());

        $refusal = $state->refusal();

        self::assertSame(IssueCode::INTERNAL, $refusal->getIssue());
        self::assertSame(BootChecks::CONTEXT, $refusal->getConfigKey());
        self::assertStringNotContainsString(ThrowingContextSource::MESSAGE, $refusal->getMessage());

        $context = $state->bootChecks()[0];

        self::assertSame([BootChecks::CONTEXT, BootCheckOutcome::FAILED, \RuntimeException::class], [$context->path, $context->outcome, $context->exception]);
        self::assertArrayNotHasKey('authorization:sync', Artisan::all());
    }

    /**
     * A sound configuration boots for diagnosis as it boots otherwise: the
     * package is healthy, each check that builds what the configuration names
     * ran or had nothing to build, a context source handed the resolved tenant
     * and the usage store as it is built included, and every command, operation
     * and the usage tracking are there.
     *
     * @return void
     */
    public function testASoundConfigurationBootsAsUsualForDiagnosis(): void
    {
        $app   = $this->container();
        $state = PackageState::of($app);

        self::assertNotNull($state);
        self::assertSame(PackageStatus::HEALTHY, $state->status());
        self::assertTrue($state->isDiagnostic());
        self::assertSame([], $state->findings()->issues ?? null);
        self::assertSame(BootCheckOutcome::PASSED, $state->bootChecks()[0]->outcome);
        self::assertInstanceOf(AuthorizationManager::class, $app->make('authorization'));
        self::assertArrayHasKey('authorization:sync', Artisan::all());
        self::assertArrayHasKey('authorization:check', Artisan::all());
        self::assertTrue($app['events']->hasListeners(JobProcessed::class));
    }

    /**
     * A registration step that throws while diagnosing, here a callback
     * watching the contract the class configured is bound to, refuses every
     * operation as incomplete instead of stopping the boot.
     *
     * @return void
     */
    public function testAStepThatThrowsWhileDiagnosingRefusesAsIncomplete(): void
    {
        $state = PackageState::of($this->container());

        self::assertNotNull($state);
        self::assertSame(PackageStatus::REFUSING, $state->status());

        $issues = $state->findings()->issues ?? [];

        self::assertCount(1, $issues);
        self::assertSame(['authorization', IssueCode::INTERNAL, \UnexpectedValueException::class], [$issues[0]->path, $issues[0]->code, $issues[0]->exception]);
        self::assertSame(PackageStatus::REFUSING, $state->status());
        self::assertFalse(PendingRegistration::find($this->container())?->isPending());
    }

    /**
     * Diagnosing a configuration fixed since it was refused sets the package
     * back to pending first, so it is healthy once the checks pass.
     *
     * @return void
     */
    public function testARefusedConfigurationFixedBootsHealthyForDiagnosis(): void
    {
        $app = $this->container();
        $ttl = $app['config']->get('authorization.cache.ttl');

        DiagnosticMode::enable($app);

        $app['config']->set('authorization.cache.ttl', 0);

        $state = PackageState::start($app);

        (new AuthorizationServiceProvider($app))->boot();

        self::assertSame(PackageStatus::REFUSING, $state->status());

        $app['config']->set('authorization.cache.ttl', $ttl);

        PackageState::start($app);
        (new AuthorizationServiceProvider($app))->boot();

        self::assertSame(PackageStatus::HEALTHY, $state->status());
    }

    /**
     * Outside diagnosis the registration steps run as the application boots,
     * the class configured bound, and the package is healthy, every command
     * registered, though a context source is handed the resolved tenant and the
     * usage store as the validation builds it.
     *
     * @return void
     */
    public function testOutsideDiagnosisTheStepsRunAndThePackageIsHealthy(): void
    {
        $app = $this->container();

        self::assertSame(PackageStatus::HEALTHY, PackageState::of($app)?->status());
        self::assertFalse(PackageState::of($app)->isDiagnostic());
        self::assertTrue(BindingRegistry::of($app)->get(TenantTree::class)?->configured);
        self::assertInstanceOf(StubTenantTree::class, $app->make(TenantTree::class));
        self::assertTrue((new GuardedBoot($app))->validate());
        self::assertArrayHasKey('authorization:sync', Artisan::all());
    }

    /**
     * The registration steps run as the application boots, before any provider
     * boots: one booting before the package's resolves the class configured,
     * with how the package boots decided, while a check it asks of the package
     * refuses, the configuration not validated yet.
     *
     * @return void
     */
    public function testTheStepsRunBeforeAnyProviderBoots(): void
    {
        $app   = $this->container();
        $check = $app->make(EarlyBootingProvider::CHECK);

        self::assertSame(StubTenantTree::class, $app->make(EarlyBootingProvider::TENANT_TREE));
        self::assertTrue($app->make(EarlyBootingProvider::DECIDED));
        self::assertInstanceOf(InvalidAuthorizationConfigException::class, $check);
        self::assertSame(IssueCode::INTERNAL, $check->getIssue());
        self::assertSame(PackageStatus::HEALTHY, PackageState::of($app)?->status());
    }

    /**
     * Registering on an application not booted yet leaves the steps to its
     * boot; registering on one already booted runs them at once.
     *
     * @return void
     */
    public function testTheStepsWaitForTheBootUnlessTheApplicationBooted(): void
    {
        $config = ['authorization' => ['tenant_tree' => StubTenantTree::class]];

        try {
            $app = new Application(\dirname(__DIR__, 3));

            $app->instance('config', new Repository($config));

            (new AuthorizationServiceProvider($app))->register();

            self::assertFalse(PackageState::of($app)?->isDecided());
            self::assertFalse(BindingRegistry::of($app)->get(TenantTree::class)?->configured);

            $app->boot();

            self::assertTrue(PackageState::of($app)?->isDecided());
            self::assertTrue(BindingRegistry::of($app)->get(TenantTree::class)?->configured);

            $booted = new Application(\dirname(__DIR__, 3));

            $booted->instance('config', new Repository($config));
            $booted->boot();

            (new AuthorizationServiceProvider($booted))->register();

            self::assertTrue(PackageState::of($booted)?->isDecided());
            self::assertTrue(BindingRegistry::of($booted)->get(TenantTree::class)?->configured);
        } finally {
            Container::setInstance($this->container());
        }
    }

    /**
     * Booting again for diagnosis, on a sound configuration or a refused one,
     * runs no query.
     *
     * @return void
     */
    public function testBootingForDiagnosisRunsNoQuery(): void
    {
        $app     = $this->container();
        $queries = [];

        Event::listen(QueryExecuted::class, static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        DiagnosticMode::enable($app);

        $state = PackageState::start($app);

        (new AuthorizationServiceProvider($app))->boot();

        self::assertSame(PackageStatus::HEALTHY, $state->status());

        $app['config']->set('authorization.cache.ttl', 0);

        PackageState::start($app);
        (new AuthorizationServiceProvider($app))->boot();

        self::assertSame(PackageStatus::REFUSING, $state->status());
        self::assertSame([], $queries);
    }

    /**
     * Outside diagnosis the boot throws the first refusal, as the validation
     * always has, and the package stays pending, so an application that goes on
     * serving after its boot threw refuses every operation rather than running
     * unvalidated; booting the provider again throws again.
     *
     * @return void
     */
    public function testOutsideDiagnosisTheBootThrowsAndThePackageStaysPending(): void
    {
        $app = new Application(\dirname(__DIR__, 3));

        try {
            $app->instance('config', new Repository(['authorization' => ['nonsense' => true, 'cache' => ['ttl' => 0]]]));

            (new AuthorizationServiceProvider($app))->register();

            $app->boot();

            $expected = self::refusalOf(static fn () => ConfigValidator::validate($app['config']->get('authorization'), $app));
            $thrown   = self::refusalOf(static fn () => (new AuthorizationServiceProvider($app))->boot());

            self::assertSame($expected->getMessage(), $thrown->getMessage());
            self::assertSame(PackageStatus::PENDING, PackageState::of($app)?->status());
            self::assertSame($expected->getMessage(), self::refusalOf(static fn () => (new AuthorizationServiceProvider($app))->boot())->getMessage());

            $pending = self::refusalOf(static fn () => PackageState::guard($app));

            self::assertSame(['authorization', IssueCode::INTERNAL], [$pending->getConfigKey(), $pending->getIssue()]);
        } finally {
            Container::setInstance($this->container());
        }
    }

    /**
     * Validating again, as when the package registers and boots again, sets a
     * healthy package back to pending first, so a validation that throws leaves
     * it refusing.
     *
     * @return void
     */
    public function testValidatingAgainSetsThePackagePendingFirst(): void
    {
        $app   = $this->container();
        $state = PackageState::of($app);

        self::assertNotNull($state);
        self::assertSame(PackageStatus::HEALTHY, $state->status());

        $app['config']->set('authorization.cache.ttl', 0);

        self::refusalOf(static fn () => (new AuthorizationServiceProvider($app))->boot());

        self::assertSame(PackageStatus::PENDING, $state->status());
    }

    /**
     * Without the package registered, validating throws as it always did and
     * leaves nothing to stand.
     *
     * @return void
     */
    public function testWithoutThePackageRegisteredTheValidationStillRuns(): void
    {
        $app = new Application(\dirname(__DIR__, 3));

        try {
            $app->instance('config', new Repository(['authorization' => ['nonsense' => true]]));

            self::assertSame('authorization.nonsense', self::refusalOf(static fn () => (new GuardedBoot($app))->validate())->getConfigKey());
            self::assertNull(PackageState::of($app));
        } finally {
            Container::setInstance($this->container());
        }
    }

    /**
     * Turn the switch on and set the configuration of the test booting for
     * diagnosis, and what it holds before the package registers, before any
     * provider registers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        $authorization = self::DIAGNOSED[$this->name()] ?? self::CONFIGURED[$this->name()] ?? null;

        if ($authorization === null) {
            return;
        }

        if (isset(self::DIAGNOSED[$this->name()])) {
            DiagnosticMode::enable($app);
        }

        /** @var \Illuminate\Config\Repository $config */
        $config = $app['config'];

        foreach ($authorization as $key => $value) {
            $config->set("authorization.{$key}", $value);
        }

        $this->holdBefore($app);
    }

    /**
     * Register a provider booting before the package's for the test that needs
     * one, then the package's.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        $providers = parent::getPackageProviders($app);

        return $this->name() === 'testTheStepsRunBeforeAnyProviderBoots' ? [EarlyBootingProvider::class, ...$providers] : $providers;
    }

    /**
     * Have the application hold, before the package registers, what the test
     * needs held: for the refused configuration a grant hook; for the step that
     * throws a tenant tree resolved and watched by a callback that throws.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    private function holdBefore(Application $app): void
    {
        if ($this->name() === 'testABrokenConfigurationRefusesWithEveryIssueInsteadOfThrowing') {
            $this->held = new RefusingGrantHook;

            $app->instance(GrantHook::class, $this->held);
        }

        if ($this->name() !== 'testAStepThatThrowsWhileDiagnosingRefusesAsIncomplete') {
            return;
        }

        $app->bind(TenantTree::class, static fn (): TenantTree => new StubTenantTree);
        $app->rebinding(TenantTree::class, static function (): never {
            throw new \UnexpectedValueException('a watcher failed');
        });
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
}
