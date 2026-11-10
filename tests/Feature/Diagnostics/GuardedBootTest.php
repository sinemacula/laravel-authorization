<?php

declare(strict_types = 1);

namespace Tests\Feature\Diagnostics;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
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
use Tests\Feature\Stubs\StubTenantTree;
use Tests\Fixtures\Diagnostics\ExplodingTenantTree;
use Tests\Fixtures\Diagnostics\Explosions;
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
    /** @var array<string, array<string, mixed>> The configuration each test booting for diagnosis sets, by the test's name. */
    private const array DIAGNOSED = [
        'testABrokenConfigurationRefusesWithEveryIssueInsteadOfThrowing' => [
            'nonsense'    => true,
            'cache'       => ['ttl' => 0],
            'gate'        => ['enabled' => 'yes'],
            'tenant_tree' => ExplodingTenantTree::class,
            'grant_hooks' => [RecordingGrantHook::class],
        ],
        'testAnUnforeseenFailureAloneRefusesAsIncomplete' => [
            'context' => ['sources' => [ThrowingContextSource::class]],
        ],
        'testASoundConfigurationBootsAsUsualForDiagnosis'       => [],
        'testAStepThatThrowsWhileDiagnosingRefusesAsIncomplete' => [
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
     * is registered, and none of the registration steps ran: the class
     * configured was not bound or built, and the grant hook held was not
     * wrapped.
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
        self::assertSame($paths[0], $state->refusal()->getConfigKey());
        self::assertSame(\array_fill(0, 5, BootCheckOutcome::NOT_RUN), \array_map(static fn (BootCheck $check): BootCheckOutcome => $check->outcome, $state->bootChecks()));

        self::assertSame(0, Explosions::$count);
        self::assertFalse(BindingRegistry::of($app)->get(TenantTree::class)?->configured);
        self::assertSame($this->held, ContainerState::instance($app, GrantHook::class));

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
    }

    /**
     * A sound configuration boots for diagnosis as it boots otherwise: the
     * package is healthy, each check that builds what the configuration names
     * ran or had nothing to build, and every command and operation is there.
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

        $authorization = self::DIAGNOSED[$this->name()] ?? null;

        if ($authorization === null) {
            return;
        }

        DiagnosticMode::enable($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app['config'];

        foreach ($authorization as $key => $value) {
            $config->set("authorization.{$key}", $value);
        }

        $this->holdBefore($app);
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
