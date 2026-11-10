<?php

declare(strict_types = 1);

namespace Tests\Feature\Registrars;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Registrars\SeamBindings;
use Tests\Feature\Stubs\ContributingAuthenticationContext;
use Tests\Feature\Stubs\SiblingSeamsProvider;
use Tests\Feature\Stubs\StubRequirementChecker;
use Tests\Feature\Stubs\StubSessionPolicySource;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\SwitchableSubjectResolver;
use Tests\TestCase;

/**
 * Feature tests for a sibling package that binds the seams over the package's
 * defaults in its own `register()`, as `laravel-iam` does, registered before
 * the package or after it in the order the application registers its package
 * providers.
 *
 * The sibling binds a seam only while it is unbound or holds the package's own
 * default, which it tells from the application's binding by the class that
 * declares the closure the seam is bound to: the package's service provider.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SeamBindings::class)]
#[CoversClass(AuthorizationServiceProvider::class)]
final class SiblingSeamsTest extends TestCase
{
    /**
     * Provide the order the application registers the package providers in.
     *
     * @return iterable<string, array{list<class-string<\Illuminate\Support\ServiceProvider>>}>
     */
    public static function orderProvider(): iterable
    {
        yield 'the sibling registers before the package' => [[SiblingSeamsProvider::class, AuthorizationServiceProvider::class]];
        yield 'the sibling registers after the package' => [[AuthorizationServiceProvider::class, SiblingSeamsProvider::class]];
    }

    /**
     * Each seam resolves to the sibling's binding, whichever registers first.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     */
    #[DataProvider('orderProvider')]
    public function testTheSiblingsBindingsStandInEitherOrder(array $providers): void
    {
        $this->assertRegisteredInOrder($providers);

        self::assertInstanceOf(StubSubjectResolver::class, $this->app?->make(SubjectResolver::class));
        self::assertInstanceOf(StubRequirementChecker::class, $this->app->make(AuthenticationRequirementChecker::class));
        self::assertInstanceOf(StubSessionPolicySource::class, $this->app->make(SessionPolicySource::class));
        self::assertInstanceOf(ContributingAuthenticationContext::class, $this->app->make(AuthenticationContext::class));
    }

    /**
     * The key the sibling declares as the catalogue is built is declared,
     * whichever registers first.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     */
    #[DataProvider('orderProvider')]
    public function testTheKeyTheSiblingDeclaresIsDeclaredInEitherOrder(array $providers): void
    {
        $this->assertRegisteredInOrder($providers);

        self::assertNotNull($this->app?->make(ContextKeyCatalogue::class)->find(SiblingSeamsProvider::KEY));
    }

    /**
     * A class the application names in the configuration stands over the
     * sibling's adapter whichever registers first (N106): the package binds it
     * through a closure its provider does not declare, so the sibling keeps it,
     * and isPackageDefault() says it is not the package's default.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     */
    #[DataProvider('orderProvider')]
    public function testAConfiguredClassStandsOverTheSiblingInEitherOrder(array $providers): void
    {
        $this->assertRegisteredInOrder($providers);

        self::assertInstanceOf(SwitchableSubjectResolver::class, $this->app?->make(SubjectResolver::class));
        self::assertFalse(AuthorizationServiceProvider::isPackageDefault($this->app, SubjectResolver::class));
    }

    /**
     * Name a subject resolver in the configuration for the test that asks the
     * application's choice to stand, before any provider registers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        if ($this->name() !== 'testAConfiguredClassStandsOverTheSiblingInEitherOrder') {
            return;
        }

        /** @var \Illuminate\Config\Repository $config */
        $config = $app['config'];

        $config->set('authorization.subject_resolver', SwitchableSubjectResolver::class);
    }

    /**
     * Register the package providers in the order the test is given.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        /** @var array<int, class-string<\Illuminate\Support\ServiceProvider>> */
        return $this->providedData()[0];
    }

    /**
     * Assert the application registered the providers in the order given.
     *
     * @param  list<class-string<\Illuminate\Support\ServiceProvider>>  $providers
     * @return void
     */
    private function assertRegisteredInOrder(array $providers): void
    {
        $registered = \array_keys($this->app?->getLoadedProviders() ?? []);

        self::assertSame($providers, \array_values(\array_intersect($registered, $providers)));
    }
}
