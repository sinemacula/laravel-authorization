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
