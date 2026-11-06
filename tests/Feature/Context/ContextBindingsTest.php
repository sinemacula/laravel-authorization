<?php

declare(strict_types = 1);

namespace Tests\Feature\Context;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Context\ClockEnvironmentContext;
use SineMacula\Laravel\Authorization\Context\ContextBindings;
use SineMacula\Laravel\Authorization\Context\GuardAuthenticationContext;
use SineMacula\Laravel\Authorization\Context\RoutedRequestContext;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\EnvironmentContext;
use SineMacula\Laravel\Authorization\Contracts\RequestContext;
use Tests\Feature\Stubs\PlanContextSource;
use Tests\Feature\Stubs\ReservedContextSource;
use Tests\TestCase;

/**
 * Feature tests for `ContextBindings`, which builds what the service provider
 * binds for the context of a check: the trusted sources' defaults, the context
 * key catalogue and the check context factory.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContextBindings::class)]
final class ContextBindingsTest extends TestCase
{
    /**
     * Each trusted source's contract defaults to Laravel's guard, routed
     * request and clock.
     *
     * @return void
     */
    public function testTheTrustedSourcesDefaultToLaravels(): void
    {
        self::assertSame([
            AuthenticationContext::class => GuardAuthenticationContext::class,
            RequestContext::class        => RoutedRequestContext::class,
            EnvironmentContext::class    => ClockEnvironmentContext::class,
        ], ContextBindings::DEFAULTS);
    }

    /**
     * The catalogue declares the package's keys and those of
     * `authorization.context.keys`.
     *
     * @return void
     */
    public function testTheCatalogueDeclaresTheConfiguredKeys(): void
    {
        $this->config()->set('authorization.context.keys', ['input' => ['post.status' => 'string'], 'plan' => ['tier' => 'string']]);

        $catalogue = ContextBindings::catalogue($this->application());

        self::assertSame(['authentication', 'environment', 'input', 'plan', 'request'], $catalogue->namespaces());
        self::assertTrue($catalogue->permits('input.post.status', 'eq'));
        self::assertTrue($catalogue->permits('plan.tier', 'like'));
    }

    /**
     * The factory holds the bound trusted sources and the sources of
     * `authorization.context.sources`, each resolved from the container, and
     * holds what the caller passes under `input` alone.
     *
     * @return void
     */
    public function testTheFactoryHoldsTheBoundAndConfiguredSources(): void
    {
        $source = new PlanContextSource('team');

        $this->application()->instance(PlanContextSource::class, $source);
        $this->application()->instance(RequestContext::class, new class implements RequestContext {
            /**
             * Return the request's values.
             *
             * @return array<string, mixed>
             */
            #[\Override]
            public function values(): array
            {
                return ['ip' => '10.0.0.9'];
            }
        });

        $this->config()->set('authorization.context.sources', [PlanContextSource::class]);

        $context = ContextBindings::factory($this->application())->make(['plan' => ['tier' => 'free'], 'request' => ['ip' => '10.0.0.1']]);

        self::assertSame([true, 'team'], $context->lookup('plan.tier'));
        self::assertSame([true, '10.0.0.9'], $context->lookup('request.ip'));
        self::assertSame([true, 'free'], $context->lookup('input.plan.tier'));
        self::assertSame([true, '10.0.0.1'], $context->lookup('input.request.ip'));
        self::assertSame([true, 'web'], $context->lookup('authentication.guard'));
        self::assertTrue($context->lookup('environment.time')[0]);
    }

    /**
     * A configured source claiming a reserved namespace is refused when the
     * factory is built.
     *
     * @return void
     */
    public function testTheFactoryRefusesASourceClaimingAReservedNamespace(): void
    {
        $this->config()->set('authorization.context.sources', [ReservedContextSource::class]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Context source ' . ReservedContextSource::class . ' cannot supply the namespace \'request\'');

        ContextBindings::factory($this->application());
    }

    /**
     * Return the configuration repository.
     *
     * @return \Illuminate\Contracts\Config\Repository
     */
    private function config(): ConfigRepository
    {
        return $this->application()->make(ConfigRepository::class);
    }

    /**
     * Return the application.
     *
     * @return \Illuminate\Foundation\Application
     *
     * @throws \LogicException
     */
    private function application(): Application
    {
        return $this->app ?? throw new \LogicException('The application has not been created.');
    }
}
