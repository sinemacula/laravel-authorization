<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Context;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\ContextSource;
use SineMacula\Laravel\Authorization\Contracts\EnvironmentContext;
use SineMacula\Laravel\Authorization\Contracts\RequestContext;

/**
 * Builds what the service provider binds for the context of a check (N25, N26):
 * the trusted sources' defaults, the context key catalogue and the check
 * context factory.
 *
 * The key catalogue is built from `authorization.context.keys` and the factory
 * from the bound trusted sources and the sources
 * `authorization.context.sources` lists, each resolved from the container. Both
 * read a configuration the service provider validated at boot.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ContextBindings
{
    /** @var array<class-string, class-string> The default of each trusted source's contract, which an application replaces by binding the contract. */
    public const array DEFAULTS = [
        AuthenticationContext::class => GuardAuthenticationContext::class,
        RequestContext::class        => RoutedRequestContext::class,
        EnvironmentContext::class    => ClockEnvironmentContext::class,
    ];

    /**
     * Build the context key catalogue from the package's keys, those of
     * `authorization.context.keys` and those the attribute providers declare,
     * with the namespaces the bound authentication context contributes, whose
     * assurance keys it never lets a condition test.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return \SineMacula\Laravel\Authorization\Context\DeclaredContextKeyCatalogue
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public static function catalogue(Application $app): DeclaredContextKeyCatalogue
    {
        /** @var array<string, array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>> $keys */
        $keys = (array) $app['config']->get('authorization.context.keys', []);

        $namespaces = $app->bound(AuthenticationContext::class) ? $app->make(AuthenticationContext::class)->namespaces() : [];

        return new DeclaredContextKeyCatalogue($keys, AttributeProviders::fromConfig($app)->declarations(), $namespaces);
    }

    /**
     * Build the check context factory from the bound trusted sources, the
     * sources of `authorization.context.sources`, the attribute providers of
     * `authorization.attributes` and the bound authentication requirement
     * checker, each resolved from the container.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return \SineMacula\Laravel\Authorization\Context\CheckContextFactory
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public static function factory(Application $app): CheckContextFactory
    {
        /** @var list<class-string<\SineMacula\Laravel\Authorization\Contracts\ContextSource>> $classes */
        $classes = (array) $app['config']->get('authorization.context.sources', []);

        return new CheckContextFactory(
            authentication: $app->make(AuthenticationContext::class),
            request: $app->make(RequestContext::class),
            environment: $app->make(EnvironmentContext::class),
            sources: \array_map(static fn (string $class): ContextSource => $app->make($class), $classes),
            attributes: AttributeProviders::fromConfig($app),
            requirements: $app->make(AuthenticationRequirementChecker::class),
        );
    }
}
