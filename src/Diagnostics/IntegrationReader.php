<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Query\Grammars\Grammar;
use Illuminate\Routing\Router;
use Illuminate\View\Compilers\BladeCompiler;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Config\SwitchConfigValidator;
use SineMacula\Laravel\Authorization\Query\AuthorizedQuery;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\QueryScopeRegistrar;
use SineMacula\Laravel\Authorization\Support\DeclaredAbilities;

/**
 * Read how the package is wired into the application: the Gate hook, the Blade
 * directives, the query macros and the route middleware aliases.
 *
 * Only what the container already holds is read: the Blade compiler and the
 * router are read when they were built already, and are otherwise shown as
 * `unavailable`, never built for the report.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IntegrationReader
{
    /**
     * Create a new reader.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The container the package is wired into. */
        private Container $container,

        /** The application's configuration. */
        private Repository $config,
    ) {}

    /**
     * Return each integration, by name, with its state and, where it helps,
     * what it is wired to.
     *
     * @return list<array{name: string, state: string, detail: string|null}>
     */
    public function read(): array
    {
        return [
            ['name' => 'gate', 'state' => $this->gate(), 'detail' => null],
            ['name' => 'blade_directives', 'state' => $this->blade(), 'detail' => null],
            ['name' => 'query_macro', 'state' => Builder::hasGlobalMacro(QueryScopeRegistrar::MACRO) ? 'registered' : 'not_registered', 'detail' => null],
            ['name' => 'grammar_macro', 'state' => Grammar::hasMacro(AuthorizedQuery::GRAMMAR_MACRO) ? 'registered' : 'not_registered', 'detail' => null],
            ...$this->middleware(),
        ];
    }

    /**
     * Return the Gate hook's state: `enabled` when the switch is on and the
     * hook's abilities are bound, `disabled` when the switch is off, else
     * `not_registered`, or `unknown` when the switch cannot be read.
     *
     * @return string
     */
    private function gate(): string
    {
        try {
            $enabled = SwitchConfigValidator::isEnabled('gate', $this->config);
        } catch (\Throwable) {
            return 'unknown';
        }

        return match (true) {
            !$enabled                                                                     => 'disabled',
            ContainerState::concrete($this->container, DeclaredAbilities::class) !== null => 'enabled',
            default                                                                       => 'not_registered',
        };
    }

    /**
     * Return whether every Blade directive is registered, on the compiler the
     * container holds.
     *
     * @return string
     */
    private function blade(): string
    {
        $compiler = ContainerState::instance($this->container, 'blade.compiler');

        if (!$compiler instanceof BladeCompiler) {
            return 'unavailable';
        }

        $missing = \array_diff(BladeDirectiveRegistrar::DIRECTIVES, \array_keys($compiler->getCustomDirectives()));

        return match (\count($missing)) {
            0                                           => 'registered',
            \count(BladeDirectiveRegistrar::DIRECTIVES) => 'not_registered',
            default                                     => 'partly_registered',
        };
    }

    /**
     * Return each route middleware alias the package registers, on the router
     * the container holds: `registered` when it names the package's middleware,
     * `other` when the application aliased another, with that class, else
     * `not_registered`.
     *
     * @return list<array{name: string, state: string, detail: string|null}>
     */
    private function middleware(): array
    {
        $router  = ContainerState::instance($this->container, 'router');
        $aliases = $router instanceof Router ? $router->getMiddleware() : null;
        $rows    = [];

        foreach (AuthorizationServiceProvider::MIDDLEWARE as $alias => $middleware) {
            $bound = $aliases[$alias] ?? null;

            $rows[] = [
                'name'  => "middleware.{$alias}",
                'state' => match (true) {
                    $aliases === null        => 'unavailable',
                    $bound   === null        => 'not_registered',
                    $bound   === $middleware => 'registered',
                    default                  => 'other',
                },
                'detail' => \is_string($bound) && $bound !== $middleware ? $bound : null,
            ];
        }

        return $rows;
    }
}
