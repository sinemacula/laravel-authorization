<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime;

/**
 * Where a sibling package declares the adapters it binds to the package's
 * contracts, so `authorization:check` names them instead of reporting custom
 * code whose class is decided at first use.
 *
 * A sibling declares in its `register()`, after binding the contract:
 *
 * ```php
 *     $binding = static fn (Application $app): TenantTree => $app->make('acme.tenants');
 *
 *     $this->app->bind(TenantTree::class, $binding);
 *
 *     Declarations::of($this->app)
 *         ->adapter(TenantTree::class, 'acme/tenants', AcmeTenantTree::class, Lifetime::SCOPED, $binding);
 * ```
 *
 * or, for a binding that decides among several classes as it is resolved,
 * `factory()` with the classes it may build and when it decides. Naming the
 * closure bound lets the report tell the sibling's adapter, still bound, from a
 * binding made later over it; a declaration naming none is shown beside
 * whatever is bound.
 *
 * A sibling whose command runs `authorization:check` in the same process, as a
 * check of its own that composes the package's, declares that command's name
 * with `composingCommand()` in its `register()`, so the console running it
 * boots the package for diagnosis, as it does for `authorization:check` (see
 * `DiagnosticMode`). It is read as the application boots, after every provider
 * registered, so a sibling registered after the package counts; a deferred
 * provider registers too late for it to count.
 *
 * Declarations are data only: nothing is loaded or built, and each application
 * holds its own, as an instance of its container.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class Declarations
{
    /** @var array<string, \SineMacula\Laravel\Authorization\Diagnostics\Declaration> Each declaration, keyed by its contract. */
    private array $declarations = [];

    /** @var array<string, true> The name of each command declared to run `authorization:check` in the same process. */
    private array $composingCommands = [];

    /**
     * Return the declarations the container holds, holding new ones first when
     * it holds none, whichever package registers first.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return self
     */
    public static function of(Container $container): self
    {
        $declarations = ContainerState::instance($container, self::class);

        if ($declarations instanceof self) {
            return $declarations;
        }

        $declarations = new self;

        $container->instance(self::class, $declarations);

        return $declarations;
    }

    /**
     * Declare the adapter a sibling binds to the contract: its class, how long
     * it lives and, optionally, the closure bound.
     *
     * @param  string  $contract
     * @param  string  $owner
     * @param  string  $class
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime  $lifetime
     * @param  (\Closure(never): mixed)|null  $binding
     * @return void
     */
    public function adapter(string $contract, string $owner, string $class, Lifetime $lifetime, ?\Closure $binding = null): void
    {
        $this->declarations[$contract] = new Declaration($contract, $owner, [$class], null, $lifetime, $binding);
    }

    /**
     * Declare a factory a sibling binds to the contract: the classes it may
     * build, when it decides among them, how long what it builds lives and,
     * optionally, the closure bound.
     *
     * @param  string  $contract
     * @param  string  $owner
     * @param  list<string>  $classes
     * @param  string  $decides
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime  $lifetime
     * @param  (\Closure(never): mixed)|null  $binding
     * @return void
     */
    public function factory(string $contract, string $owner, array $classes, string $decides, Lifetime $lifetime, ?\Closure $binding = null): void
    {
        $this->declarations[$contract] = new Declaration($contract, $owner, $classes, $decides, $lifetime, $binding);
    }

    /**
     * Return the declaration of the contract, or null when none was made.
     *
     * @param  string  $contract
     * @return \SineMacula\Laravel\Authorization\Diagnostics\Declaration|null
     */
    public function for(string $contract): ?Declaration
    {
        return $this->declarations[$contract] ?? null;
    }

    /**
     * Return every declaration, keyed by its contract, in the order made.
     *
     * @return array<string, \SineMacula\Laravel\Authorization\Diagnostics\Declaration>
     */
    public function all(): array
    {
        return $this->declarations;
    }

    /**
     * Declare a command that runs `authorization:check` in the same process, by
     * the name the console runs it under.
     *
     * @param  string  $name
     * @return void
     */
    public function composingCommand(string $name): void
    {
        $this->composingCommands[$name] = true;
    }

    /**
     * Determine whether the command of the name was declared to run
     * `authorization:check` in the same process.
     *
     * @param  string  $name
     * @return bool
     */
    public function isComposing(string $name): bool
    {
        return isset($this->composingCommands[$name]);
    }

    /**
     * Return the name of every command declared to run `authorization:check` in
     * the same process, in the order declared.
     *
     * @return list<string>
     */
    public function composingCommands(): array
    {
        return \array_map(\strval(...), \array_keys($this->composingCommands));
    }
}
