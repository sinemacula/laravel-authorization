<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

use Illuminate\Container\Container as BaseContainer;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\PackageStatus;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Where the package stands in the application that registered it, which every
 * operation the package offers consults before it runs (N124).
 *
 * The package's service provider holds one, as an instance of the container,
 * from the start of its `register()`: pending until the configuration is
 * validated and the package set up, then healthy, or refusing with what the
 * diagnostic boot found. It is changed in place, never replaced, so an object
 * that holds it, and a container cloned from the application, as an Octane
 * sandbox is, see each change.
 *
 * A container that holds none never registered the package: nothing refuses
 * there, so a class built directly, as a test or an embedding application may
 * build one, runs as it always has. A container whose provider registered but
 * did not finish validating refuses every operation, so an application whose
 * boot threw, and which goes on to serve another request or command without
 * booting again, runs nothing unvalidated, and so does a provider that boots
 * before the package's own and asks it to decide.
 *
 * Building is told apart from running: what the container builds for an
 * operation (the manager, the resolved tenant, the usage recorder and store),
 * and what the boot's own validation builds and reads (the context sources, the
 * action catalogue and the permissions declared), refuse only while the package
 * refuses, never while it is pending, so a valid configuration whose context
 * source is handed one of them as it is built boots healthy (see
 * `guardBuild()`).
 *
 * The operations that refuse, each before it resolves a seam, reads a cache or
 * returns early, are exactly these:
 *
 * - every decision, listing, explanation and preview of the manager and the
 *   facade, and every scoped manager it builds, `for()`, `forUser()`,
 *   `withPolicies()`, `capped()` and `previewFor()` among them; the manager is
 *   handed the state as it is built, so one obtained earlier refuses too;
 * - the route middleware, the Blade helpers and directives, `whereAuthorized()`
 *   and `AuthorizedScope`;
 * - the model traits' decisions: `hasPermission()`, `getPermissions()`,
 *   `hasRole()`, `getRoles()`, `getPolicies()`, `canActOn()`, a role's own
 *   permission checks and its rank and ancestry comparisons;
 * - `TenantScope`'s `apply()`, `within()` and tenant getters, and the resolved
 *   tenant's factory and binding;
 * - `ApplicationAccess::mayUse()`, on every path;
 * - the management services (roles, permissions, policies, grants, resource
 *   policies, boundaries and guardrails), the grant scope query, the access
 *   reviews and the pruner;
 * - the grant usage recorder and the package's usage store, as the container
 *   builds them; one held by outside code is outside this guarantee;
 * - `PermissionCatalogue::definitions()`, which runs the configured providers,
 *   and, while the package refuses, `PermissionCatalogue::declared()` and the
 *   declared action catalogue, which run them too, so a policy's document set
 *   on the model refuses rather than run them.
 *
 * Eloquent relations and models read directly (`roles()`, `permissions()` and
 * the like) read rows rather than decide, and are outside it.
 *
 * Telling whether to run is one property read, after one lookup in the
 * container for an operation that holds no state; the refusal is built only
 * when an operation is refused. It names the first refusal by its path and
 * code, never the value configured; with none, a fixed reason for a validation
 * that did not finish, under the `internal` code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PackageState
{
    /** @var \SineMacula\Laravel\Authorization\Diagnostics\Enums\PackageStatus Where the package stands. */
    private PackageStatus $status = PackageStatus::PENDING;

    /** @var bool Whether every operation runs, kept apart from the status so the check is one property read. */
    private bool $isHealthy = false;

    /** @var bool|null Whether the application boots for a check command, or null until that is decided. */
    private ?bool $isDiagnostic = null;

    /** @var \SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings|null What the diagnostic boot found, or null when it did not run. */
    private ?ConfigFindings $findings = null;

    /** @var list<\SineMacula\Laravel\Authorization\Diagnostics\BootCheck> The outcome of each check the diagnostic boot runs by building what a setting names. */
    private array $bootChecks = [];

    /**
     * Return the state the container holds, holding a new one, pending, first
     * when it holds none, as the package registers.
     *
     * Registering again keeps where the package stands, as an application
     * already booted is not booted again, and leaves whether it boots for
     * diagnosis to be decided afresh, as the registration steps run again.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return self
     */
    public static function start(Container $container): self
    {
        $state = self::of($container);

        if ($state === null) {
            $state = new self;

            $container->instance(self::class, $state);
        }

        $state->isDiagnostic = null;

        return $state;
    }

    /**
     * Return the state the container holds, or null when the package never
     * registered in it.
     *
     * Nothing is resolved: the instance is read where the container keeps it.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return self|null
     */
    public static function of(Container $container): ?self
    {
        if (!$container instanceof BaseContainer) {
            return $container->bound(self::class) ? self::held($container->make(self::class)) : null;
        }

        // Read in the container's own scope, as no public method reads an
        // instance without resolving it; the reader is bound once, so each read
        // is one call.
        static $reader = \Closure::bind(static fn (BaseContainer $container): mixed => $container->instances[PackageState::class] ?? null, null, BaseContainer::class);

        return self::held($reader($container));
    }

    /**
     * Refuse when the package of the current container is not healthy; do
     * nothing when the package never registered in it.
     *
     * The state is looked up afresh each time, never remembered, so a container
     * the package registers in later is guarded from then on.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function guardCurrent(): void
    {
        self::of(BaseContainer::getInstance())?->ensureHealthy();
    }

    /**
     * Refuse when the container's package is not healthy, before an operation
     * runs, and return its state; do nothing, and return null, when the package
     * never registered in it.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return self|null
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function guard(Container $container): ?self
    {
        $state = self::of($container);

        $state?->ensureHealthy();

        return $state;
    }

    /**
     * Refuse while the container's package refuses, and return its state, for
     * what the container builds, and what the boot's own validation builds and
     * reads, as the configuration is validated; let a pending package through,
     * and do nothing, returning null, when the package never registered in it.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return self|null
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function guardBuild(Container $container): ?self
    {
        $state = self::of($container);

        if ($state?->status === PackageStatus::REFUSING) {
            throw $state->refusal();
        }

        return $state;
    }

    /**
     * Refuse unless every operation runs.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public function ensureHealthy(): void
    {
        if ($this->isHealthy) {
            return;
        }

        throw $this->refusal();
    }

    /**
     * Return the refusal an operation throws while the package is not healthy:
     * the first refusal found, by its path and code, or, with none, a fixed
     * reason under the `internal` code.
     *
     * @return \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public function refusal(): InvalidAuthorizationConfigException
    {
        $issues  = $this->findings->issues                                                                                     ?? [];
        $refusal = \array_values(\array_filter($issues, static fn (ConfigIssue $issue): bool => $issue->code->isRefusal()))[0] ?? null;

        if ($refusal !== null) {
            $reason = "the configuration is refused ({$refusal->code->value}), so the package refuses every operation; run authorization:check to list every issue.";

            return new InvalidAuthorizationConfigException($refusal->path, $reason, $refusal->code, $refusal->expected, $refusal->gotType);
        }

        $reason = $this->status === PackageStatus::REFUSING
            ? 'the configuration could not be checked completely, so the package refuses every operation; run authorization:check to list every issue.'
            : 'the configuration has not been validated, as the package did not finish booting, so the package refuses every operation.';

        return new InvalidAuthorizationConfigException($issues[0]->path ?? StructuralCheck::ROOT, $reason, IssueCode::INTERNAL);
    }

    /**
     * Return where the package stands.
     *
     * @return \SineMacula\Laravel\Authorization\Diagnostics\Enums\PackageStatus
     */
    public function status(): PackageStatus
    {
        return $this->status;
    }

    /**
     * Record whether the application boots for a check command.
     *
     * @param  bool  $isDiagnostic
     * @return void
     */
    public function decide(bool $isDiagnostic): void
    {
        $this->isDiagnostic = $isDiagnostic;
    }

    /**
     * Determine whether it was decided whether the application boots for a
     * check command.
     *
     * @return bool
     */
    public function isDecided(): bool
    {
        return $this->isDiagnostic !== null;
    }

    /**
     * Determine whether the application boots for a check command.
     *
     * @return bool
     */
    public function isDiagnostic(): bool
    {
        return $this->isDiagnostic === true;
    }

    /**
     * Set the package back to pending as its configuration is validated again,
     * so it refuses until the validation passes.
     *
     * @return void
     */
    public function pending(): void
    {
        $this->status    = PackageStatus::PENDING;
        $this->isHealthy = false;
    }

    /**
     * Keep what the diagnostic boot found so far, where the package stands left
     * as it is.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings  $findings
     * @return void
     */
    public function found(ConfigFindings $findings): void
    {
        $this->findings = $findings;
    }

    /**
     * Mark the configuration validated and the package set up, keeping what the
     * diagnostic boot found, when it ran.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings|null  $findings
     * @return void
     */
    public function healthy(?ConfigFindings $findings = null): void
    {
        $this->findings  = $findings ?? $this->findings;
        $this->status    = PackageStatus::HEALTHY;
        $this->isHealthy = true;
    }

    /**
     * Refuse every operation, keeping what the diagnostic boot found.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings  $findings
     * @return void
     */
    public function refuse(ConfigFindings $findings): void
    {
        $this->findings  = $findings;
        $this->status    = PackageStatus::REFUSING;
        $this->isHealthy = false;
    }

    /**
     * Determine whether the diagnostic boot refused the configuration.
     *
     * @return bool
     */
    public function isRefusing(): bool
    {
        return $this->status === PackageStatus::REFUSING;
    }

    /**
     * Return what the diagnostic boot found, or null when it did not run.
     *
     * @return \SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings|null
     */
    public function findings(): ?ConfigFindings
    {
        return $this->findings;
    }

    /**
     * Keep the outcome of each check the diagnostic boot ran by building what a
     * setting names.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Diagnostics\BootCheck>  $checks
     * @return void
     */
    public function recordBootChecks(array $checks): void
    {
        $this->bootChecks = $checks;
    }

    /**
     * Return the outcome of each check the diagnostic boot ran by building what
     * a setting names, none when it did not run.
     *
     * @return list<\SineMacula\Laravel\Authorization\Diagnostics\BootCheck>
     */
    public function bootChecks(): array
    {
        return $this->bootChecks;
    }

    /**
     * Return the value given when it is a state, else null.
     *
     * @param  mixed  $value
     * @return self|null
     */
    private static function held(mixed $value): ?self
    {
        return $value instanceof self ? $value : null;
    }
}
