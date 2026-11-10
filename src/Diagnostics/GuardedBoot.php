<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Foundation\Application as FoundationApplication;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Registrars\PendingRegistration;

/**
 * Validate the configuration as the application boots, and set the package up
 * only when it is sound, deciding where the package stands (see
 * `PackageState`).
 *
 * `prepare()` runs as the application boots, after every provider registered
 * and before any boots. It decides whether the application boots the package
 * for diagnosis (see `DiagnosticMode`), then runs the registration steps the
 * package left to the boot (see `PendingRegistration`). For diagnosis, the
 * structural check of the configuration runs first, collecting every issue
 * (`ConfigValidator::issues()`): when it finds any, the package refuses every
 * operation, and the steps, which may load and run code the configuration
 * names, are dropped. A step that throws while diagnosing is recorded as an
 * `internal` issue, and refuses.
 *
 * `validate()` runs as the package boots. For diagnosis, it runs the checks
 * that build what the configuration names (see `BootChecks`), unless the
 * package already refuses, recording the outcome of each; the package is
 * healthy only when they found nothing, and refuses otherwise, an issue the
 * package did not foresee included. Otherwise the configuration is validated as
 * it always was, the first refusal thrown, the package staying pending, so
 * every operation refuses should the application go on to serve anything; it is
 * healthy once the validation passed. Validating again, as when the package
 * registers and boots again, sets the package back to pending first.
 *
 * Dropping the steps holds back only what the package itself would run: the
 * console kernel still loads every deferred provider left once it bootstraps,
 * and the application's booting callbacks and sibling providers run their own
 * code, which the package cannot stop.
 *
 * `schedule()`, which the package's `register()` calls, has the application
 * prepare as it boots, or at once when it already booted, as when the package
 * registers again in an application serving requests; `validate()` prepares
 * first, should only the provider boot.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class GuardedBoot
{
    /**
     * Create a new boot.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     */
    public function __construct(

        /** The application the package boots in. */
        private Application $app,
    ) {}

    /**
     * Have the application prepare as it boots, after every provider registered
     * and before any boots, or at once when it already booted.
     *
     * @return void
     */
    public function schedule(): void
    {
        if ($this->app instanceof FoundationApplication && $this->app->isBooted()) {
            $this->prepare();

            return;
        }

        $this->app->booting(static function (Application $app): void {
            (new self($app))->prepare();
        });
    }

    /**
     * Decide whether the application boots the package for diagnosis, check the
     * configuration's structure when it does, and run the registration steps
     * left to the boot unless the package refuses. Runs once for each time the
     * package registers.
     *
     * @return void
     */
    public function prepare(): void
    {
        $state = PackageState::of($this->app);

        if ($state === null || $state->isDecided()) {
            return;
        }

        $state->decide(DiagnosticMode::isOn($this->app));

        if (!$state->isDiagnostic()) {
            PendingRegistration::find($this->app)?->run();

            return;
        }

        $this->diagnoseStructure($state);
    }

    /**
     * Validate the configuration as the package boots, and return whether the
     * package is healthy: refuse every operation when diagnosing found an
     * issue, and otherwise throw the first refusal, failing fast on a malformed
     * configuration, as a clear typed exception rather than a deep stack trace
     * from the first check in production.
     *
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public function validate(): bool
    {
        $this->prepare();

        $state = PackageState::of($this->app);

        if ($state?->isDiagnostic() === true) {
            return $this->hasPassedBootChecks($state);
        }

        $state?->pending();

        ConfigValidator::validate($this->app['config']->get('authorization', []), $this->app);

        $state?->healthy();

        return true;
    }

    /**
     * Collect every issue of the configuration's structure, and run the
     * registration steps when there is none, refusing, the steps left dropped,
     * when there is any or a step throws.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\PackageState  $state
     * @return void
     */
    private function diagnoseStructure(PackageState $state): void
    {
        $pending  = PendingRegistration::find($this->app);
        $findings = ConfigValidator::issues($this->app['config']->get('authorization', []), $this->app);

        $state->pending();
        $state->recordBootChecks(BootChecks::notRun());

        if ($findings->issues === []) {
            $findings = self::afterRunning($pending, $findings);
        }

        if ($findings->issues === []) {
            $state->found($findings);
        } else {
            $pending?->discard();
            $state->refuse($findings);
        }
    }

    /**
     * Run the registration steps left to the boot, and return what the
     * structural check found, or, when a step throws, the `internal` issue it
     * raised in its place.
     *
     * @param  \SineMacula\Laravel\Authorization\Registrars\PendingRegistration|null  $pending
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings  $findings
     * @return \SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings
     */
    private static function afterRunning(?PendingRegistration $pending, ConfigFindings $findings): ConfigFindings
    {
        try {
            $pending?->run();
        } catch (\Throwable $exception) {
            return new ConfigFindings([ConfigIssue::internal(StructuralCheck::ROOT, $exception)], $findings->checkedAtBoot);
        }

        return $findings;
    }

    /**
     * Run the checks that build what the configuration names, unless the
     * package already refuses, and return whether it is healthy.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\PackageState  $state
     * @return bool
     */
    private function hasPassedBootChecks(PackageState $state): bool
    {
        $structural = $state->findings();

        if ($state->isRefusing() || $structural === null) {
            return false;
        }

        $config = $this->app['config']->get('authorization', []);

        [$checks, $issues] = (new BootChecks($this->app))->run(\is_array($config) ? $config : []);

        // The structure was sound, or the package would refuse already, so the
        // boot checks found every issue there is.
        $findings = new ConfigFindings($issues, $structural->checkedAtBoot);

        $state->recordBootChecks($checks);

        if ($issues !== []) {
            $state->refuse($findings);

            return false;
        }

        $state->healthy($findings);

        return true;
    }
}
