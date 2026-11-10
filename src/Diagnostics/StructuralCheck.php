<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Diagnostics\Checks\BlockChecks;
use SineMacula\Laravel\Authorization\Diagnostics\Checks\ExtensionChecks;
use SineMacula\Laravel\Authorization\Diagnostics\Checks\RootChecks;

/**
 * Check the authorization configuration as the boot does, collecting every
 * refusal instead of throwing the first (N113).
 *
 * Each setting and each entry of a list is checked on its own, so one refused
 * value does not hide its siblings: a key the package does not define is
 * refused under its own path, and the rest of its block is still checked. A
 * configuration that is not an array is one refusal, and every setting is then
 * skipped. A check that depends on a setting refused is recorded as skipped,
 * naming that setting.
 *
 * Only the structural checks run (types, keys, that classes exist and implement
 * their contracts, that names name configured entries). The checks that build
 * what the configuration names, the context sources, the attribute providers,
 * the action catalogue a session scope is checked against and the cache store,
 * ran, and passed, as the application booted; they are listed as
 * `checked_at_boot` and never run again, so the check builds nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class StructuralCheck
{
    /** @var string The path of the configuration. */
    public const string ROOT = 'authorization';

    /**
     * Create a new check.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the configured names are checked against. */
        private Container $container,
    ) {}

    /**
     * Check the configuration given and return what the checks found.
     *
     * @param  mixed  $root
     * @return \SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings
     */
    public function run(mixed $root): ConfigFindings
    {
        $collector = new IssueCollector;
        $config    = $collector->block(self::ROOT, $root, ConfigValidator::KEYS);

        if ($config === null) {
            $collector->skipBlock(self::ROOT, ConfigValidator::KEYS);

            return $collector->findings();
        }

        (new RootChecks($collector, $this->container, $config))->run();
        (new BlockChecks($collector, $this->container, $config))->run();
        (new ExtensionChecks($collector, $config))->run();

        return $collector->findings();
    }
}
