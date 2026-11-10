<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;

/**
 * Reports the configuration state the package runs with, one line per check,
 * each `name: state` (AUTHZ-17.2).
 *
 * It reports whether the Gate hook is enabled, that is whether the package is
 * the authority of Laravel's Gate (AUTHZ-9.1). It is the start of the
 * configuration report: each further setting or seam it reports is one more
 * entry in `checks()`, and so one more line. The configuration has passed the
 * boot-time validation before the command runs, so it always exits
 * successfully.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class CheckConfigurationCommand extends Command
{
    /** @var string The console command's name. */
    public const string NAME = 'authorization:check';

    /** @var string The console command signature. */
    protected $signature = self::NAME;

    /** @var string The console command description. */
    protected $description = 'Report the authorization configuration the application runs with';

    /**
     * Execute the console command.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return int
     */
    public function handle(ConfigRepository $config): int
    {
        foreach (self::checks($config) as $name => $state) {
            $this->line("{$name}: {$state}");
        }

        return self::SUCCESS;
    }

    /**
     * Return the state each check reports, keyed by the check's name, in the
     * order they are reported.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return array<string, string>
     */
    private static function checks(ConfigRepository $config): array
    {
        return [
            'Gate hook' => GateRegistrar::isEnabled($config)
                ? 'enabled (the package answers every ability it declares through Gate::before)'
                : 'disabled (authorization.gate.enabled is false; Laravel decides every ability)',
        ];
    }
}
