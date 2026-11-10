<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics\Settings;

use SineMacula\Laravel\Authorization\Diagnostics\BootCheck;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\BootCheckOutcome;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;

/**
 * Read every setting the shipped configuration defines, then each key the
 * configuration sets that the package does not define, as the report shows
 * them, with what the check found of each.
 *
 * Given the outcome of each check the diagnostic boot ran by building what a
 * setting names, a setting whose check failed is shown as `failed_at_boot`, and
 * one the boot left unchecked, as the structural check found an issue, as
 * `not_run`; without them, a setting whose checks were left to the boot is
 * shown as `checked_at_boot`, as a boot that completed ran them, and they
 * passed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SettingsReader
{
    /**
     * Create a new reader.
     *
     * @param  mixed  $root
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings  $findings
     * @param  list<\SineMacula\Laravel\Authorization\Diagnostics\BootCheck>  $bootChecks
     */
    public function __construct(

        /** The authorization configuration. */
        private mixed $root,

        /** What the check of it found. */
        private ConfigFindings $findings,

        /** The outcome of each check the diagnostic boot ran by building what a setting names, none when it did not run. */
        private array $bootChecks = [],
    ) {}

    /**
     * Return a row for every setting the package defines, in the order the
     * shipped configuration lists them, then one for each unknown key, in the
     * order the check found them.
     *
     * @return list<\SineMacula\Laravel\Authorization\Diagnostics\Settings\SettingRow>
     */
    public function rows(): array
    {
        $unknown = \array_filter($this->findings->issues, static fn (ConfigIssue $issue): bool => $issue->code === IssueCode::UNKNOWN_KEY);
        $paths   = \array_unique([...\array_keys(SettingCatalogue::SETTINGS), ...\array_map(static fn (ConfigIssue $issue): string => $issue->path, $unknown)]);

        return \array_map($this->row(...), \array_values($paths));
    }

    /**
     * Return the row of the setting under the path.
     *
     * @param  string  $path
     * @return \SineMacula\Laravel\Authorization\Diagnostics\Settings\SettingRow
     */
    private function row(string $path): SettingRow
    {
        [$isSet, $value] = $this->lookup($path);

        return new SettingRow(
            path: $path,
            isKnown: \array_key_exists($path, SettingCatalogue::SETTINGS),
            isSet: $isSet,
            shown: $isSet ? ValueRenderer::render(SettingCatalogue::kindOf($path), $value) : null,
            type: $isSet ? ValueRenderer::typeOf($value) : null,
            status: $this->status($path),
            isMap: \in_array(SettingCatalogue::kindOf($path), SettingCatalogue::MAPS, true),
        );
    }

    /**
     * Return whether the configuration sets the setting under the path, and its
     * value.
     *
     * @param  string  $path
     * @return array{0: bool, 1: mixed}
     */
    private function lookup(string $path): array
    {
        $value = ['authorization' => $this->root];

        foreach (\explode('.', $path) as $key) {
            if (!\is_array($value) || !\array_key_exists($key, $value)) {
                return [false, null];
            }

            $value = $value[$key];
        }

        return [true, $value];
    }

    /**
     * Return what the check found of the setting under the path: a check the
     * diagnostic boot ran on it that failed first, then its own issues and
     * those of what it holds, then a refusal of a block it sits in, which left
     * it unchecked, then whether its checks were left to the boot, and what
     * became of them.
     *
     * @param  string  $path
     * @return string
     */
    private function status(string $path): string
    {
        $own     = \array_filter($this->findings->issues, static fn (ConfigIssue $issue): bool => $issue->path === $path || \str_starts_with($issue->path, "{$path}."));
        $above   = \array_filter($this->findings->issues, static fn (ConfigIssue $issue): bool => \str_starts_with($path, "{$issue->path}."));
        $kinds   = \array_map(static fn (ConfigIssue $issue): string => $issue->kind(), $own);
        $outcome = $this->outcomeOf($path);

        return match (true) {
            $outcome === BootCheckOutcome::FAILED                  => 'failed_at_boot',
            \in_array('refusal', $kinds, true)                     => 'refused',
            \in_array('internal', $kinds, true)                    => 'unchecked',
            $kinds !== [] || $above !== []                         => 'skipped',
            \in_array($path, $this->findings->checkedAtBoot, true) => $outcome === BootCheckOutcome::NOT_RUN ? 'not_run' : 'checked_at_boot',
            default                                                => 'ok',
        };
    }

    /**
     * Return what became of the check the diagnostic boot ran on the setting
     * under the path, or null when it ran none.
     *
     * @param  string  $path
     * @return \SineMacula\Laravel\Authorization\Diagnostics\Enums\BootCheckOutcome|null
     */
    private function outcomeOf(string $path): ?BootCheckOutcome
    {
        $checks = \array_filter($this->bootChecks, static fn (BootCheck $check): bool => $check->path === $path);

        return \array_values($checks)[0]->outcome ?? null;
    }
}
