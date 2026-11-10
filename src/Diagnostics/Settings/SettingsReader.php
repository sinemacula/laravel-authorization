<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics\Settings;

use SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;

/**
 * Read every setting the shipped configuration defines, then each key the
 * configuration sets that the package does not define, as the report shows
 * them, with what the check found of each.
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
     */
    public function __construct(

        /** The authorization configuration. */
        private mixed $root,

        /** What the check of it found. */
        private ConfigFindings $findings,
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
     * Return what the check found of the setting under the path: its own issues
     * and those of what it holds first, then a refusal of a block it sits in,
     * which left it unchecked, then whether it was checked at boot.
     *
     * @param  string  $path
     * @return string
     */
    private function status(string $path): string
    {
        $own   = \array_filter($this->findings->issues, static fn (ConfigIssue $issue): bool => $issue->path === $path || \str_starts_with($issue->path, "{$path}."));
        $above = \array_filter($this->findings->issues, static fn (ConfigIssue $issue): bool => \str_starts_with($path, "{$issue->path}."));
        $kinds = \array_map(static fn (ConfigIssue $issue): string => $issue->kind(), $own);

        return match (true) {
            \in_array('refusal', $kinds, true)                     => 'refused',
            \in_array('internal', $kinds, true)                    => 'unchecked',
            $kinds !== [] || $above !== []                         => 'skipped',
            \in_array($path, $this->findings->checkedAtBoot, true) => 'checked_at_boot',
            default                                                => 'ok',
        };
    }
}
