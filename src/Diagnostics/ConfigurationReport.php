<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

use SineMacula\Laravel\Authorization\Diagnostics\Enums\ReportStatus;
use SineMacula\Laravel\Authorization\Diagnostics\Settings\SettingRow;

/**
 * The configuration the application runs with, as `authorization:check` reports
 * it (N113), built without building any seam (see `Inspector`).
 *
 * Its shape is versioned (`VERSION`, see `toArray()`):
 *
 * - `version`, and `status`: `refused` when any issue refuses a setting, else
 *   `incomplete` when a check or a part of the report could not be completed,
 *   else `passed`; a seam whose class custom code decides at first use never
 *   changes it;
 * - `settings`: every setting the package defines and each unknown key set,
 *   with its value where it may be shown, its source and status (see
 *   `Settings\SettingRow`);
 * - `tables`: the prefix of the tables' default names, and the name each table
 *   takes, whether it was set explicitly (see `TableReader`);
 * - `seams`: where each seam's binding came from, its class or classes, how
 *   long it lives, its extenders and history (see `SeamRow`);
 * - `grant_hooks`: the hooks in the order they run (see `GrantHookOrder`);
 * - `connection`: the database connection, cache store and queue connection by
 *   name and driver, never tested (see `ConnectionReader`);
 * - `integrations`: the Gate hook, the Blade directives, the query macros and
 *   the route middleware aliases (see `IntegrationReader`);
 * - `issues`: each issue, structured, never a message (see `ConfigIssue`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConfigurationReport
{
    /** @var int The version of the report's shape. */
    public const int VERSION = 1;

    /** @var \SineMacula\Laravel\Authorization\Diagnostics\Enums\ReportStatus The outcome of the report. */
    public ReportStatus $status;

    /**
     * Create a new report.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Diagnostics\Settings\SettingRow>  $settings
     * @param  list<\SineMacula\Laravel\Authorization\Diagnostics\SeamRow>  $seams
     * @param  list<array<string, mixed>>  $grantHooks
     * @param  array<string, mixed>  $connection
     * @param  list<array{name: string, state: string, detail: string|null}>  $integrations
     * @param  list<\SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue>  $issues
     * @param  array{prefix: string|null, names: list<array{key: string, name: string|null, explicit: bool}>}  $tables
     */
    public function __construct(

        /** Every setting, as shown. */
        public array $settings,

        /** Every seam, as shown. */
        public array $seams,

        /** The grant hooks, in the order they run. */
        public array $grantHooks,

        /** The database connection, cache store and queue connection. */
        public array $connection,

        /** How the package is wired into the application. */
        public array $integrations,

        /** Every issue found. */
        public array $issues,

        /** The prefix of the tables' default names, and the name each table takes. */
        public array $tables = TableReader::UNREAD,
    ) {
        $this->status = self::statusOf($issues);
    }

    /**
     * Return the outcome the issues give: a refusal wins over an incomplete
     * check.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue>  $issues
     * @return \SineMacula\Laravel\Authorization\Diagnostics\Enums\ReportStatus
     */
    public static function statusOf(array $issues): ReportStatus
    {
        $findings = new ConfigFindings($issues, []);

        return match (true) {
            $findings->isRefused()    => ReportStatus::REFUSED,
            $findings->isIncomplete() => ReportStatus::INCOMPLETE,
            default                   => ReportStatus::PASSED,
        };
    }

    /**
     * Return the report in its versioned shape.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'version'      => self::VERSION,
            'status'       => $this->status->value,
            'settings'     => \array_map(static fn (SettingRow $row): array => $row->toArray(), $this->settings),
            'tables'       => $this->tables,
            'seams'        => \array_map(static fn (SeamRow $row): array => $row->toArray(), $this->seams),
            'grant_hooks'  => $this->grantHooks,
            'connection'   => $this->connection,
            'integrations' => $this->integrations,
            'issues'       => \array_map(static fn (ConfigIssue $issue): array => $issue->toArray(), $this->issues),
        ];
    }
}
