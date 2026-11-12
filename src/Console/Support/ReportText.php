<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console\Support;

use SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigurationReport;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\ReportStatus;
use SineMacula\Laravel\Authorization\Diagnostics\Settings\SettingRow;
use SineMacula\Laravel\Authorization\Evaluation\ExplanationText;
use Symfony\Component\Console\Formatter\OutputFormatter;

/**
 * The configuration report as `authorization:check` prints it as text (N113):
 * one line per issue first, then a section each for the settings, the tables,
 * the seams, the grant hooks, the connection and the integrations, each line
 * `[subject] state`, and a last line with the outcome.
 *
 * The text holds what the report holds, and nothing else: names, classes,
 * drivers, paths and what the package wrote, never a value the report does not
 * show. Each name has its console markup, control, format, bidirectional and
 * line separator characters escaped, as the explanation text escapes names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReportText
{
    /** @var array<string, string> The last line for each outcome. */
    public const array CONCLUSIONS = [
        ReportStatus::PASSED->value     => 'Every check passed.',
        ReportStatus::REFUSED->value    => 'A check failed.',
        ReportStatus::INCOMPLETE->value => 'The check could not be completed.',
    ];

    /** @var string The heading of the grant hooks' section. */
    private const string GRANT_HOOKS = 'Grant hooks, in the order they run; the chain stops at the first refusal';

    /** @var array<string, string> How each state of the Gate hook is shown. */
    private const array GATE = [
        'enabled'        => 'enabled (the package answers every ability it declares through Gate::before)',
        'disabled'       => 'disabled (authorization.gate.enabled is false; Laravel decides every ability)',
        'not_registered' => 'not registered (authorization.gate.enabled is on, but the hook is not in place)',
        'unknown'        => 'unknown (authorization.gate.enabled could not be read)',
    ];

    /** @var array<string, array{string, string, string, string}> Per part of the connection: its name's key, the settings choosing it, and what shows when it has none. */
    private const array CONNECTIONS = [
        'database' => ['name', 'authorization.connection', 'database.default', 'none'],
        'cache'    => ['store', 'authorization.cache.store', 'cache.default', 'none (entries are kept for the request or job alone)'],
        'queue'    => ['connection', 'authorization.usage.connection', 'queue.default', 'none'],
    ];

    /** @var array<string, string> How each status of a setting is shown. */
    private const array STATUSES = [
        'ok'              => 'ok',
        'refused'         => 'refused',
        'skipped'         => 'skipped',
        'unchecked'       => 'not checked',
        'checked_at_boot' => 'checked at boot',
        'failed_at_boot'  => 'failed at boot',
        'not_run'         => 'not run at boot',
    ];

    /**
     * Return the report's lines, in order.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\ConfigurationReport  $report
     * @return list<string>
     */
    public static function lines(ConfigurationReport $report): array
    {
        return [
            ...\array_map(self::issue(...), $report->issues),
            ...self::section('Settings', \array_map(self::setting(...), $report->settings)),
            ...self::section('Tables', self::tables($report->tables)),
            ...self::section('Seams', \array_map(SeamText::line(...), $report->seams)),
            ...self::section(self::GRANT_HOOKS, \array_map(self::grantHook(...), $report->grantHooks)),
            ...self::section('Connection', self::connection($report->connection)),
            ...self::section('Integrations', \array_map(self::integration(...), $report->integrations)),
            '',
            self::CONCLUSIONS[$report->status->value],
        ];
    }

    /**
     * Return a line `[subject] state`, the subject escaped and styled.
     *
     * @param  string  $subject
     * @param  string  $state
     * @param  string|null  $style
     * @return string
     */
    public static function line(string $subject, string $state, ?string $style = null): string
    {
        $subject = '[' . self::escape($subject) . ']';

        return ($style === null ? $subject : "<{$style}>{$subject}</{$style}>") . ' ' . $state;
    }

    /**
     * Return the name escaped: its console markup, and its control, format,
     * bidirectional and line separator characters, or all of it when it is not
     * UTF-8.
     *
     * @param  string  $name
     * @return string
     */
    public static function escape(string $name): string
    {
        $escaped = \preg_replace_callback('/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u', static fn (array $character): string => ExplanationText::bare($character[0]), $name);

        return OutputFormatter::escape($escaped ?? ExplanationText::bare($name));
    }

    /**
     * Return the line of an issue: a refusal and an incomplete check as errors,
     * a skipped check as a comment.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue  $issue
     * @return string
     */
    private static function issue(ConfigIssue $issue): string
    {
        $subject = (\str_starts_with($issue->path, 'authorization.') || $issue->path === 'authorization' ? 'setting ' : 'check ') . $issue->path;

        $state = match ($issue->code) {
            IssueCode::SKIPPED  => 'skipped; it depends on ' . self::escape((string) $issue->dependsOn) . ', which was refused',
            IssueCode::INTERNAL => 'could not be completed (' . self::escape((string) $issue->exception) . ')',
            default             => self::refusal($issue),
        };

        return self::line($subject, $state, $issue->code === IssueCode::SKIPPED ? 'comment' : 'error');
    }

    /**
     * Return what a refusal says: its code, what the setting expects and the
     * type of the value refused.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue  $issue
     * @return string
     */
    private static function refusal(ConfigIssue $issue): string
    {
        $parts = [\str_replace('_', ' ', $issue->code->value)];

        if ($issue->expected !== null) {
            $parts[] = 'expected ' . self::escape($issue->expected);
        }

        if ($issue->gotType !== null) {
            $parts[] = 'found ' . self::escape($issue->gotType);
        }

        return \implode('; ', $parts);
    }

    /**
     * Return the line of a setting: its status, then its value where it is
     * shown, else its type alone.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Settings\SettingRow  $setting
     * @return string
     */
    private static function setting(SettingRow $setting): string
    {
        $value = match (true) {
            !$setting->isSet         => 'not set, so its default applies',
            $setting->shown === null => 'value not shown (' . self::escape((string) $setting->type) . ')',
            default                  => self::value($setting->shown[0] ?? null),
        };

        return self::line('setting ' . $setting->path, (self::STATUSES[$setting->status] ?? $setting->status) . ($setting->isKnown ? '' : '; unknown key') . "; {$value}");
    }

    /**
     * Return a value the report shows: a name, a class, a whole number, a
     * switch, null, an empty prefix, or a list or map of names.
     *
     * @param  mixed  $value
     * @return string
     */
    private static function value(mixed $value): string
    {
        return match (true) {
            $value === ''      => 'empty',
            \is_array($value)  => self::entries($value),
            \is_string($value) => self::escape($value),
            \is_bool($value)   => $value ? 'true' : 'false',
            default            => \is_int($value) ? (string) $value : 'null',
        };
    }

    /**
     * Return a list or map of names the report shows, each key of a map before
     * its value.
     *
     * @param  array<array-key, mixed>  $entries
     * @return string
     */
    private static function entries(array $entries): string
    {
        $shown = [];

        foreach ($entries as $key => $entry) {
            $shown[] = (\is_int($key) ? '' : self::escape($key) . ' => ') . self::value($entry);
        }

        return '[' . \implode(', ', $shown) . ']';
    }

    /**
     * Return the lines of the tables: the prefix of their default names, then
     * the name each table takes, and whether it was set explicitly or is the
     * table's default with the prefix before it.
     *
     * @param  array{prefix: string|null, names: list<array{key: string, name: string|null, explicit: bool}>}  $tables
     * @return list<string>
     */
    private static function tables(array $tables): array
    {
        $prefix = $tables['prefix'];
        $lines  = [self::line('table prefix', match ($prefix) {
            null    => 'not known, as the setting was refused',
            ''      => 'none',
            default => self::escape($prefix),
        })];

        foreach ($tables['names'] as $table) {
            $name    = $table['name'] === null ? 'not known, as its setting or the prefix was refused' : self::escape($table['name']);
            $lines[] = self::line('table ' . $table['key'], $name . ($table['explicit'] ? '; set explicitly, so used as written' : '; the default, with the prefix'));
        }

        return $lines;
    }

    /**
     * Return the line of a grant hook, in the order it runs.
     *
     * @param  array<string, mixed>  $hook
     * @return string
     */
    private static function grantHook(array $hook): string
    {
        $state = ($hook['source'] ?? null) === 'configured' ? self::listedHook($hook) : self::boundHook($hook);

        return self::line('grant hook ' . self::scalar($hook['position'] ?? null), $state);
    }

    /**
     * Return what a hook the configuration lists is: its class, or its type
     * when its value is not shown.
     *
     * @param  array<string, mixed>  $hook
     * @return string
     */
    private static function listedHook(array $hook): string
    {
        $class = $hook['class'] ?? null;

        return (\is_string($class) ? self::escape($class) : 'value not shown (' . self::scalar($hook['type'] ?? null) . ')') . '; listed in authorization.grant_hooks';
    }

    /**
     * Return what the hook bound to the contract is, as the seam's line shows
     * it, and that the package's own runs no hook of its own.
     *
     * @param  array<string, mixed>  $hook
     * @return string
     */
    private static function boundHook(array $hook): string
    {
        $factory = $hook['factory'] ?? null;
        $bound   = self::scalar($hook['class'] ?? null, \is_string($factory) ? SeamText::customCode($factory) : 'nothing');
        $origin  = \str_replace('_', ' ', self::scalar($hook['origin'] ?? null));

        return "{$bound}; bound to the contract, {$origin}" . (($hook['runs'] ?? false) === true ? '' : '; runs no hook of its own');
    }

    /**
     * Return the lines of the database connection, the cache store and the
     * queue connection: names, the setting each was chosen by and drivers
     * alone.
     *
     * @param  array<string, mixed>  $connection
     * @return list<string>
     */
    private static function connection(array $connection): array
    {
        $lines = [];

        foreach (self::CONNECTIONS as $part => [$key, $configured, $default, $none]) {
            $entry   = \is_array($connection[$part] ?? null) ? $connection[$part] : [];
            $name    = self::field($entry, $key, '');
            $chosen  = ($entry['chosen'] ?? null) === 'configured' ? $configured : $default;
            $lines[] = self::line("connection {$part}", $name === ''
                ? $none
                : "{$name}; chosen by {$chosen}; driver " . self::field($entry, 'driver', 'unknown') . self::connectionNote($part, $entry));
        }

        return $lines;
    }

    /**
     * Return a field of a part of the connection: its name escaped, `value not
     * shown` when the report withheld it, as it is not a name, or else the
     * fallback.
     *
     * @param  array<array-key, mixed>  $entry
     * @param  string  $field
     * @param  string  $fallback
     * @return string
     */
    private static function field(array $entry, string $field, string $fallback): string
    {
        $redacted = \is_array($entry['redacted'] ?? null) && \in_array($field, $entry['redacted'], true);

        return $redacted ? 'value not shown' : self::scalar($entry[$field] ?? null, $fallback);
    }

    /**
     * Return what the line of a part of the connection adds: that the database
     * is not connected to, and the queue the usage is sent to.
     *
     * @param  string  $part
     * @param  array<array-key, mixed>  $entry
     * @return string
     */
    private static function connectionNote(string $part, array $entry): string
    {
        return match ($part) {
            'database' => '; not connected to',
            'queue'    => '; queue ' . self::field($entry, 'queue', 'the default'),
            default    => '',
        };
    }

    /**
     * Return the line of an integration.
     *
     * @param  array{name: string, state: string, detail: string|null}  $integration
     * @return string
     */
    private static function integration(array $integration): string
    {
        $state = $integration['name'] === 'gate' ? self::GATE[$integration['state']] ?? $integration['state'] : \str_replace('_', ' ', $integration['state']);

        return self::line('integration ' . $integration['name'], self::escape($state) . ($integration['detail'] === null ? '' : ' (' . self::escape($integration['detail']) . ')'));
    }

    /**
     * Return a section: a blank line, its heading and its lines.
     *
     * @param  string  $heading
     * @param  list<string>  $lines
     * @return list<string>
     */
    private static function section(string $heading, array $lines): array
    {
        return ['', "<comment>{$heading}</comment>", ...$lines];
    }

    /**
     * Return a scalar from the report escaped, or the fallback when it is not a
     * string or an integer.
     *
     * @param  mixed  $value
     * @param  string  $fallback
     * @return string
     */
    private static function scalar(mixed $value, string $fallback = 'unknown'): string
    {
        return \is_string($value) || \is_int($value) ? self::escape((string) $value) : $fallback;
    }
}
