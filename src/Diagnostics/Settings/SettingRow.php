<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics\Settings;

/**
 * One setting as the configuration report shows it: its path, whether the
 * configuration sets it, its value when the report may show it (see
 * `ValueRenderer`), else its type alone, where its value comes from, and what
 * the check found of it.
 *
 * `source` is `default` for a setting the configuration leaves out, so the
 * package's default applies, and `unknown` for one it sets: whether a value was
 * written in the application's configuration, read from the environment or
 * merged from the package's defaults cannot be told reliably once the
 * configuration is merged or cached, so it is never guessed.
 *
 * `value` is an object for a setting mapping names to classes or permissions,
 * empty or not, so its JSON keeps one type.
 *
 * `status` is `ok`, `refused`, `skipped` (not checked, as a setting it depends
 * on was refused), `unchecked` (its check failed in a way the package did not
 * foresee) or `checked_at_boot` (its checks that build what it names ran, and
 * passed, as the application booted).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SettingRow
{
    /**
     * Create a new row.
     *
     * @param  string  $path
     * @param  bool  $isKnown
     * @param  bool  $isSet
     * @param  array{0: mixed}|null  $shown
     * @param  string|null  $type
     * @param  string  $status
     * @param  bool  $isMap
     */
    public function __construct(

        /** The dotted path of the setting. */
        public string $path,

        /** Whether the package defines the setting. */
        public bool $isKnown,

        /** Whether the configuration sets it. */
        public bool $isSet,

        /** The value as shown, wrapped in a list, or null when it is not shown. */
        public ?array $shown,

        /** The type of the value set, or null when it is not set. */
        public ?string $type,

        /** What the check found of it. */
        public string $status,

        /** Whether the setting maps names to values, so its value is shown as a map even when it holds none. */
        public bool $isMap = false,
    ) {}

    /**
     * Return where its value comes from: `default` or `unknown`.
     *
     * @return string
     */
    public function source(): string
    {
        return $this->isSet ? 'unknown' : 'default';
    }

    /**
     * Return the row in the report's versioned shape.
     *
     * @return array{path: string, known: bool, set: bool, value: mixed, redacted: bool, type: string|null, source: string, status: string}
     */
    public function toArray(): array
    {
        return [
            'path'     => $this->path,
            'known'    => $this->isKnown,
            'set'      => $this->isSet,
            'value'    => $this->isMap && $this->shown !== null ? (object) $this->shown[0] : $this->shown[0] ?? null,
            'redacted' => $this->isSet && $this->shown === null,
            'type'     => $this->type,
            'source'   => $this->source(),
            'status'   => $this->status,
        ];
    }
}
