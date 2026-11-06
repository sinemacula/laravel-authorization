<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Context;

use Illuminate\Support\Facades\Date;
use SineMacula\Laravel\Authorization\Contracts\EnvironmentContext;

/**
 * The default environment context: the current time (AUTHZ-8.6).
 *
 * Supplies `time`, the instant Laravel's `now()` gives (so a test that freezes
 * or travels in time decides as of that time), in UTC as ISO 8601
 * (`2026-01-31T09:30:00Z`). It is fixed the first time the check reads
 * `environment`, then kept for the rest of the check, so every statement of the
 * check reads the same time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ClockEnvironmentContext implements EnvironmentContext
{
    /** @var string The format of `environment.time`: ISO 8601 in UTC, to the second. */
    public const string TIME_FORMAT = 'Y-m-d\TH:i:s\Z';

    /**
     * Return the current time, in UTC.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function values(): array
    {
        return ['time' => Date::now()->utc()->format(self::TIME_FORMAT)];
    }
}
