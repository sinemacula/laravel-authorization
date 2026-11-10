<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

/**
 * What the structural check of the configuration found: every issue, in the
 * order the checks ran, and the settings whose checks that build what they name
 * were left to the boot (`checked_at_boot`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConfigFindings
{
    /**
     * Create a new set of findings.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue>  $issues
     * @param  list<string>  $checkedAtBoot
     */
    public function __construct(

        /** Every issue found, in the order the checks ran. */
        public array $issues,

        /** The paths of the settings whose building checks ran, and passed, as the application booted, and are not run again. */
        public array $checkedAtBoot,
    ) {}

    /**
     * Determine whether any issue refuses the configuration.
     *
     * @return bool
     */
    public function isRefused(): bool
    {
        return \array_filter($this->issues, static fn (ConfigIssue $issue): bool => $issue->code->isRefusal()) !== [];
    }

    /**
     * Determine whether any check failed in a way the package did not foresee.
     *
     * @return bool
     */
    public function isIncomplete(): bool
    {
        return \array_filter($this->issues, static fn (ConfigIssue $issue): bool => $issue->kind() === 'internal') !== [];
    }
}
