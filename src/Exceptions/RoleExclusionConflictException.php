<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

use SineMacula\Laravel\Authorization\Exclusions\ConflictReport;

/**
 * Thrown when two roles are declared mutually exclusive while someone holds
 * both where their reach overlaps (AUTHZ-11.8, N135): the pair is refused, and
 * nothing is written or removed, until an administrator resolves every
 * conflict, by revoking a grant or narrowing its reach, and declares it again.
 * Also thrown, as `written()` builds it, for a role grant, a re-parenting or a
 * break-glass activation that would leave someone holding both roles of a
 * declared pair where their reach overlaps: the write is refused and nothing is
 * written.
 *
 * It carries the conflict report, references and scopes only, never a model:
 * who holds both, with the identity a conflict came through, and the two routes
 * of each conflict; for a write, only the conflicts it would create.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RoleExclusionConflictException extends \RuntimeException
{
    /**
     * Create a new exception instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Exclusions\ConflictReport  $report
     * @param  string  $roleName
     * @param  string  $excludedRoleName
     */
    public function __construct(

        /** Who holds both roles where their reach overlaps, and through which routes. */
        private readonly ConflictReport $report,

        // The name of the pair's first role, for the message.
        string $roleName,

        // The name of the pair's second role, for the message.
        string $excludedRoleName,
    ) {
        $holders = \count($report->holders());

        parent::__construct(
            "Roles '{$roleName}' and '{$excludedRoleName}' cannot be declared mutually exclusive: {$holders} "
                . ($holders === 1 ? 'holder holds' : 'holders hold') . ' both where their reach overlaps; resolve every conflict first.',
        );
    }

    /**
     * Return the refusal of a write that would leave someone holding both roles
     * of the pair where their reach overlaps, carrying the report of the
     * conflicts it would create.
     *
     * @param  \SineMacula\Laravel\Authorization\Exclusions\ConflictReport  $report
     * @param  string  $roleName
     * @param  string  $excludedRoleName
     * @return self
     */
    public static function written(ConflictReport $report, string $roleName, string $excludedRoleName): self
    {
        $refusal = new self($report, $roleName, $excludedRoleName);
        $holders = \count($report->holders());

        $refusal->message = "Roles '{$roleName}' and '{$excludedRoleName}' are mutually exclusive: the write would leave {$holders} "
            . ($holders === 1 ? 'holder' : 'holders') . ' holding both where their reach overlaps.';

        return $refusal;
    }

    /**
     * Return the conflict report the declaration or the write was refused with.
     *
     * @return \SineMacula\Laravel\Authorization\Exclusions\ConflictReport
     */
    public function getReport(): ConflictReport
    {
        return $this->report;
    }
}
