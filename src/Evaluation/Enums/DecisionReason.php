<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation\Enums;

/**
 * Decision-reason codes for the policy evaluator.
 *
 * Every evaluation result carries one of these cases, indicating
 * which branch of the four-step decision order produced the
 * outcome. Backed by strings so serialised audit-log entries
 * remain human-readable while call-site comparisons gain
 * exhaustive `match` coverage at PHPStan level 8.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum DecisionReason: string
{
    /**
     * An explicit allow from a matching policy statement.
     */
    case EXPLICIT_ALLOW = 'explicit_allow';

    /**
     * An explicit deny from a matching policy statement.
     */
    case EXPLICIT_DENY = 'explicit_deny';

    /**
     * No statement matched; the evaluator fell through to implicit deny.
     */
    case IMPLICIT_DENY = 'implicit_deny';

    /**
     * RBAC (roles/permissions) granted the allow after policies were
     * indeterminate.
     */
    case RBAC_ALLOW = 'rbac_allow';

    /**
     * Return a human-readable explanation label for the reason.
     *
     * @return string
     */
    public function label(): string
    {
        return match ($this) {
            self::EXPLICIT_ALLOW => 'explicit allow from a policy statement',
            self::EXPLICIT_DENY  => 'explicit deny from a policy statement',
            self::RBAC_ALLOW     => 'RBAC grant (direct permission or role-inherited)',
            self::IMPLICIT_DENY  => 'implicit deny (no statement matched)',
        };
    }
}
