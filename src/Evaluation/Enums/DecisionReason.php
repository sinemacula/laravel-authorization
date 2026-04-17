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
    case ExplicitAllow = 'explicit_allow';

    /**
     * An explicit deny from a matching policy statement.
     */
    case ExplicitDeny = 'explicit_deny';

    /**
     * No statement matched; the evaluator fell through to implicit deny.
     */
    case ImplicitDeny = 'implicit_deny';

    /**
     * RBAC (roles/permissions) granted the allow after policies were
     * indeterminate.
     */
    case RbacAllow = 'rbac_allow';

    /**
     * Return a human-readable explanation label for the reason.
     *
     * @return string
     */
    public function label(): string
    {
        return match ($this) {
            self::ExplicitAllow => 'explicit allow from a policy statement',
            self::ExplicitDeny  => 'explicit deny from a policy statement',
            self::RbacAllow     => 'RBAC grant (direct permission or role-inherited)',
            self::ImplicitDeny  => 'implicit deny (no statement matched)',
        };
    }
}
