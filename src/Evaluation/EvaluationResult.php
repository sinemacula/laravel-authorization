<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Permissions\Evaluation;

/**
 * Evaluation result.
 *
 * An immutable value object representing the outcome of an
 * IAM-style policy evaluation. Captures whether the action was
 * allowed, the reason for the decision, and the statement that
 * determined the result.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final readonly class EvaluationResult
{
    /** Reason code indicating the action was explicitly allowed by a policy statement */
    public const string REASON_EXPLICIT_ALLOW = 'explicit_allow';

    /** Reason code indicating the action was explicitly denied by a policy statement */
    public const string REASON_EXPLICIT_DENY = 'explicit_deny';

    /** Reason code indicating the action was denied because no statement granted access */
    public const string REASON_IMPLICIT_DENY = 'implicit_deny';

    /** Reason code indicating the action was allowed via RBAC permission */
    public const string REASON_RBAC_ALLOW = 'rbac_allow';

    /**
     * Create a new evaluation result instance.
     *
     * @param  bool  $allowed
     * @param  string  $reason
     * @param  \SineMacula\Laravel\Iam\Permissions\Evaluation\Statement|null  $matchedStatement
     */
    public function __construct(
        public bool $allowed,
        public string $reason,
        public ?Statement $matchedStatement = null,
    ) {}

    /**
     * Create a result indicating the action was explicitly allowed.
     *
     * @param  \SineMacula\Laravel\Iam\Permissions\Evaluation\Statement  $statement
     * @return self
     */
    public static function allowed(Statement $statement): self
    {
        return new self(
            allowed: true,
            reason: self::REASON_EXPLICIT_ALLOW,
            matchedStatement: $statement,
        );
    }

    /**
     * Create a result indicating the action was explicitly denied.
     *
     * @param  \SineMacula\Laravel\Iam\Permissions\Evaluation\Statement  $statement
     * @return self
     */
    public static function explicitlyDenied(Statement $statement): self
    {
        return new self(
            allowed: false,
            reason: self::REASON_EXPLICIT_DENY,
            matchedStatement: $statement,
        );
    }

    /**
     * Create a result indicating the action was implicitly denied.
     *
     * @return self
     */
    public static function implicitlyDenied(): self
    {
        return new self(
            allowed: false,
            reason: self::REASON_IMPLICIT_DENY,
        );
    }

    /**
     * Create a result indicating the action was allowed via RBAC.
     *
     * @return self
     */
    public static function rbacAllowed(): self
    {
        return new self(
            allowed: true,
            reason: self::REASON_RBAC_ALLOW,
        );
    }
}
