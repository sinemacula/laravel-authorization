<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * Immutable evaluation result.
 *
 * Captures the outcome of a single authorization check, including the
 * statement that decided the result (if any) and a reproducible trace
 * of every statement the evaluator considered. The trace is ordered,
 * serialisable, and safe to persist to an audit log.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-type EvaluationTraceEntry array{policy: string, statement_index: int, decision: 'matched'|'skipped', reason: string}
 */
final readonly class EvaluationResult
{
    /** Reason code indicating an explicit allow from a policy statement. */
    public const string REASON_EXPLICIT_ALLOW = 'explicit_allow';

    /** Reason code indicating an explicit deny from a policy statement. */
    public const string REASON_EXPLICIT_DENY = 'explicit_deny';

    /** Reason code indicating the evaluator reached implicit deny. */
    public const string REASON_IMPLICIT_DENY = 'implicit_deny';

    /** Reason code indicating RBAC (roles/permissions) granted the allow. */
    public const string REASON_RBAC_ALLOW = 'rbac_allow';

    /**
     * Create a new evaluation result.
     *
     * @param  bool  $allowed
     * @param  string  $reason
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement|null  $matchedStatement
     * @param  list<EvaluationTraceEntry>  $trace
     */
    public function __construct(

        /** Whether the check resolved to an allow decision. */
        public bool $allowed,

        /** Reason code describing how the decision was reached. */
        public string $reason,

        /** Statement that produced the decision, or null for implicit/RBAC outcomes. */
        public ?Statement $matchedStatement = null,

        /** Ordered, serialisable trace of every statement the evaluator considered. */
        public array $trace = [],

    ) {}

    /**
     * Build a result for an explicit allow.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @param  list<EvaluationTraceEntry>  $trace
     * @return self
     */
    public static function allowed(Statement $statement, array $trace = []): self
    {
        return new self(
            allowed: true,
            reason: self::REASON_EXPLICIT_ALLOW,
            matchedStatement: $statement,
            trace: $trace,
        );
    }

    /**
     * Build a result for an explicit deny.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @param  list<EvaluationTraceEntry>  $trace
     * @return self
     */
    public static function explicitlyDenied(Statement $statement, array $trace = []): self
    {
        return new self(
            allowed: false,
            reason: self::REASON_EXPLICIT_DENY,
            matchedStatement: $statement,
            trace: $trace,
        );
    }

    /**
     * Build a result for implicit deny.
     *
     * @param  list<EvaluationTraceEntry>  $trace
     * @return self
     */
    public static function implicitlyDenied(array $trace = []): self
    {
        return new self(
            allowed: false,
            reason: self::REASON_IMPLICIT_DENY,
            trace: $trace,
        );
    }

    /**
     * Build a result produced by an RBAC lookup.
     *
     * @param  list<EvaluationTraceEntry>  $trace
     * @return self
     */
    public static function rbacAllowed(array $trace = []): self
    {
        return new self(
            allowed: true,
            reason: self::REASON_RBAC_ALLOW,
            trace: $trace,
        );
    }

    /**
     * Render a human-readable explanation of the decision.
     *
     * @return string
     */
    public function explain(): string
    {
        $verdict = $this->allowed ? 'ALLOW' : 'DENY';
        $reason  = match ($this->reason) {
            self::REASON_EXPLICIT_ALLOW => 'explicit allow from a policy statement',
            self::REASON_EXPLICIT_DENY  => 'explicit deny from a policy statement',
            self::REASON_RBAC_ALLOW     => 'RBAC grant (direct permission or role-inherited)',
            default                     => 'implicit deny (no statement matched)',
        };

        $summary = \sprintf('%s — %s.', $verdict, $reason);

        if ($this->trace === []) {
            return $summary;
        }

        $lines = [$summary, 'Trace:'];

        foreach ($this->trace as $entry) {
            $lines[] = \sprintf(
                '  [%s] %s#%d — %s',
                $entry['decision'],
                $entry['policy'],
                $entry['statement_index'],
                $entry['reason'],
            );
        }

        return \implode("\n", $lines);
    }
}
