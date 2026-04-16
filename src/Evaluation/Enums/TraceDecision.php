<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation\Enums;

/**
 * Trace-entry decision field.
 *
 * Each entry in the evaluation trace records whether the
 * statement matched or was skipped. Backed by strings so
 * serialised trace arrays stay human-readable while the
 * evaluator and result objects gain exhaustive `match`
 * coverage.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum TraceDecision: string
{
    /**
     * The statement matched the action/resource and conditions.
     */
    case MATCHED = 'matched';

    /**
     * The statement did not match (action/resource miss or condition failure).
     */
    case SKIPPED = 'skipped';
}
