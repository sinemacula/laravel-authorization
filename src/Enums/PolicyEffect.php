<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Enums;

/**
 * Policy effect.
 *
 * Represents the two possible outcomes of a matching policy statement
 * under AWS IAM-style evaluation. A statement with effect {@see self::ALLOW}
 * contributes an allow decision; a statement with effect {@see self::DENY}
 * contributes an explicit deny and short-circuits the evaluator.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum PolicyEffect: string
{
    case ALLOW = 'allow';
    case DENY  = 'deny';
}
