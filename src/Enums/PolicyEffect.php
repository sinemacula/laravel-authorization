<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Permissions\Enums;

/**
 * Policy effect enum.
 *
 * Defines the two possible effects of a policy statement: allow
 * or deny. Used during IAM-style policy evaluation to determine
 * whether a given action is permitted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
enum PolicyEffect: string
{
    case ALLOW = 'allow';
    case DENY  = 'deny';
}
