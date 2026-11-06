<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation\Enums;

/**
 * What a decision concluded: the check is allowed, or it is denied.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum DecisionEffect: string
{
    /** The check is allowed. */
    case ALLOW = 'allow';

    /** The check is denied, for the decision's reason. */
    case DENY = 'deny';
}
