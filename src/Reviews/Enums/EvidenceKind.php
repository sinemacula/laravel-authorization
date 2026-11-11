<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Enums;

/**
 * What gives the action a review of holdings filtered by one asks about (see
 * `Reviews\ActionEvidence`):
 *
 * - `permission`: a permission whose name covers the action under the held
 *   permission rules (see `Support\HeldPermissions`), held directly, through a
 *   role or one above it, or through the identity;
 * - `policy_statement`: a policy with at least one statement naming the action
 *   under the policy matcher's rules (see `Evaluation\Statement`), its effect
 *   reported, its conditions, resource patterns and requirements reported as
 *   present but never evaluated.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum EvidenceKind: string
{
    /** A permission whose name covers the action. */
    case PERMISSION = 'permission';

    /** A policy with a statement naming the action. */
    case POLICY_STATEMENT = 'policy_statement';
}
