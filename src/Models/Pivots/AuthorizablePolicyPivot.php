<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Models\Pivots;

/**
 * Morph pivot for the `authorizable_policies` table.
 *
 * Extends the shared `AuthorizableGrantPivot` base for the common
 * `expires_at` cast and carries the policy-attachment-specific
 * surface area. Kept as a distinct class (rather than sharing one
 * pivot across three tables) so future per-table fields — most
 * notably a policy-attachment approval workflow's `approved_by`
 * column — can land here without leaking across the sibling
 * `authorizable_roles` and `authorizable_permissions` tables (see
 * issue #90).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class AuthorizablePolicyPivot extends AuthorizableGrantPivot {}
