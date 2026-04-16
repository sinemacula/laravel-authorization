<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Models;

/**
 * Morph pivot for the `authorizable_roles` table.
 *
 * Extends the shared `AuthorizableGrantPivot` base for the common
 * `expires_at` cast and carries the role-grant-specific surface
 * area. Kept as a distinct class (rather than sharing one pivot
 * across three tables) so future per-table fields — tenant
 * scoping, granted-by audit, approval workflow — can land here
 * without leaking across the sibling `authorizable_permissions`
 * and `authorizable_policies` tables (see issue #90).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class AuthorizableRolePivot extends AuthorizableGrantPivot {}
