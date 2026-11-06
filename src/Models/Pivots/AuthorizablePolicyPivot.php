<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Models\Pivots;

use Illuminate\Database\Eloquent\Attributes\ObservedBy;
use SineMacula\Laravel\Authorization\Observers\AuthorizablePolicyPivotObserver;

/**
 * Morph pivot for the `authorizable_policies` table.
 *
 * Extends the shared `AuthorizableGrantPivot` base for the common `expires_at`
 * cast and carries the policy-attachment-specific surface area. Kept as a
 * distinct class (rather than sharing one pivot across three tables) so future
 * per-table fields — most notably a policy-attachment approval workflow's
 * `approved_by` column — can land here without leaking across the sibling
 * `authorizable_roles` and `authorizable_permissions` tables.
 *
 * A row written through a grantee's `policies()` relation saves this model, so
 * the `AuthorizablePolicyPivotObserver` refuses an inline policy attached to
 * any grantee but its own there, as the grant service does on its own writes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[ObservedBy(AuthorizablePolicyPivotObserver::class)]
final class AuthorizablePolicyPivot extends AuthorizableGrantPivot {}
