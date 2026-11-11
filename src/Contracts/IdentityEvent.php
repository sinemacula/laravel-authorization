<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Marker interface for the grant events: a role, permission or policy granted
 * to, revoked from or re-dated on a grantee.
 *
 * Every event under `Events\Identity\` carries a `grantee` reference naming the
 * identity whose grants changed, so a listener can accept the whole set with a
 * single type hint rather than a long union. It narrows
 * `AuthorizationMutation`, which every change event implements, so the grantee
 * is also each event's subject and its one grantee.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface IdentityEvent extends AuthorizationMutation {}
