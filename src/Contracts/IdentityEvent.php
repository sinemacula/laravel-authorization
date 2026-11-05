<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Marker interface for the grant events: a role, permission or policy granted
 * to, revoked from or re-dated on a grantee.
 *
 * Every event under `Events\Identity\` carries a `grantee` reference naming the
 * identity whose grants changed, so a listener can accept the whole set with a
 * single type hint rather than a long union. It narrows `AuthorizationEvent`,
 * which every event the package dispatches implements.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface IdentityEvent extends AuthorizationEvent {}
