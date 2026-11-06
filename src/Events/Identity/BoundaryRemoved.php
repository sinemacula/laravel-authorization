<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Identity;

/**
 * Dispatched when a grantee's permission boundary is removed in a scope
 * (AUTHZ-7.4), by the boundary service or once the grantee is deleted.
 *
 * It carries what every change to a boundary does (see `BoundaryEvent`): the
 * operation, the grantee, the policy that was the boundary, its name and the
 * scope.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class BoundaryRemoved extends BoundaryEvent {}
