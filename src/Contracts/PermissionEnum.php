<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Permission enum contract.
 *
 * Implemented by application-defined enums whose cases represent
 * discrete permissions. The enum must be a backed string enum — the
 * backing value is the canonical permission name used by the
 * authorization engine. The package's service provider walks every
 * case in every configured enum at boot and registers a matching
 * Laravel Gate, eliminating hand-wired Gate definitions for
 * enum-driven permission catalogues.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PermissionEnum extends \BackedEnum {}
