<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Permission enum contract.
 *
 * Implemented by application-defined enums whose cases represent
 * discrete permission strings. The package's service provider walks
 * every case in every configured enum at boot and registers a
 * matching Laravel Gate, eliminating hand-wired Gate definitions for
 * enum-driven permission catalogues.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PermissionEnum extends \UnitEnum
{
    /**
     * Return the permission string used by the authorization engine.
     *
     * @return string
     */
    public function toString(): string;
}
