<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Permission enum contract.
 *
 * Implemented by application-defined, string-backed enums whose cases declare
 * the application's permissions. A case's value is the permission name, so
 * `PostPermission::UPDATE->value` is the string the engine checks. The service
 * provider registers a Laravel Gate for every case of every configured enum at
 * boot, and `authorization:sync` writes the cases to the permission catalogue,
 * with the metadata of any `#[Permission]` attribute on the case.
 *
 * The boot-time config validation refuses a configured enum backed by integers,
 * since an integer is not a permission name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PermissionEnum extends \BackedEnum {}
