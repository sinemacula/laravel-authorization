<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a tenant resolver returns an object that the scope
 * boundary cannot map to a stable `(tenant_type, tenant_id)` pair.
 *
 * The scope accepts two shapes:
 *
 *   - `Illuminate\Database\Eloquent\Model` — reads `getMorphClass()`
 *     and `getKey()`.
 *   - `SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant`
 *     — reads `getMorphClass()` and `getKey()` via the contract.
 *
 * Anything else — a plain `object` with no stable identity — is
 * refused with this exception instead of falling back to
 * `spl_object_hash`, which produces request-scoped hashes that
 * silently do not match previously-persisted rows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class InvalidTenantException extends \LogicException
{
    /**
     * Create a new exception instance for the supplied tenant
     * object, embedding its class name in the message so the
     * consumer can identify the offending resolver.
     *
     * @param  object  $tenant
     */
    public function __construct(object $tenant)
    {
        parent::__construct(\sprintf(
            'Tenant must be an Eloquent Model or implement %s. Got %s.',
            \SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant::class,
            $tenant::class,
        ));
    }
}
