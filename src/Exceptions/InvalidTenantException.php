<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;

/**
 * Thrown when the subject resolver returns a tenant that the scope boundary
 * cannot map to a stable `(tenant_type, tenant_id)` pair.
 *
 * The scope accepts two shapes:
 *
 *   - `Illuminate\Database\Eloquent\Model` — reads `getMorphClass()`
 *     and `getKey()`.
 *   - `SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant`
 *     — reads `getMorphClass()` and `getKey()` via the contract.
 *
 * Anything else — a plain `object` with no stable identity — is refused with
 * this exception instead of falling back to `spl_object_hash`, which produces
 * request-scoped hashes that silently do not match previously-persisted rows. A
 * tenant of an accepted shape without a key (an unsaved model) is refused
 * through `withoutKey()`, since `tenant_id = ''` matches no row it owns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidTenantException extends \LogicException
{
    /**
     * Create a new exception instance for the supplied tenant object, embedding
     * its class name in the message so the consumer can identify the offending
     * resolver.
     *
     * @param  object  $tenant
     * @param  string|null  $message
     */
    public function __construct(object $tenant, ?string $message = null)
    {
        parent::__construct($message ?? \sprintf(
            'Tenant must be an Eloquent Model or implement %s. Got %s.',
            AuthorizableTenant::class,
            $tenant::class,
        ));
    }

    /**
     * Create an exception for a tenant that has no key, such as a model that
     * has not been saved yet.
     *
     * @param  object  $tenant
     * @return self
     */
    public static function withoutKey(object $tenant): self
    {
        return new self($tenant, \sprintf(
            'Tenant %s has no key, so it cannot be matched to the rows it owns.',
            $tenant::class,
        ));
    }
}
