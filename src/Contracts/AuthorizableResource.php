<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * Contract for objects that identify themselves as the resource of a check
 * (AUTHZ-4.2).
 *
 * The reference it returns wins over a model's own `type:id` and its tenant
 * resolver, so a non-Eloquent object, or a model that knows its own tenant,
 * names exactly the resource, and the tenant, a check is about (N8).
 *
 * A model that implements it is still handed to its type's resource attribute
 * provider: when its reference names one record and carries no model, the check
 * adds the model to it (N30).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AuthorizableResource
{
    /**
     * Return the reference to the resource: its identifier, type, id and
     * tenant.
     *
     * @return \SineMacula\Laravel\Authorization\Support\ResourceReference
     */
    public function toResourceReference(): ResourceReference;
}
