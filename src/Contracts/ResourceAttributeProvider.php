<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * Resource attribute provider contract (N30, AUTHZ-8.4).
 *
 * Supplies the attributes of the records of one resource type (its owner,
 * status, classification and the like), which conditions and `${…}` references
 * read under `resource`, never from the model's columns directly. It is
 * registered for its morph type in `authorization.attributes.resources` and
 * resolved from the container.
 *
 * The attributes it declares enter the context key catalogue at boot as
 * `resource.<path>`, and only those are exposed: a value it returns for a key
 * it does not declare is dropped. It may not declare a built-in (`id`, `type`
 * or anything under `tenant`), which the package supplies from the check's
 * resource reference. It is asked only for a check on one record, at most once
 * for the check and only when a statement reads `resource`; a check on a type
 * alone, an opaque identifier or no resource never asks it. A provider that
 * throws aborts the check with `AttributeProviderFailed`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ResourceAttributeProvider
{
    /**
     * Return the attributes the provider supplies, each a dot path relative to
     * `resource` mapped to its type, such as `['status' => 'string', 'owner.id'
     * => 'string']`.
     *
     * @return array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>
     */
    public function attributes(): array;

    /**
     * Return the record's attribute values, nested by key, so `['owner' =>
     * ['id' => '7']]` supplies `resource.owner.id`. A key left out is missing.
     *
     * The model is the one the check was given, so the provider can read it
     * rather than query for it; null when the check named the record some other
     * way, such as a `(type, id)` pair.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \Illuminate\Database\Eloquent\Model|null  $model
     * @return array<string, mixed>
     */
    public function values(ResourceReference $resource, ?Model $model): array;
}
