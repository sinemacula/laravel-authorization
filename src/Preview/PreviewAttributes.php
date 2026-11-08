<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Preview;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * The package's resource attribute provider for preview resources (see
 * `PreviewResource`), registered for their type whatever the application
 * configures, so a policy can restrict who may be previewed, and where (N84),
 * under `resource`:
 *
 * - `target_type`, `target_id`: the principal previewed, by morph type and key;
 * - `identity_type`, `identity_id`: the identity behind it, missing for none;
 * - `application`: the application the decision admitted is made in, missing
 *   for none.
 *
 * The built-ins `resource.id` (the principal's morph type and key),
 * `resource.type`, and `resource.tenant.type` and `resource.tenant.id` (the
 * tenant the decision admitted is made in, missing at platform scope) come from
 * the reference, as for every resource. A deny on a missing key cannot be
 * decided, so it refuses. Any other resource of the type, one that is not a
 * preview resource, has no attributes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PreviewAttributes implements ResourceAttributeProvider
{
    /**
     * Return the attributes the provider supplies.
     *
     * @return array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType>
     */
    #[\Override]
    public function attributes(): array
    {
        return [
            'target_type'   => ContextKeyType::STRING,
            'target_id'     => ContextKeyType::STRING,
            'identity_type' => ContextKeyType::STRING,
            'identity_id'   => ContextKeyType::STRING,
            'application'   => ContextKeyType::STRING,
        ];
    }

    /**
     * Return the attributes of the preview resource the reference hands on, or
     * none for any other.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \Illuminate\Database\Eloquent\Model|null  $model
     * @return array<string, mixed>
     */
    #[\Override]
    public function values(ResourceReference $resource, ?Model $model): array
    {
        return $resource->source instanceof PreviewResource ? $resource->source->attributes() : [];
    }
}
