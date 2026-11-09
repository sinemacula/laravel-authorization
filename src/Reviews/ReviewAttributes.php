<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * The package's resource attribute provider for review resources (see
 * `ReviewResource`), registered for their type whatever the application
 * configures, so a policy can restrict who may review what, and where (N96),
 * under `resource`:
 *
 * - `query`: `holders`, `holdings`, `expiring` or `granted_by`;
 * - `scope`: `applies_in`, `rooted_within` or `everywhere`;
 * - `application_selection`: `none`, `named` or `any`, and `application`, the
 *   application named, missing otherwise;
 * - `target_type`, `target_id`: the role, permission or policy whose holders
 *   are listed, missing for any other review;
 * - `subject_type`, `subject_id`: the principal or identity whose holdings are
 *   listed, missing for any other review;
 * - `actor_type`, `actor_id`: the actor whose last grants are listed, missing
 *   for any other review;
 * - `impersonated`, a boolean, `impersonator_type`, `impersonator_id`: whether
 *   someone is impersonating the reviewer, and who, missing when no one is.
 *
 * The built-ins `resource.id` (the question), `resource.type`, and
 * `resource.tenant.type` and `resource.tenant.id` (the reviewed tenant, missing
 * for the platform and everywhere) come from the reference, as for every
 * resource. A deny on a missing key cannot be decided, so it refuses. Any other
 * resource of the type has no attributes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ReviewAttributes implements ResourceAttributeProvider
{
    /** @var list<string> The keys the provider supplies as strings, beside `impersonated`. */
    private const array KEYS = [
        'query',
        'scope',
        'application_selection',
        'application',
        'target_type',
        'target_id',
        'subject_type',
        'subject_id',
        'actor_type',
        'actor_id',
        'impersonator_type',
        'impersonator_id',
    ];

    /**
     * Return the attributes the provider supplies.
     *
     * @return array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType>
     */
    #[\Override]
    public function attributes(): array
    {
        return [...\array_fill_keys(self::KEYS, ContextKeyType::STRING), 'impersonated' => ContextKeyType::BOOL];
    }

    /**
     * Return the attributes of the review resource the reference hands on, or
     * none for any other.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \Illuminate\Database\Eloquent\Model|null  $model
     * @return array<string, mixed>
     */
    #[\Override]
    public function values(ResourceReference $resource, ?Model $model): array
    {
        return $resource->source instanceof ReviewResource ? $resource->source->attributes() : [];
    }
}
