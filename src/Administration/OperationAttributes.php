<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * The package's resource attribute provider for administration operation
 * resources (see `OperationResource`), registered for their type whatever the
 * application configures, so a policy can condition a delegated change on what
 * it names, under `resource`:
 *
 * - `action`: the administration action, such as `authorization:role.grant`;
 * - `narrowing`: whether the change can only narrow what anyone may do;
 * - `unchanged`: set when the change changes nothing, missing otherwise;
 * - `target_type`, `target_id`: the record acted on, by morph type and key;
 * - `role`, `permission`, `policy`: the name of the record acted on, under its
 *   kind;
 * - `grantee_type`, `grantee_id`: the identity, principal or role a grant or a
 *   removal is for, or the resource type and key (`*` for the whole type) a
 *   resource policy is attached to;
 * - `application`: the application a grant holds in, missing for every one;
 * - `subtree`: whether a grant reaches the tenants below its tenant;
 * - `expires_at`: when a grant expires, missing for one that never does;
 * - `change.name`, `change.description`, `change.rank`, `change.parent`,
 *   `change.guard`, `change.category`, `change.digest`, `change.owner_type`,
 *   `change.owner_id`: the proposed change to a definition, a policy document
 *   by its digest alone;
 * - `impersonated`, `impersonator_type`, `impersonator_id`: whether the actor
 *   is impersonated, and by whom.
 *
 * The built-ins `resource.id` (the operation's id), `resource.type` and
 * `resource.tenant` (the intended tenant, or a definition's owner) come from
 * the reference, as for every resource. A key the change does not name is
 * missing. Any other resource of the type, one that is not an operation
 * resource, has no attributes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class OperationAttributes implements ResourceAttributeProvider
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
            'action'             => ContextKeyType::STRING,
            'narrowing'          => ContextKeyType::BOOL,
            'unchanged'          => ContextKeyType::BOOL,
            'target_type'        => ContextKeyType::STRING,
            'target_id'          => ContextKeyType::STRING,
            'role'               => ContextKeyType::STRING,
            'permission'         => ContextKeyType::STRING,
            'policy'             => ContextKeyType::STRING,
            'grantee_type'       => ContextKeyType::STRING,
            'grantee_id'         => ContextKeyType::STRING,
            'application'        => ContextKeyType::STRING,
            'subtree'            => ContextKeyType::BOOL,
            'expires_at'         => ContextKeyType::TIME,
            'change.name'        => ContextKeyType::STRING,
            'change.description' => ContextKeyType::STRING,
            'change.rank'        => ContextKeyType::NUMBER,
            'change.parent'      => ContextKeyType::STRING,
            'change.guard'       => ContextKeyType::STRING,
            'change.category'    => ContextKeyType::STRING,
            'change.digest'      => ContextKeyType::STRING,
            'change.owner_type'  => ContextKeyType::STRING,
            'change.owner_id'    => ContextKeyType::STRING,
            'impersonated'       => ContextKeyType::BOOL,
            'impersonator_type'  => ContextKeyType::STRING,
            'impersonator_id'    => ContextKeyType::STRING,
        ];
    }

    /**
     * Return the attributes of the operation resource the reference hands on,
     * or none for any other.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \Illuminate\Database\Eloquent\Model|null  $model
     * @return array<string, mixed>
     */
    #[\Override]
    public function values(ResourceReference $resource, ?Model $model): array
    {
        return $resource->source instanceof OperationResource ? $resource->source->attributes() : [];
    }
}
