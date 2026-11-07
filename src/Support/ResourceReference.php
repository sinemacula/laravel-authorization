<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableResource;

/**
 * The resource a check is about (AUTHZ-4.2): its type, its id and, where it has
 * one, its tenant, with the identifier statements match their resource patterns
 * against.
 *
 * A model is identified as `type:id`, a `(type, id)` pair the same way, and a
 * type alone ("create a post") as `type:*`, so a pattern naming the type covers
 * it and one naming a single record does not (N6). A plain string is taken as
 * an opaque identifier, used as given, with no type, id or tenant (N7).
 *
 * A reference made from a model keeps the model, so the resource attribute
 * provider of its type can read it rather than query for it (N30). A resource
 * that identifies itself and is no model can hand itself on as its source in
 * the same way, as an administration operation resource does, so its own
 * attribute provider and the constraints of the operation can read it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ResourceReference
{
    /**
     * Create a new resource reference.
     *
     * @param  string  $identifier
     * @param  string|null  $type
     * @param  string|null  $id
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  \Illuminate\Database\Eloquent\Model|null  $model
     * @param  \SineMacula\Laravel\Authorization\Contracts\AuthorizableResource|null  $source
     */
    public function __construct(

        /** What statements match their resource patterns against. */
        public string $identifier,

        /** The resource's type, its morph class; null for an opaque identifier. */
        public ?string $type = null,

        /** The resource's id; null for a type alone or an opaque identifier. */
        public ?string $id = null,

        /** The tenant that owns the resource; null for none or unknown. */
        public ?Reference $tenant = null,

        /** The model the check was given; null when it named the resource some other way. */
        public ?Model $model = null,

        /** The resource that identified itself with this reference, when it hands itself on; null otherwise. */
        public ?AuthorizableResource $source = null,
    ) {}

    /**
     * Return the reference to one record of the type.
     *
     * @param  string  $type
     * @param  string  $id
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  \Illuminate\Database\Eloquent\Model|null  $model
     * @return self
     */
    public static function record(string $type, string $id, ?Reference $tenant = null, ?Model $model = null): self
    {
        return new self("{$type}:{$id}", $type, $id, $tenant, $model);
    }

    /**
     * Return the reference to a type alone, for a check such as "create a post"
     * that names no one record.
     *
     * @param  string  $type
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return self
     */
    public static function type(string $type, ?Reference $tenant = null): self
    {
        return new self("{$type}:*", $type, null, $tenant);
    }
}
