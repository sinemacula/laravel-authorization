<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

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
    ) {}

    /**
     * Return the reference to one record of the type.
     *
     * @param  string  $type
     * @param  string  $id
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return self
     */
    public static function record(string $type, string $id, ?Reference $tenant = null): self
    {
        return new self("{$type}:{$id}", $type, $id, $tenant);
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
