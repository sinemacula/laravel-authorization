<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

/**
 * A grantee named by its morph type and key, for granting to a grantee that is
 * not loaded, or whose model class is not available, such as the rows an import
 * copies from another package's tables.
 *
 * It answers `getMorphClass()` and `getKey()` as a model does, so the grant
 * events and the resolution cache treat it as the grantee it names. A reference
 * carries no guard, so a role or permission named by a string is looked up
 * under the package's default guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class GranteeReference
{
    /**
     * Create a new grantee reference.
     *
     * @param  string  $type
     * @param  string  $id
     */
    public function __construct(

        /** The grantee's morph type, as `authorizable_type` stores it. */
        public string $type,

        /** The grantee's key, as `authorizable_id` stores it. */
        public string $id,
    ) {}

    /**
     * Return the grantee's morph type.
     *
     * @return string
     */
    public function getMorphClass(): string
    {
        return $this->type;
    }

    /**
     * Return the grantee's key.
     *
     * @return string
     */
    public function getKey(): string
    {
        return $this->id;
    }
}
