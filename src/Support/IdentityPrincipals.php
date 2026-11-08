<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

/**
 * The principals an identity owns, as the identity directory lists them, and
 * whether that list is complete (N81).
 *
 * An incomplete list may still name the principals the directory knows: their
 * grants are read all the same, so a grant of theirs outside a tenant still
 * proves the identity reaches outside it, but nothing can prove the identity
 * stays within one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IdentityPrincipals
{
    /**
     * Create a new list of an identity's principals.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $principals
     * @param  bool  $isComplete
     */
    public function __construct(

        /** The principals the identity owns, as far as they are known. */
        public array $principals,

        /** Whether no principal of the identity is missing from the list. */
        public bool $isComplete,
    ) {}

    /**
     * Return the complete list of the identity's principals: none beyond these.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $principals
     * @return self
     */
    public static function complete(array $principals = []): self
    {
        return new self($principals, true);
    }

    /**
     * Return a list that may leave principals of the identity out, naming the
     * ones that are known.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $principals
     * @return self
     */
    public static function incomplete(array $principals = []): self
    {
        return new self($principals, false);
    }
}
