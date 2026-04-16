<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Contract for objects that can identify themselves as an
 * authorization resource string.
 *
 * When an object implementing this contract is passed through the
 * Gate translation layer, the evaluator receives the string returned
 * by `toResourceIdentifier()` instead of falling back to Eloquent's
 * `{morphClass}:{key}` convention or `__toString()`. This gives
 * non-Eloquent resource objects a first-class hook into the policy
 * evaluator's resource-matching surface.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AuthorizableResource
{
    /**
     * Return the canonical resource identifier string used by the
     * policy evaluator for resource matching.
     *
     * @return string
     */
    public function toResourceIdentifier(): string;
}
