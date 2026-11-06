<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Environment context contract (AUTHZ-8.6).
 *
 * Supplies the `environment` namespace of the context. It is trusted: its
 * values never come from what the caller passes, and only rebinding this
 * contract replaces it.
 *
 * The shipped default supplies the current time, fixed the first time the check
 * reads `environment`, then kept for the rest of the check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EnvironmentContext
{
    /**
     * Return the namespace's values for the current check, nested by key. A key
     * left out is missing; an empty array leaves the namespace absent.
     *
     * @return array<string, mixed>
     */
    public function values(): array;
}
