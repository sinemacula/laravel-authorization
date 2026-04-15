<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Permissions\Contracts;

use SineMacula\Laravel\Iam\Permissions\Evaluation\Policy;

/**
 * Policy store contract.
 *
 * Defines the interface for retrieving IAM-style policies for a
 * given principal. Implementations may load policies from a
 * database, cache, or external service.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
interface PolicyStore
{
    /**
     * Retrieve all policies for the given principal identifier.
     *
     * @param  mixed  $principalIdentifier
     * @return array<int, \SineMacula\Laravel\Iam\Permissions\Evaluation\Policy>
     */
    public function policiesFor(mixed $principalIdentifier): array;
}
