<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

use SineMacula\Laravel\Authorization\Evaluation\Policy;

/**
 * Policy store contract.
 *
 * Optional extension point for sourcing policies from an external system — a
 * cache, a remote service, or an audit log — in addition to the policies
 * attached directly to an identity. When the service container has a binding
 * for this contract, the authorization manager consults it on every evaluation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PolicyStore
{
    /**
     * Return the policies that apply to the supplied principal.
     *
     * @param  object  $principal
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    public function policiesFor(object $principal): array;
}
