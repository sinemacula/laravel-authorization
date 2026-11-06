<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Action catalogue contract (AUTHZ-6.2).
 *
 * The actions a policy may name. Every `actions` and `not_actions` pattern of a
 * policy document must cover at least one of them before the document is
 * written, so a mistyped action never becomes a statement that names nothing.
 * The shipped default reads the permissions the code declares in
 * `authorization.permission_enums` and `authorization.permission_providers`; an
 * application may bind its own.
 *
 * A catalogue that covers no pattern, not even `*`, declares no actions, and
 * every policy write is then refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ActionCatalogue
{
    /**
     * Determine whether the action pattern covers at least one action of the
     * catalogue.
     *
     * @param  string  $pattern
     * @return bool
     */
    public function covers(string $pattern): bool;
}
