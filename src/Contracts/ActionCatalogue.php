<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Action catalogue contract (AUTHZ-6.2).
 *
 * The actions the application lets a policy name. Every `actions` and
 * `not_actions` pattern of a policy document must cover at least one of them,
 * or one of the package's own permissions (see `PackagePermissions`), before
 * the document is written, so a mistyped action never becomes a statement that
 * names nothing. The package's own permissions are never the catalogue's to
 * declare: the validator accepts them whatever it holds. The shipped default
 * reads the permissions the code declares in `authorization.permission_enums`
 * and `authorization.permission_providers`, the package's own left out; an
 * application may bind its own.
 *
 * A catalogue that covers no pattern, not even `*`, declares no actions, and
 * every policy write whose patterns need any action but the package's own is
 * then refused, with the one reason that nothing is declared.
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
