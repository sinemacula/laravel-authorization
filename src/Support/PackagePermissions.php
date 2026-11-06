<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;

/**
 * The permissions the package itself declares: the rights its own management
 * services check, which the permission catalogue always holds, whatever the
 * application configures, so `authorization:sync` writes them, they can be
 * granted, and a policy naming them validates.
 *
 * Each is guard-agnostic and filed under the `authorization` category.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PackagePermissions implements PermissionProvider
{
    /** @var string The right to set and remove guardrails, held from above the scope they cap (AUTHZ-7.6). */
    public const string GUARDRAILS_MANAGE = 'authorization:guardrails:manage';

    /** @var string The category every package permission is filed under. */
    private const string CATEGORY = 'authorization';

    /**
     * Return the permissions the package declares.
     *
     * @return list<\SineMacula\Laravel\Authorization\Support\PermissionDefinition>
     */
    #[\Override]
    public function permissions(): array
    {
        return [
            new PermissionDefinition(self::GUARDRAILS_MANAGE, 'Set and remove guardrails from above the scope they cap.', self::CATEGORY),
        ];
    }
}
