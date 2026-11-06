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
 * Each is guard-agnostic and filed under the `authorization` category. They are
 * the package's, not the application's: the action catalogue holds what the
 * application declares, and the policy validator accepts a pattern that covers
 * one of these whatever the catalogue holds.
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

    /**
     * Determine whether the name is one the package declares.
     *
     * @param  string  $name
     * @return bool
     */
    public static function isDeclared(string $name): bool
    {
        return \in_array($name, self::names(), true);
    }

    /**
     * Determine whether the action pattern covers at least one permission the
     * package declares: it is the name, or matches it with `fnmatch` and
     * `FNM_NOESCAPE`, as statements match actions.
     *
     * @param  string  $pattern
     * @return bool
     */
    public static function covers(string $pattern): bool
    {
        foreach (self::names() as $name) {
            if ($pattern === $name || \fnmatch($pattern, $name, \FNM_NOESCAPE)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return the name of every permission the package declares.
     *
     * @return list<string>
     */
    private static function names(): array
    {
        return \array_map(static fn (PermissionDefinition $definition): string => $definition->name, (new self)->permissions());
    }
}
