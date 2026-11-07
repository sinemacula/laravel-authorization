<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;

/**
 * The permissions the package itself declares: the administration actions its
 * own management services check (AUTHZ-11.1), which the permission catalogue
 * always holds, whatever the application configures, so `authorization:sync`
 * writes them, they can be granted, and a policy naming them validates.
 *
 * Each is spelt `authorization:NOUN.VERB`, is guard-agnostic and is filed under
 * the `authorization` category. They are the package's, not the application's:
 * the action catalogue holds what the application declares, and the policy
 * validator accepts a pattern that covers one of these whatever the catalogue
 * holds.
 *
 * A service called with an acting context decides the action of each change it
 * makes through `check()`, on the change's operation resource (see
 * `Administration\OperationResource`). Holding an action permits the operation;
 * it never implicitly permits distributing whatever the operation hands out.
 * The grantable rights let an actor hand out a permission or an approved
 * version of a policy it does not hold, and `administration.unbounded` lets a
 * delegated change lift or widen a permission boundary; the read actions are
 * declared for a later part of delegated administration, and nothing checks
 * them yet.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PackagePermissions implements PermissionProvider
{
    /** @var string The right to grant a role to a principal or identity, a regrant, a changed expiry and a changed reach included. */
    public const string ROLE_GRANT = 'authorization:role.grant';

    /** @var string The right to revoke a role from a principal or identity. */
    public const string ROLE_REVOKE = 'authorization:role.revoke';

    /** @var string The right to grant a permission directly to a grantee, or to add one to a role. */
    public const string PERMISSION_GRANT = 'authorization:permission.grant';

    /** @var string The right to revoke a direct permission, or to remove one from a role. */
    public const string PERMISSION_REVOKE = 'authorization:permission.revoke';

    /** @var string The right to attach a policy to an identity, a principal or a role. */
    public const string POLICY_ATTACH = 'authorization:policy.attach';

    /** @var string The right to detach a policy from an identity, a principal or a role. */
    public const string POLICY_DETACH = 'authorization:policy.detach';

    /** @var string The right to create a role. */
    public const string ROLE_CREATE = 'authorization:role.create';

    /** @var string The right to rename a role. */
    public const string ROLE_RENAME = 'authorization:role.rename';

    /** @var string The right to change a role's description or rank. */
    public const string ROLE_UPDATE = 'authorization:role.update';

    /** @var string The right to delete a role, and with it every grant of it. */
    public const string ROLE_DELETE = 'authorization:role.delete';

    /** @var string The right to set, replace or clear a role's parent. */
    public const string ROLE_PARENT_SET = 'authorization:role.parent.set';

    /** @var string The right to create a permission. */
    public const string PERMISSION_CREATE = 'authorization:permission.create';

    /** @var string The right to rename a permission, which changes what every grant of it means. */
    public const string PERMISSION_RENAME = 'authorization:permission.rename';

    /** @var string The right to change a permission's description or category. */
    public const string PERMISSION_UPDATE = 'authorization:permission.update';

    /** @var string The right to delete a permission, and with it every grant of it. */
    public const string PERMISSION_DELETE = 'authorization:permission.delete';

    /** @var string The right to create a policy, an inline one included. */
    public const string POLICY_CREATE = 'authorization:policy.create';

    /** @var string The right to rename a policy. */
    public const string POLICY_RENAME = 'authorization:policy.rename';

    /** @var string The right to rewrite a policy's document or change its description. */
    public const string POLICY_UPDATE = 'authorization:policy.update';

    /** @var string The right to delete a policy, and with it every attachment of it. */
    public const string POLICY_DELETE = 'authorization:policy.delete';

    /** @var string The right to set or replace a grantee's permission boundary. */
    public const string BOUNDARY_SET = 'authorization:boundary.set';

    /** @var string The right to remove a grantee's permission boundary. */
    public const string BOUNDARY_REMOVE = 'authorization:boundary.remove';

    /** @var string The right to set and remove guardrails, held from above the scope they cap (AUTHZ-7.6). */
    public const string GUARDRAIL_MANAGE = 'authorization:guardrail.manage';

    /** @var string The right to attach a policy to a resource record or a whole resource type. */
    public const string RESOURCE_POLICY_ATTACH = 'authorization:resource-policy.attach';

    /** @var string The right to detach a policy from a resource record or a whole resource type. */
    public const string RESOURCE_POLICY_DETACH = 'authorization:resource-policy.detach';

    /** @var string The right to read and list roles through the management services. */
    public const string ROLE_READ = 'authorization:role.read';

    /** @var string The right to read and list permissions through the management services. */
    public const string PERMISSION_READ = 'authorization:permission.read';

    /** @var string The right to read and list policies, their documents and attachments, through the management services. */
    public const string POLICY_READ = 'authorization:policy.read';

    /** @var string The explicit right to delegate a permission without holding it. */
    public const string PERMISSION_GRANTABLE = 'authorization:permission.grantable';

    /** @var string The explicit right to delegate an approved version of a policy without holding what it allows. */
    public const string POLICY_GRANTABLE = 'authorization:policy.grantable';

    /** @var string The further right an otherwise permitted change needs when it benefits the actor itself. */
    public const string ADMINISTRATION_SELF = 'authorization:administration.self';

    /** @var string The right to make a delegated change while impersonating. */
    public const string ADMINISTRATION_IMPERSONATED = 'authorization:administration.impersonated';

    /** @var string The further right a delegated boundary change needs when it may lift or widen what a boundary caps. */
    public const string ADMINISTRATION_UNBOUNDED = 'authorization:administration.unbounded';

    /** @var string The category every package permission is filed under. */
    private const string CATEGORY = 'authorization';

    /** @var array<string, string> The description of every permission the package declares, by name, in the catalogue's order. */
    private const array DESCRIPTIONS = [
        self::ROLE_GRANT                  => 'Grant a role to a principal or identity.',
        self::ROLE_REVOKE                 => 'Revoke a role from a principal or identity.',
        self::PERMISSION_GRANT            => 'Grant a permission directly, or add one to a role.',
        self::PERMISSION_REVOKE           => 'Revoke a direct permission, or remove one from a role.',
        self::POLICY_ATTACH               => 'Attach a policy to an identity, a principal or a role.',
        self::POLICY_DETACH               => 'Detach a policy from an identity, a principal or a role.',
        self::ROLE_CREATE                 => 'Create a role.',
        self::ROLE_RENAME                 => 'Rename a role.',
        self::ROLE_UPDATE                 => 'Change a role\'s description or rank.',
        self::ROLE_DELETE                 => 'Delete a role.',
        self::ROLE_PARENT_SET             => 'Set, replace or clear a role\'s parent.',
        self::PERMISSION_CREATE           => 'Create a permission.',
        self::PERMISSION_RENAME           => 'Rename a permission.',
        self::PERMISSION_UPDATE           => 'Change a permission\'s description or category.',
        self::PERMISSION_DELETE           => 'Delete a permission.',
        self::POLICY_CREATE               => 'Create a policy.',
        self::POLICY_RENAME               => 'Rename a policy.',
        self::POLICY_UPDATE               => 'Rewrite a policy\'s document or change its description.',
        self::POLICY_DELETE               => 'Delete a policy.',
        self::BOUNDARY_SET                => 'Set or replace a permission boundary.',
        self::BOUNDARY_REMOVE             => 'Remove a permission boundary.',
        self::GUARDRAIL_MANAGE            => 'Set and remove guardrails from above the scope they cap.',
        self::RESOURCE_POLICY_ATTACH      => 'Attach a policy to a resource or a resource type.',
        self::RESOURCE_POLICY_DETACH      => 'Detach a policy from a resource or a resource type.',
        self::ROLE_READ                   => 'Read and list roles.',
        self::PERMISSION_READ             => 'Read and list permissions.',
        self::POLICY_READ                 => 'Read and list policies and their attachments.',
        self::PERMISSION_GRANTABLE        => 'Delegate a permission without holding it.',
        self::POLICY_GRANTABLE            => 'Delegate an approved version of a policy without holding what it allows.',
        self::ADMINISTRATION_SELF         => 'Make an otherwise permitted change that benefits the actor itself.',
        self::ADMINISTRATION_IMPERSONATED => 'Make a delegated change while impersonating.',
        self::ADMINISTRATION_UNBOUNDED    => 'Replace a permission boundary with a wider one, or remove one.',
    ];

    /**
     * Return the permissions the package declares.
     *
     * @return list<\SineMacula\Laravel\Authorization\Support\PermissionDefinition>
     */
    #[\Override]
    public function permissions(): array
    {
        $permissions = [];

        foreach (self::DESCRIPTIONS as $name => $description) {
            $permissions[] = new PermissionDefinition($name, $description, self::CATEGORY);
        }

        return $permissions;
    }

    /**
     * Determine whether the name is one the package declares.
     *
     * @param  string  $name
     * @return bool
     */
    public static function isDeclared(string $name): bool
    {
        return \array_key_exists($name, self::DESCRIPTIONS);
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
        foreach (\array_keys(self::DESCRIPTIONS) as $name) {
            if ($pattern === $name || \fnmatch($pattern, $name, \FNM_NOESCAPE)) {
                return true;
            }
        }

        return false;
    }
}
