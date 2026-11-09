<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;

/**
 * Unit tests for the permissions the package declares for its own services: the
 * administration actions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PackagePermissions::class)]
final class PackagePermissionsTest extends TestCase
{
    /** @var list<string> Every administration action, the right to preview and the review rights, in the catalogue's order. */
    private const array ACTIONS = [
        'authorization:role.grant',
        'authorization:role.revoke',
        'authorization:permission.grant',
        'authorization:permission.revoke',
        'authorization:policy.attach',
        'authorization:policy.detach',
        'authorization:role.create',
        'authorization:role.rename',
        'authorization:role.update',
        'authorization:role.delete',
        'authorization:role.parent.set',
        'authorization:permission.create',
        'authorization:permission.rename',
        'authorization:permission.update',
        'authorization:permission.delete',
        'authorization:policy.create',
        'authorization:policy.rename',
        'authorization:policy.update',
        'authorization:policy.delete',
        'authorization:boundary.set',
        'authorization:boundary.remove',
        'authorization:guardrail.manage',
        'authorization:resource-policy.attach',
        'authorization:resource-policy.detach',
        'authorization:role.read',
        'authorization:permission.read',
        'authorization:policy.read',
        'authorization:permission.grantable',
        'authorization:policy.grantable',
        'authorization:administration.self',
        'authorization:administration.impersonated',
        'authorization:administration.unbounded',
        'authorization:subject.preview',
        'authorization:review.read',
        'authorization:review.export',
    ];

    /**
     * The package declares every administration action, as a permission
     * provider: each spelt `authorization:<noun>.<verb>`, described,
     * guard-agnostic and filed under its own category.
     *
     * @return void
     */
    public function testDeclaresEveryAdministrationAction(): void
    {
        $permissions = new PackagePermissions;
        $definitions = $permissions->permissions();

        self::assertInstanceOf(PermissionProvider::class, $permissions);
        self::assertSame(self::ACTIONS, \array_map(static fn (PermissionDefinition $definition): string => $definition->name, $definitions));

        foreach ($definitions as $definition) {
            self::assertMatchesRegularExpression('/^authorization:[a-z-]+(\.[a-z]+)+$/', $definition->name);
            self::assertNotSame('', (string) $definition->description, $definition->name);
            self::assertSame('authorization', $definition->category, $definition->name);
            self::assertNull($definition->guard, $definition->name);
        }
    }

    /**
     * Each action's constant names it, the right to manage guardrails renamed
     * to `authorization:guardrail.manage`, the right to preview is
     * `authorization:subject.preview`, and the review rights are
     * `authorization:review.read` and `authorization:review.export`.
     *
     * @return void
     */
    public function testEachConstantNamesItsAction(): void
    {
        self::assertSame(self::ACTIONS, [
            PackagePermissions::ROLE_GRANT,
            PackagePermissions::ROLE_REVOKE,
            PackagePermissions::PERMISSION_GRANT,
            PackagePermissions::PERMISSION_REVOKE,
            PackagePermissions::POLICY_ATTACH,
            PackagePermissions::POLICY_DETACH,
            PackagePermissions::ROLE_CREATE,
            PackagePermissions::ROLE_RENAME,
            PackagePermissions::ROLE_UPDATE,
            PackagePermissions::ROLE_DELETE,
            PackagePermissions::ROLE_PARENT_SET,
            PackagePermissions::PERMISSION_CREATE,
            PackagePermissions::PERMISSION_RENAME,
            PackagePermissions::PERMISSION_UPDATE,
            PackagePermissions::PERMISSION_DELETE,
            PackagePermissions::POLICY_CREATE,
            PackagePermissions::POLICY_RENAME,
            PackagePermissions::POLICY_UPDATE,
            PackagePermissions::POLICY_DELETE,
            PackagePermissions::BOUNDARY_SET,
            PackagePermissions::BOUNDARY_REMOVE,
            PackagePermissions::GUARDRAIL_MANAGE,
            PackagePermissions::RESOURCE_POLICY_ATTACH,
            PackagePermissions::RESOURCE_POLICY_DETACH,
            PackagePermissions::ROLE_READ,
            PackagePermissions::PERMISSION_READ,
            PackagePermissions::POLICY_READ,
            PackagePermissions::PERMISSION_GRANTABLE,
            PackagePermissions::POLICY_GRANTABLE,
            PackagePermissions::ADMINISTRATION_SELF,
            PackagePermissions::ADMINISTRATION_IMPERSONATED,
            PackagePermissions::ADMINISTRATION_UNBOUNDED,
            PackagePermissions::SUBJECT_PREVIEW,
            PackagePermissions::REVIEW_READ,
            PackagePermissions::REVIEW_EXPORT,
        ]);
        self::assertSame('Preview what a subject may do, without acting as it.', (new PackagePermissions)->permissions()[32]->description);
        self::assertSame('Set and remove guardrails from above the scope they cap.', (new PackagePermissions)->permissions()[21]->description);
        self::assertSame('Run an access review of who holds what.', (new PackagePermissions)->permissions()[33]->description);
        self::assertSame('Export an access review.', (new PackagePermissions)->permissions()[34]->description);
    }

    /**
     * Only the name of a permission the package declares is one of its own:
     * never a pattern covering it, the old spelling of the guardrail right, nor
     * a name that differs in case.
     *
     * @return void
     */
    public function testTellsItsOwnNamesApart(): void
    {
        foreach (self::ACTIONS as $name) {
            self::assertTrue(PackagePermissions::isDeclared($name), $name);
        }

        foreach (['authorization:*', 'authorization:guardrails:manage', 'authorization:guardrail', 'AUTHORIZATION:GUARDRAIL.MANAGE', 'posts:create', ''] as $name) {
            self::assertFalse(PackagePermissions::isDeclared($name), $name);
        }
    }

    /**
     * A pattern covers the package's permissions when it is one of their names
     * or matches one as statements match actions, a backslash literally.
     *
     * @return void
     */
    public function testCoversItsOwnPermissionsByNameOrPattern(): void
    {
        $covering = ['authorization:guardrail.manage', 'authorization:*', 'authorization:guardrail.*', '*', 'authorization:guardrail.manag?'];

        foreach ([...$covering, 'authorization:administration.impersonated'] as $pattern) {
            self::assertTrue(PackagePermissions::covers($pattern), $pattern);
        }

        foreach (['authorization:roles:*', 'authorization:guardrails:manage', 'AUTHORIZATION:*', 'authorization\:*', 'posts:*', ''] as $pattern) {
            self::assertFalse(PackagePermissions::covers($pattern), $pattern);
        }
    }
}
