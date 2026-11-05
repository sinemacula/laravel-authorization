<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\OwnerMismatchException;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for the refusal of a permission or parent another tenant owns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OwnerMismatchException::class)]
final class OwnerMismatchExceptionTest extends TestCase
{
    /**
     * An owner mismatch names the role, what it would take, and both owners.
     *
     * @return void
     */
    public function testAnOwnerMismatchNamesBothOwners(): void
    {
        $tenantA = new Reference('organisation', 'org-a');
        $tenantB = new Reference('organisation', 'org-b');

        $platform = new OwnerMismatchException('editor', null, 'permission', 'posts:own', $tenantA);
        $tenant   = new OwnerMismatchException('author', $tenantB, 'parent role', 'owner', $tenantA);

        self::assertSame(
            'Role \'editor\', owned by the platform, cannot take permission \'posts:own\', owned by tenant \'organisation:org-a\':'
                . ' a role takes only the platform\'s and its own tenant\'s.',
            $platform->getMessage(),
        );
        self::assertSame(
            'Role \'author\', owned by tenant \'organisation:org-b\', cannot take parent role \'owner\','
                . ' owned by tenant \'organisation:org-a\': a role takes only the platform\'s and its own tenant\'s.',
            $tenant->getMessage(),
        );
        self::assertSame('author', $tenant->getRoleName());
        self::assertSame($tenantB, $tenant->getRoleOwner());
        self::assertSame('parent role', $tenant->getRelatedKind());
        self::assertSame('owner', $tenant->getRelatedName());
        self::assertSame($tenantA, $tenant->getRelatedOwner());
    }
}
