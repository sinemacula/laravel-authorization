<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\RoleHasChildrenException;

/**
 * Unit tests for the refusal to delete a role with children.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RoleHasChildrenException::class)]
final class RoleHasChildrenExceptionTest extends TestCase
{
    /**
     * The message names the role and each child, and the accessors return them.
     *
     * @return void
     */
    public function testNamesTheRoleAndItsChildren(): void
    {
        $exception = new RoleHasChildrenException('admin', ['author', 'editor']);

        self::assertSame('Role \'admin\' has children (\'author\', \'editor\') and cannot be deleted; move them to another parent or delete them first.', $exception->getMessage());
        self::assertSame('admin', $exception->getRoleName());
        self::assertSame(['author', 'editor'], $exception->getChildNames());
    }
}
