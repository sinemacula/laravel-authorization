<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\BoundaryException;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for the refusals the permission boundary rules raise.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BoundaryException::class)]
final class BoundaryExceptionTest extends TestCase
{
    /**
     * An inline policy is refused by name, naming no grantee.
     *
     * @return void
     */
    public function testInline(): void
    {
        $exception = BoundaryException::inline('mine');

        self::assertInstanceOf(\LogicException::class, $exception);
        self::assertSame('Inline policy \'mine\' belongs to one grantee and cannot be set as a boundary; set a managed policy.', $exception->getMessage());
        self::assertSame('mine', $exception->getPolicyName());
        self::assertSame([], $exception->getGrantees());
    }

    /**
     * A boundary set on a grantee that is never a subject is refused, naming
     * the grantee and its kind.
     *
     * @return void
     */
    public function testNotASubject(): void
    {
        $role      = new Reference('role', 'role-1');
        $exception = BoundaryException::notASubject('cap', $role, 'role');

        self::assertSame('Policy \'cap\' cannot be set as the boundary of role \'role-1\': a boundary caps a principal or an identity, never a role.', $exception->getMessage());
        self::assertSame('cap', $exception->getPolicyName());
        self::assertSame([$role], $exception->getGrantees());

        $permission = BoundaryException::notASubject('cap', new Reference('permission', 'p-1'), 'permission');
        $message    = 'Policy \'cap\' cannot be set as the boundary of permission \'p-1\': a boundary caps a principal or an identity, never a permission.';

        self::assertSame($message, $permission->getMessage());
    }

    /**
     * The deletion of a policy in use as a boundary is refused, naming every
     * grantee it bounds.
     *
     * @return void
     */
    public function testInUse(): void
    {
        $grantees  = [new Reference('user', 'user-1'), new Reference('member', 'm-1')];
        $exception = BoundaryException::inUse('cap', $grantees);

        self::assertSame('Policy \'cap\' is the boundary of user:user-1, member:m-1; remove each boundary before deleting the policy.', $exception->getMessage());
        self::assertSame('cap', $exception->getPolicyName());
        self::assertSame($grantees, $exception->getGrantees());
    }
}
