<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\SystemPermissionProtectedException;
use SineMacula\Laravel\Authorization\Exceptions\SystemPolicyProtectedException;
use SineMacula\Laravel\Authorization\Exceptions\SystemRecordProtectedException;
use SineMacula\Laravel\Authorization\Exceptions\SystemRoleProtectedException;

/**
 * Unit tests for the system-record protection exceptions: one message, code and
 * pair of accessors shared by the role, permission and policy kinds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SystemRecordProtectedException::class)]
#[CoversClass(SystemRoleProtectedException::class)]
#[CoversClass(SystemPermissionProtectedException::class)]
#[CoversClass(SystemPolicyProtectedException::class)]
final class SystemRecordProtectedExceptionTest extends TestCase
{
    /**
     * One exception class of each kind, with the record it refuses.
     *
     * The exceptions are built in the test, not here, so their construction is
     * measured as the test's coverage.
     *
     * @return iterable<string, array{0: class-string<\SineMacula\Laravel\Authorization\Exceptions\SystemRecordProtectedException>, 1: string, 2: string}>
     */
    public static function exceptions(): iterable
    {
        yield 'role' => [SystemRoleProtectedException::class, 'role', 'owner'];
        yield 'permission' => [SystemPermissionProtectedException::class, 'permission', '*'];
        yield 'policy' => [SystemPolicyProtectedException::class, 'policy', 'break-glass'];
    }

    /**
     * Each kind of record names itself in the message and exposes the record
     * name and the refused operation.
     *
     * @param  class-string<\SineMacula\Laravel\Authorization\Exceptions\SystemRecordProtectedException>  $class
     * @param  string  $kind
     * @param  string  $name
     * @return void
     */
    #[DataProvider('exceptions')]
    public function testMessageCodeAndAccessors(string $class, string $kind, string $name): void
    {
        $exception = new $class($name, 'delete');

        self::assertSame(
            "Refusing to delete system {$kind} '{$name}'. Call `forceSystem()` on the model before the operation to override.",
            $exception->getMessage(),
        );
        self::assertSame(403, $exception->getCode());
        self::assertSame($name, $exception->getRecordName());
        self::assertSame('delete', $exception->getOperation());
    }

    /**
     * Each kind keeps its own name accessor.
     *
     * @return void
     */
    public function testKindSpecificNameAccessors(): void
    {
        self::assertSame('owner', (new SystemRoleProtectedException('owner', 'modify'))->getRoleName());
        self::assertSame('*', (new SystemPermissionProtectedException('*', 'modify'))->getPermissionName());
        self::assertSame('break-glass', (new SystemPolicyProtectedException('break-glass', 'modify'))->getPolicyName());
    }
}
