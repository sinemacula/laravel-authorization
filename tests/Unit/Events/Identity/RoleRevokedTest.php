<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Identity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Events\Identity\RoleRevoked;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for what an audit mapper reads from the event dispatched on
 * revoking a role from a grantee.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RoleRevoked::class)]
final class RoleRevokedTest extends TestCase
{
    use AssertsAuditAccessors;

    /**
     * The event is about its grantee, holds in its scope's tenant and
     * application, and reports the role, its name, its reach and its dates as
     * plain details.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDescribesTheChangeForAnAuditMapper(): void
    {
        $grantee = self::grantee();
        $event   = new RoleRevoked(Operation::begin(), $grantee, new Reference('role', '3'), 'editor', self::scope());

        self::assertDescribes($event, [
            'operation'   => 'identity.role.revoked',
            'subject'     => $grantee,
            'tenant'      => self::tenant(),
            'application' => 'admin',
            'grantees'    => [$grantee],
            'properties'  => ['role' => 'role:3', 'name' => 'editor', 'scope.include_subtree' => false],
        ]);
    }
}
