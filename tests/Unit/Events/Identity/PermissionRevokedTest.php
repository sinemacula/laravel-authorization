<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Identity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionRevoked;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for what an audit mapper reads from the event dispatched on
 * revoking a permission from a grantee.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PermissionRevoked::class)]
final class PermissionRevokedTest extends TestCase
{
    use AssertsAuditAccessors;

    /**
     * The event is about its grantee, holds in its scope's tenant and
     * application, and reports the permission, its name, its reach and its
     * dates as plain details.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDescribesTheChangeForAnAuditMapper(): void
    {
        $grantee = self::grantee();
        $event   = new PermissionRevoked(Operation::begin(), $grantee, new Reference('permission', '5'), 'posts.update', self::scope());

        self::assertDescribes($event, [
            'operation'   => 'identity.permission.revoked',
            'subject'     => $grantee,
            'tenant'      => self::tenant(),
            'application' => 'admin',
            'grantees'    => [$grantee],
            'properties'  => [
                'permission'            => 'permission:5',
                'name'                  => 'posts.update',
                'scope.include_subtree' => false,
            ],
        ]);
    }
}
