<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Role;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Events\Role\PermissionExpired;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for what an audit mapper reads from the event dispatched on
 * pruning a role's expired permission.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PermissionExpired::class)]
final class PermissionExpiredTest extends TestCase
{
    use AssertsAuditAccessors;

    /**
     * The event is about the role, whose access changed, holds where the role's
     * owning tenant is, and reports the permission, the names and the dates as
     * plain details.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDescribesTheChangeForAnAuditMapper(): void
    {
        $role  = new Reference('role', '3');
        $event = new PermissionExpired(Operation::begin(), $role, 'editor', new Reference('permission', '5'), 'posts.update', self::tenant(), self::date());

        self::assertDescribes($event, [
            'operation'   => 'role.permission.expired',
            'subject'     => $role,
            'tenant'      => self::tenant(),
            'application' => null,
            'grantees'    => [$role],
            'properties'  => [
                'role'            => 'role:3',
                'role_name'       => 'editor',
                'permission'      => 'permission:5',
                'permission_name' => 'posts.update',
                'expired_at'      => '2026-01-02T01:04:05+00:00',
            ],
        ]);
    }
}
