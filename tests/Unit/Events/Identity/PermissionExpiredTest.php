<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Identity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionExpired;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for what an audit mapper reads from the event dispatched on
 * pruning a grantee's expired permission.
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
        $event   = new PermissionExpired(Operation::begin(), $grantee, new Reference('permission', '5'), 'posts.update', self::scope(), self::date());

        self::assertDescribes($event, [
            'operation'   => 'identity.permission.expired',
            'subject'     => $grantee,
            'tenant'      => self::tenant(),
            'application' => 'admin',
            'grantees'    => [$grantee],
            'properties'  => [
                'permission'            => 'permission:5',
                'name'                  => 'posts.update',
                'scope.include_subtree' => false,
                'expired_at'            => '2026-01-02T01:04:05+00:00',
            ],
        ]);
    }

    /**
     * The event reports the call that made the change, trusted or delegated,
     * with or without an impersonator, and never its client.
     *
     * @return void
     */
    public function testDescribesTheCallForAnAuditMapper(): void
    {
        self::assertDescribesTheCall(static fn (Operation $operation): PermissionExpired => new PermissionExpired(
            $operation,
            self::grantee(),
            new Reference('permission', '5'),
            'posts.update',
            self::scope(),
            self::date(),
        ));
    }
}
