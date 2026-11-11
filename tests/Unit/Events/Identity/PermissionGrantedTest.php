<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Identity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionGranted;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for what an audit mapper reads from the event dispatched on
 * granting a permission to a grantee directly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PermissionGranted::class)]
final class PermissionGrantedTest extends TestCase
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
        $event   = new PermissionGranted(Operation::begin(), $grantee, new Reference('permission', '5'), 'posts.update', self::scope(), self::date());

        self::assertDescribes($event, [
            'operation'   => 'identity.permission.granted',
            'subject'     => $grantee,
            'tenant'      => self::tenant(),
            'application' => 'admin',
            'grantees'    => [$grantee],
            'properties'  => [
                'permission'            => 'permission:5',
                'name'                  => 'posts.update',
                'scope.include_subtree' => false,
                'expires_at'            => '2026-01-02T01:04:05+00:00',
            ],
        ]);
    }
}
