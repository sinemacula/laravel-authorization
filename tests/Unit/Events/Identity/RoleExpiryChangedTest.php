<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Identity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Events\Identity\RoleExpiryChanged;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for what an audit mapper reads from the event dispatched on
 * re-dating a grantee's role.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RoleExpiryChanged::class)]
final class RoleExpiryChangedTest extends TestCase
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
        $event   = new RoleExpiryChanged(Operation::begin(), $grantee, new Reference('role', '3'), 'editor', self::scope(), null, self::date());

        self::assertDescribes($event, [
            'operation'   => 'identity.role.expiry_changed',
            'subject'     => $grantee,
            'tenant'      => self::tenant(),
            'application' => 'admin',
            'grantees'    => [$grantee],
            'properties'  => [
                'role'                  => 'role:3',
                'name'                  => 'editor',
                'scope.include_subtree' => false,
                'previous_expires_at'   => null,
                'expires_at'            => '2026-01-02T01:04:05+00:00',
            ],
        ]);
    }
}
