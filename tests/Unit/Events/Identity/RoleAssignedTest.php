<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Identity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Events\Identity\RoleAssigned;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for what an audit mapper reads from the event dispatched on
 * granting a role to a grantee.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RoleAssigned::class)]
final class RoleAssignedTest extends TestCase
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
        $event   = new RoleAssigned(Operation::begin(), $grantee, new Reference('role', '3'), 'editor', self::scope(), self::date());

        self::assertDescribes($event, [
            'operation'   => 'identity.role.assigned',
            'subject'     => $grantee,
            'tenant'      => self::tenant(),
            'application' => 'admin',
            'grantees'    => [$grantee],
            'properties'  => [
                'role'                  => 'role:3',
                'name'                  => 'editor',
                'scope.include_subtree' => false,
                'expires_at'            => '2026-01-02T01:04:05+00:00',
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
        self::assertDescribesTheCall(static fn (Operation $operation): RoleAssigned => new RoleAssigned(
            $operation,
            self::grantee(),
            new Reference('role', '3'),
            'editor',
            self::scope(),
            self::date(),
        ));
    }
}
