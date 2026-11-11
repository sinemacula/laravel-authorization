<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Role;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Events\Role\Created;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for what an audit mapper reads from the event dispatched on
 * creating a role.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Created::class)]
final class CreatedTest extends TestCase
{
    use AssertsAuditAccessors;

    /**
     * The event is about the role created, holds where its owning tenant is,
     * names no grantee and reports its details as plain values.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDescribesTheChangeForAnAuditMapper(): void
    {
        $role  = new Reference('role', '3');
        $event = new Created(Operation::begin(), $role, 'editor', 'web', self::tenant(), true);

        self::assertDescribes($event, [
            'operation'   => 'role.created',
            'subject'     => $role,
            'tenant'      => self::tenant(),
            'application' => null,
            'grantees'    => [],
            'properties'  => ['role' => 'role:3', 'name' => 'editor', 'guard' => 'web', 'is_system' => true],
        ]);
    }
}
