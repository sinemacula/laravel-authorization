<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Permission;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Events\Permission\Created;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for what an audit mapper reads from the event dispatched on
 * creating a permission.
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
     * The event is about the permission created, holds where its owning tenant
     * is, names no grantee and reports its details as plain values.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDescribesTheChangeForAnAuditMapper(): void
    {
        $permission = new Reference('permission', '5');
        $event      = new Created(Operation::begin(), $permission, 'posts.update', 'web', self::tenant(), true);

        self::assertDescribes($event, [
            'operation'   => 'permission.created',
            'subject'     => $permission,
            'tenant'      => self::tenant(),
            'application' => null,
            'grantees'    => [],
            'properties'  => [
                'permission' => 'permission:5',
                'name'       => 'posts.update',
                'guard'      => 'web',
                'is_system'  => true,
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
        self::assertDescribesTheCall(static fn (Operation $operation): Created => new Created(
            $operation,
            new Reference('permission', '5'),
            'posts.update',
            'web',
            self::tenant(),
            true,
        ));
    }
}
