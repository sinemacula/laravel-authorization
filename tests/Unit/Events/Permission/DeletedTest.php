<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Permission;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Events\Permission\Deleted;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for what an audit mapper reads from the event dispatched on
 * deleting a permission.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Deleted::class)]
final class DeletedTest extends TestCase
{
    use AssertsAuditAccessors;

    /**
     * The event is about the permission deleted and names every grantee that
     * lost it, each direct grantee in order and then each role that carried it.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDescribesTheChangeForAnAuditMapper(): void
    {
        $grantee    = self::grantee();
        $other      = new Reference('user', '43');
        $permission = new Reference('permission', '5');
        $role       = new Reference('role', '3');
        $otherRole  = new Reference('role', '4');
        $event      = new Deleted(Operation::begin(), $permission, 'posts.update', 'web', self::tenant(), [$grantee, $other], [$role, $otherRole]);

        self::assertDescribes($event, [
            'operation'   => 'permission.deleted',
            'subject'     => $permission,
            'tenant'      => self::tenant(),
            'application' => null,
            'grantees'    => [$grantee, $other, $role, $otherRole],
            'properties'  => [
                'permission' => 'permission:5',
                'name'       => 'posts.update',
                'guard'      => 'web',
                'roles'      => ['role:3', 'role:4'],
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
        self::assertDescribesTheCall(static fn (Operation $operation): Deleted => new Deleted(
            $operation,
            new Reference('permission', '5'),
            'posts.update',
            'web',
            self::tenant(),
            [self::grantee(), new Reference('user', '43')],
            [new Reference('role', '3'), new Reference('role', '4')],
        ));
    }
}
