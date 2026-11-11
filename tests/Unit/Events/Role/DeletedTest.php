<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Role;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Events\Role\Deleted;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for what an audit mapper reads from the event dispatched on
 * deleting a role.
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
     * The event is about the role deleted and names every grantee that lost it.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDescribesTheChangeForAnAuditMapper(): void
    {
        $grantee = self::grantee();
        $role    = new Reference('role', '3');
        $event   = new Deleted(Operation::begin(), $role, 'editor', 'web', self::tenant(), [$grantee], [new Reference('permission', '5')]);

        self::assertDescribes($event, [
            'operation'   => 'role.deleted',
            'subject'     => $role,
            'tenant'      => self::tenant(),
            'application' => null,
            'grantees'    => [$grantee],
            'properties'  => [
                'role'        => 'role:3',
                'name'        => 'editor',
                'guard'       => 'web',
                'permissions' => ['permission:5'],
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
            new Reference('role', '3'),
            'editor',
            'web',
            self::tenant(),
            [self::grantee()],
            [new Reference('permission', '5')],
        ));
    }
}
