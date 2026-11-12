<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Role;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Events\Role\ExclusionEvent;
use SineMacula\Laravel\Authorization\Events\Role\ExclusionRemoved;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for the event removing a pair of mutually exclusive roles
 * dispatches.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExclusionRemoved::class)]
final class ExclusionRemovedTest extends TestCase
{
    use AssertsAuditAccessors;

    /**
     * The event is a final readonly change to a pair.
     *
     * @return void
     */
    public function testIsAFinalChangeToAPair(): void
    {
        $event = new ExclusionRemoved(Operation::begin(), new Reference('role', '1'), 'clerk', new Reference('role', '2'), 'auditor', null);

        self::assertInstanceOf(ExclusionEvent::class, $event);
        self::assertTrue((new \ReflectionClass($event))->isFinal());
        self::assertTrue((new \ReflectionClass($event))->isReadOnly());
    }

    /**
     * The event is about the pair's first role, holds where the pair's owner
     * is, in no one application, names no grantee, and reports the roles and
     * their names as plain details.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDescribesTheChangeForAnAuditMapper(): void
    {
        $role  = new Reference('role', '1');
        $event = new ExclusionRemoved(Operation::begin(), $role, 'clerk', new Reference('role', '2'), 'auditor', self::tenant());

        self::assertDescribes($event, [
            'operation'   => 'role.exclusion.removed',
            'subject'     => $role,
            'tenant'      => self::tenant(),
            'application' => null,
            'grantees'    => [],
            'properties'  => [
                'role'               => 'role:1',
                'role_name'          => 'clerk',
                'excluded_role'      => 'role:2',
                'excluded_role_name' => 'auditor',
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
        self::assertDescribesTheCall(static fn (Operation $operation): ExclusionRemoved => new ExclusionRemoved(
            $operation,
            new Reference('role', '1'),
            'clerk',
            new Reference('role', '2'),
            'auditor',
            null,
        ));
    }
}
