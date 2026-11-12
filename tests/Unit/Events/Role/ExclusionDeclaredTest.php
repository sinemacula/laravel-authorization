<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Role;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Events\Role\ExclusionDeclared;
use SineMacula\Laravel\Authorization\Events\Role\ExclusionEvent;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for the event declaring a pair of mutually exclusive roles
 * dispatches.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExclusionDeclared::class)]
final class ExclusionDeclaredTest extends TestCase
{
    use AssertsAuditAccessors;

    /**
     * The event is a final readonly change to a pair.
     *
     * @return void
     */
    public function testIsAFinalChangeToAPair(): void
    {
        $event = new ExclusionDeclared(Operation::begin(), new Reference('role', '1'), 'clerk', new Reference('role', '2'), 'auditor', null);

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
        $event = new ExclusionDeclared(Operation::begin(), $role, 'clerk', new Reference('role', '2'), 'auditor', self::tenant());

        self::assertDescribes($event, [
            'operation'   => 'role.exclusion.declared',
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
        self::assertDescribesTheCall(static fn (Operation $operation): ExclusionDeclared => new ExclusionDeclared(
            $operation,
            new Reference('role', '1'),
            'clerk',
            new Reference('role', '2'),
            'auditor',
            null,
        ));
    }
}
