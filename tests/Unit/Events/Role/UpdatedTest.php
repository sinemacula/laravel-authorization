<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Role;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Events\Role\Updated;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for what an audit mapper reads from the event dispatched on
 * updating a role.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Updated::class)]
final class UpdatedTest extends TestCase
{
    use AssertsAuditAccessors;

    /**
     * The event is about the role updated, names no grantee and reports the
     * changed fields before and after under dotted keys.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDescribesTheChangeForAnAuditMapper(): void
    {
        $role  = new Reference('role', '3');
        $event = new Updated(Operation::begin(), $role, 'editor', null, self::tenant(), ['before' => ['name' => 'draft'], 'after' => ['name' => 'editor']]);

        self::assertDescribes($event, [
            'operation'   => 'role.updated',
            'subject'     => $role,
            'tenant'      => self::tenant(),
            'application' => null,
            'grantees'    => [],
            'properties'  => [
                'role'                => 'role:3',
                'name'                => 'editor',
                'guard'               => null,
                'changes.before.name' => 'draft',
                'changes.after.name'  => 'editor',
            ],
        ]);
    }
}
