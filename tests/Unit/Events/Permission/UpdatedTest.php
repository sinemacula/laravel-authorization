<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Permission;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Events\Permission\Updated;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for what an audit mapper reads from the event dispatched on
 * updating a permission.
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
     * The event is about the permission updated, names no grantee and reports
     * the changed fields before and after under dotted keys.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDescribesTheChangeForAnAuditMapper(): void
    {
        $permission = new Reference('permission', '5');
        $event      = new Updated(Operation::begin(), $permission, 'posts.update', null, self::tenant(), ['before' => ['name' => 'draft'], 'after' => ['name' => 'posts.update']]);

        self::assertDescribes($event, [
            'operation'   => 'permission.updated',
            'subject'     => $permission,
            'tenant'      => self::tenant(),
            'application' => null,
            'grantees'    => [],
            'properties'  => [
                'permission'          => 'permission:5',
                'name'                => 'posts.update',
                'guard'               => null,
                'changes.before.name' => 'draft',
                'changes.after.name'  => 'posts.update',
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
        self::assertDescribesTheCall(static fn (Operation $operation): Updated => new Updated(
            $operation,
            new Reference('permission', '5'),
            'posts.update',
            null,
            self::tenant(),
            ['before' => ['name' => 'draft'], 'after' => ['name' => 'posts.update']],
        ));
    }
}
