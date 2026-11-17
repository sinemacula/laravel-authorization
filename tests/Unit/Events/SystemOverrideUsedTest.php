<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation;
use SineMacula\Laravel\Authorization\Events\SystemOverrideUsed;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for the snapshot dispatched when `forceSystem()` unlocks a change
 * to a system record.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SystemOverrideUsed::class)]
final class SystemOverrideUsedTest extends TestCase
{
    /**
     * The event carries the operation, the record, its name before the change,
     * its tenant and the change the override allowed, as plain values, and is
     * no mutation event.
     *
     * @return void
     */
    public function testCarriesPlainValues(): void
    {
        $operation = Operation::begin(new Reference('admin', '1'));
        $record    = new Reference('role', 'role-1');
        $tenant    = new Reference('stub_tenant', 'tenant-a');
        $event     = new SystemOverrideUsed($operation, $record, 'owner', $tenant, 'rename');

        self::assertInstanceOf(AuthorizationEvent::class, $event);
        self::assertNotInstanceOf(AuthorizationMutation::class, $event);
        self::assertSame([$operation, $record, 'owner', $tenant, 'rename'], [$event->operation, $event->record, $event->name, $event->tenant, $event->protectedOperation]);
        self::assertNull((new SystemOverrideUsed($operation, $record, 'owner', null, 'delete'))->tenant);
    }
}
