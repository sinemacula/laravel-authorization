<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Guardrail;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Events\Guardrail\GuardrailEvent;
use SineMacula\Laravel\Authorization\Events\Guardrail\GuardrailRemoved;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for the event removing a guardrail dispatches.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GuardrailRemoved::class)]
final class GuardrailRemovedTest extends TestCase
{
    use AssertsAuditAccessors;

    /**
     * The event is a final readonly guardrail event carrying the operation, the
     * policy, its name and the platform scope it holds in.
     *
     * @return void
     */
    public function testCarriesWhatEveryGuardrailChangeCarries(): void
    {
        $operation = Operation::begin(new Reference('admin', '1'));
        $policy    = new Reference('policy', 'policy-1');
        $event     = new GuardrailRemoved($operation, $policy, 'platform-cap', GrantScope::platform());

        self::assertInstanceOf(GuardrailEvent::class, $event);
        self::assertTrue((new \ReflectionClass($event))->isFinal());
        self::assertTrue((new \ReflectionClass($event))->isReadOnly());
        self::assertSame($operation, $event->operation);
        self::assertSame($policy, $event->policy);
        self::assertSame('platform-cap', $event->name);
        self::assertNull($event->scope->tenant);
        self::assertTrue($event->scope->includeSubtree);
    }

    /**
     * The event about a platform guardrail has no subject or tenant, names no
     * grantee, and reports the policy, its name and its reach as plain details.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDescribesTheChangeForAnAuditMapper(): void
    {
        $event = new GuardrailRemoved(Operation::begin(), new Reference('policy', '9'), 'cap', GrantScope::platform());

        self::assertDescribes($event, [
            'operation'   => 'guardrail.removed',
            'subject'     => null,
            'tenant'      => null,
            'application' => null,
            'grantees'    => [],
            'properties'  => ['policy' => 'policy:9', 'name' => 'cap', 'scope.include_subtree' => true],
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
        self::assertDescribesTheCall(static fn (Operation $operation): GuardrailRemoved => new GuardrailRemoved(
            $operation,
            new Reference('policy', '9'),
            'cap',
            GrantScope::platform(),
        ));
    }
}
