<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Concerns;

use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation;
use SineMacula\Laravel\Authorization\Events\Concerns\DescribesOperation;
use SineMacula\Laravel\Authorization\Events\Guardrail\GuardrailSet;
use SineMacula\Laravel\Authorization\Events\Identity\RoleAssigned;
use SineMacula\Laravel\Authorization\Events\Resource\PolicyAttached;
use SineMacula\Laravel\Authorization\Events\Role\Created as RoleCreated;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for the audit accessors every change event shares for the call
 * that made the change.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(DescribesOperation::class)]
final class DescribesOperationTest extends TestCase
{
    use AssertsAuditAccessors;

    /**
     * An event of each family reports the call's id, whether it was trusted,
     * its actor, the identity behind the actor, any impersonator and its time
     * in UTC, for trusted work and for a delegated call with and without an
     * impersonator.
     *
     * @return void
     */
    public function testDescribesTheCallForEveryFamily(): void
    {
        foreach (self::factories() as $make) {
            self::assertDescribesTheCall($make);
        }
    }

    /**
     * A call made by system work names no actor, no identity and no
     * impersonator, and an operation begun now is reported at the same instant,
     * in UTC.
     *
     * @return void
     */
    public function testDescribesSystemWork(): void
    {
        $operation = Operation::begin();
        $event     = new RoleCreated($operation, new Reference('role', '3'), 'editor', null, null, false);

        self::assertSame($operation->id, $event->operationId());
        self::assertTrue($event->isTrusted());
        self::assertSame([null, null, null], [$event->actor(), $event->actorIdentity(), $event->impersonator()]);
        self::assertSame($operation->at->getTimestamp(), $event->occurredAt()->getTimestamp());
        self::assertSame('UTC', $event->occurredAt()->getTimezone()->getName());
    }

    /**
     * The call's IP address and user agent, carried by the event's operation,
     * are reported by no accessor and appear nowhere in the details: the
     * contract names no accessor for them, and an event of each family made
     * from a call with a client keeps it out.
     *
     * @return void
     */
    public function testNeverReportsTheClient(): void
    {
        $methods = \array_map(static fn (\ReflectionMethod $method): string => $method->getName(), (new \ReflectionClass(AuthorizationMutation::class))->getMethods());
        $client  = new Operation('op-client', new Reference('principal', '5'), new \DateTimeImmutable('2026-03-04T05:06:07Z'), false, null, null, [], '203.0.113.9', 'Browser/1.0');

        self::assertSame([], \preg_grep('/^ip|address|agent|client/i', $methods));

        foreach (self::factories() as $make) {
            $event = $make($client);

            self::assertStringContainsString('203.0.113.9', \serialize($event));
            self::assertStringContainsString('Browser/1.0', \serialize($event));
            self::assertSame([], \preg_grep('/(^|[._])(ip|user_agent|client)($|[._])/', \array_keys($event->auditProperties())));
            self::assertKeepsTheClientOut($event);
        }
    }

    /**
     * Return a factory for an event of each family: a grant, a record, a
     * resource policy and a guardrail event.
     *
     * @return list<\Closure(\SineMacula\Laravel\Authorization\Support\Operation): \SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation>
     */
    private static function factories(): array
    {
        $policy = new Reference('policy', '9');

        return [
            static fn (Operation $operation): RoleAssigned => new RoleAssigned($operation, self::grantee(), new Reference('role', '3'), 'editor', self::scope(), null),
            static fn (Operation $operation): RoleCreated => new RoleCreated($operation, new Reference('role', '3'), 'editor', 'web', self::tenant(), false),
            static fn (Operation $operation): PolicyAttached => new PolicyAttached($operation, 'posts', '7', $policy, 'sharing', GrantScope::platform()),
            static fn (Operation $operation): GuardrailSet => new GuardrailSet($operation, $policy, 'cap', GrantScope::platform()),
        ];
    }
}
