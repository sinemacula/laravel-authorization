<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Asserts what a change event's audit accessors return, for the tests of each
 * event class, and builds the references, scope and calls those tests share.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait AssertsAuditAccessors
{
    /**
     * Assert the event's operation identifier, subject, tenant, application,
     * grantees and details, each under its accessor's name in the expected map
     * (`properties` for the details), and that its details survive a JSON round
     * trip unchanged.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation  $event
     * @param  array<string, mixed>  $expected
     * @return void
     *
     * @throws \JsonException
     */
    protected static function assertDescribes(AuthorizationMutation $event, array $expected): void
    {
        self::assertSame($expected['operation'], $event->operation());
        self::assertEquals($expected['subject'], $event->subject());
        self::assertEquals($expected['tenant'], $event->tenant());
        self::assertSame($expected['application'], $event->application());
        self::assertEquals($expected['grantees'], $event->grantees());
        self::assertSame($expected['properties'], $event->auditProperties());
        self::assertSame($expected['properties'], \json_decode(\json_encode($event->auditProperties(), JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR));
    }

    /**
     * Assert what the event the factory makes reports of the call that made the
     * change, for each of three calls: trusted work a console command names, a
     * delegated call and a delegated call made while impersonating, each made
     * two hours ahead of UTC and the delegated ones from a client; and that the
     * client is reported by none of its accessors.
     *
     * @param  \Closure(\SineMacula\Laravel\Authorization\Support\Operation): \SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation  $make
     * @return void
     */
    protected static function assertDescribesTheCall(\Closure $make): void
    {
        $at           = new \DateTimeImmutable('2026-03-04T05:06:07+02:00');
        $command      = new Reference('command', 'authorization:sync');
        $principal    = new Reference('principal', '5');
        $identity     = new Reference('user', '5');
        $impersonator = new Reference('user', '1');
        [$ip, $agent] = ['203.0.113.9', 'Browser/1.0'];
        $calls        = [
            [new Operation('op-trusted', $command, $at), ['op-trusted', true, $command, null, null]],
            [new Operation('op-delegated', $principal, $at, false, $identity, null, [], $ip, $agent), ['op-delegated', false, $principal, $identity, null]],
            [new Operation('op-impersonated', $principal, $at, false, $identity, $impersonator, [], $ip, $agent), ['op-impersonated', false, $principal, $identity, $impersonator]],
        ];

        foreach ($calls as [$operation, $expected]) {
            $event = $make($operation);

            self::assertSame($expected, [$event->operationId(), $event->isTrusted(), $event->actor(), $event->actorIdentity(), $event->impersonator()]);
            self::assertSame('2026-03-04T03:06:07+00:00', $event->occurredAt()->format(\DATE_ATOM));
            self::assertSame('UTC', $event->occurredAt()->getTimezone()->getName());
            self::assertKeepsTheClientOut($event);
        }
    }

    /**
     * Assert that no accessor of the event, its details included, reports the
     * IP address or the user agent of the call that made the change: the client
     * is the grant hook's alone.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation  $event
     * @return void
     */
    protected static function assertKeepsTheClientOut(AuthorizationMutation $event): void
    {
        $reported = [];

        foreach ((new \ReflectionClass(AuthorizationMutation::class))->getMethods() as $method) {
            $reported[$method->getName()] = (new \ReflectionMethod($event, $method->getName()))->invoke($event);
        }

        self::assertArrayHasKey('auditProperties', $reported);
        self::assertStringNotContainsString('203.0.113.9', \serialize($reported));
        self::assertStringNotContainsString('Browser/1.0', \serialize($reported));
    }

    /**
     * Return the grantee the tests name.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    protected static function grantee(): Reference
    {
        return new Reference('user', '42');
    }

    /**
     * Return the tenant the tests name.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    protected static function tenant(): Reference
    {
        return new Reference('team', '7');
    }

    /**
     * Return a scope in the tenant and one application, reaching no tenant
     * below.
     *
     * @return \SineMacula\Laravel\Authorization\Support\GrantScope
     */
    protected static function scope(): GrantScope
    {
        return new GrantScope(self::tenant(), 'admin', false);
    }

    /**
     * Return a date two hours ahead of UTC, which the details report in UTC.
     *
     * @return \DateTimeImmutable
     */
    protected static function date(): \DateTimeImmutable
    {
        return new \DateTimeImmutable('2026-01-02T03:04:05+02:00');
    }
}
