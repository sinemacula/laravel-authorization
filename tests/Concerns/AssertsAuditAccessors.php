<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Asserts what a change event's audit accessors return, for the tests of each
 * event class, and builds the references and scope those tests share.
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
