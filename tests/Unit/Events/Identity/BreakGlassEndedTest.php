<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Identity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation;
use SineMacula\Laravel\Authorization\Contracts\IdentityEvent;
use SineMacula\Laravel\Authorization\Events\Identity\BreakGlassEnded;
use SineMacula\Laravel\Authorization\Events\Identity\BreakGlassRevoked;
use SineMacula\Laravel\Authorization\Events\Identity\BreakGlassSurrendered;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for what every break-glass activation ended before its expiry
 * carries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BreakGlassEnded::class)]
final class BreakGlassEndedTest extends TestCase
{
    use AssertsAuditAccessors;

    /**
     * The shared shape is an abstract readonly grant event, never dispatched
     * itself, that the surrendered and revoked events extend.
     *
     * @return void
     */
    public function testIsTheAbstractShapeBothEventsShare(): void
    {
        $reflection = new \ReflectionClass(BreakGlassEnded::class);

        self::assertTrue($reflection->isAbstract());
        self::assertTrue($reflection->isReadOnly());
        self::assertTrue($reflection->implementsInterface(IdentityEvent::class));
        self::assertTrue($reflection->implementsInterface(AuthorizationMutation::class));

        foreach ([BreakGlassSurrendered::class, BreakGlassRevoked::class] as $class) {
            $parent = (new \ReflectionClass($class))->getParentClass();

            self::assertNotFalse($parent);
            self::assertSame(BreakGlassEnded::class, $parent->getName());
        }
    }

    /**
     * Each event carries the operation, the grantee, the role, its name, the
     * scope, the activation and when it ended.
     *
     * @return void
     */
    public function testCarriesTheActivationAndWhenItEnded(): void
    {
        $operation = Operation::begin();
        $role      = new Reference('role', '3');

        foreach ([BreakGlassSurrendered::class, BreakGlassRevoked::class] as $class) {
            $event = new $class($operation, self::grantee(), $role, 'responder', self::scope(), 'a1b2', self::date());

            self::assertSame(
                [$operation, $role, 'responder', 'a1b2', self::date()->format(\DATE_ATOM)],
                [$event->operation, $event->role, $event->name, $event->activation, $event->endedAt->format(\DATE_ATOM)],
            );
            self::assertEquals([self::grantee(), self::scope()], [$event->grantee, $event->scope]);
        }
    }
}
