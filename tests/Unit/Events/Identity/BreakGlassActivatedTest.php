<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Identity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Events\Identity\BreakGlassActivated;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for what an audit mapper reads from the event dispatched on
 * activating break-glass access for a grantee.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BreakGlassActivated::class)]
final class BreakGlassActivatedTest extends TestCase
{
    use AssertsAuditAccessors;

    /**
     * The event is about its grantee, holds in its scope's tenant and
     * application, and reports the role, its name, its reach, the activation,
     * the justification code and the expiry as plain details, with no note.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDescribesTheChangeForAnAuditMapper(): void
    {
        $grantee = self::grantee();
        $event   = self::event(Operation::begin());

        self::assertDescribes($event, [
            'operation'   => 'identity.break_glass.activated',
            'subject'     => $grantee,
            'tenant'      => self::tenant(),
            'application' => 'admin',
            'grantees'    => [$grantee],
            'properties'  => [
                'role'                  => 'role:3',
                'name'                  => 'responder',
                'scope.include_subtree' => false,
                'activation'            => 'a1b2',
                'justification'         => 'incident',
                'expires_at'            => '2026-01-02T01:04:05+00:00',
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
        self::assertDescribesTheCall(self::event(...));
    }

    /**
     * Return the event the tests describe, made by the operation.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @return \SineMacula\Laravel\Authorization\Events\Identity\BreakGlassActivated
     */
    private static function event(Operation $operation): BreakGlassActivated
    {
        return new BreakGlassActivated($operation, self::grantee(), new Reference('role', '3'), 'responder', self::scope(), 'a1b2', 'incident', self::date());
    }
}
