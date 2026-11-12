<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Policy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Events\Policy\Created;
use SineMacula\Laravel\Authorization\Support\DocumentDigest;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for what an audit mapper reads from the event dispatched on
 * creating a policy.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Created::class)]
final class CreatedTest extends TestCase
{
    use AssertsAuditAccessors;

    /**
     * The event is about the policy created, holds where its owning tenant is,
     * names no grantee and reports its details as plain values.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDescribesTheChangeForAnAuditMapper(): void
    {
        $policy = new Reference('policy', '9');
        $event  = new Created(Operation::begin(), $policy, 'sharing', self::tenant(), new DocumentDigest(1, 'abc'), true);

        self::assertDescribes($event, [
            'operation'   => 'policy.created',
            'subject'     => $policy,
            'tenant'      => self::tenant(),
            'application' => null,
            'grantees'    => [],
            'properties'  => [
                'policy'           => 'policy:9',
                'name'             => 'sharing',
                'document.version' => 1,
                'document.digest'  => 'abc',
                'is_system'        => true,
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
        self::assertDescribesTheCall(static fn (Operation $operation): Created => new Created(
            $operation,
            new Reference('policy', '9'),
            'sharing',
            self::tenant(),
            new DocumentDigest(1, 'abc'),
            true,
        ));
    }
}
