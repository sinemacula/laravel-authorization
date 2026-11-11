<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Identity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyExpiryChanged;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for what an audit mapper reads from the event dispatched on
 * re-dating a grantee's policy.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PolicyExpiryChanged::class)]
final class PolicyExpiryChangedTest extends TestCase
{
    use AssertsAuditAccessors;

    /**
     * The event is about its grantee, holds in its scope's tenant and
     * application, and reports the policy, its name, its reach and its dates as
     * plain details.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDescribesTheChangeForAnAuditMapper(): void
    {
        $grantee = self::grantee();
        $event   = new PolicyExpiryChanged(Operation::begin(), $grantee, new Reference('policy', '9'), 'sharing', self::scope(), null, self::date());

        self::assertDescribes($event, [
            'operation'   => 'identity.policy.expiry_changed',
            'subject'     => $grantee,
            'tenant'      => self::tenant(),
            'application' => 'admin',
            'grantees'    => [$grantee],
            'properties'  => [
                'policy'                => 'policy:9',
                'name'                  => 'sharing',
                'scope.include_subtree' => false,
                'previous_expires_at'   => null,
                'expires_at'            => '2026-01-02T01:04:05+00:00',
            ],
        ]);
    }
}
