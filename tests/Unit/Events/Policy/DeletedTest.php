<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Policy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Events\Policy\Deleted;
use SineMacula\Laravel\Authorization\Support\DocumentDigest;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for what an audit mapper reads from the event dispatched on
 * deleting a policy.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Deleted::class)]
final class DeletedTest extends TestCase
{
    use AssertsAuditAccessors;

    /**
     * The event is about the policy deleted and names every grantee that lost
     * it.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDescribesTheChangeForAnAuditMapper(): void
    {
        $grantee = self::grantee();
        $policy  = new Reference('policy', '9');
        $event   = new Deleted(Operation::begin(), $policy, 'sharing', self::tenant(), new DocumentDigest(1, 'abc'), [$grantee]);

        self::assertDescribes($event, [
            'operation'   => 'policy.deleted',
            'subject'     => $policy,
            'tenant'      => self::tenant(),
            'application' => null,
            'grantees'    => [$grantee],
            'properties'  => [
                'policy'           => 'policy:9',
                'name'             => 'sharing',
                'document.version' => 1,
                'document.digest'  => 'abc',
            ],
        ]);
    }
}
