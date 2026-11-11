<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Policy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Events\Policy\Updated;
use SineMacula\Laravel\Authorization\Support\DocumentDigest;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for what an audit mapper reads from the event dispatched on
 * updating a policy.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Updated::class)]
final class UpdatedTest extends TestCase
{
    use AssertsAuditAccessors;

    /**
     * The event is about the policy updated, names no grantee and reports the
     * changed fields before and after under dotted keys.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDescribesTheChangeForAnAuditMapper(): void
    {
        $policy = new Reference('policy', '9');
        $event  = new Updated(
            Operation::begin(),
            $policy,
            'sharing',
            self::tenant(),
            ['before' => ['name' => 'draft'], 'after' => ['name' => 'sharing']],
            new DocumentDigest(2, 'def'),
            new DocumentDigest(1, 'abc'),
        );

        self::assertDescribes($event, [
            'operation'   => 'policy.updated',
            'subject'     => $policy,
            'tenant'      => self::tenant(),
            'application' => null,
            'grantees'    => [],
            'properties'  => [
                'policy'                    => 'policy:9',
                'name'                      => 'sharing',
                'changes.before.name'       => 'draft',
                'changes.after.name'        => 'sharing',
                'document.version'          => 2,
                'document.digest'           => 'def',
                'previous_document.version' => 1,
                'previous_document.digest'  => 'abc',
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
        self::assertDescribesTheCall(static fn (Operation $operation): Updated => new Updated(
            $operation,
            new Reference('policy', '9'),
            'sharing',
            self::tenant(),
            ['before' => ['name' => 'draft'], 'after' => ['name' => 'sharing']],
            new DocumentDigest(2, 'def'),
            new DocumentDigest(1, 'abc'),
        ));
    }
}
