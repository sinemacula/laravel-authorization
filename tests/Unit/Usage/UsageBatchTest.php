<?php

declare(strict_types = 1);

namespace Tests\Unit\Usage;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Usage\UsageBatch;

/**
 * Unit tests for a batch of grant usage observations.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UsageBatch::class)]
final class UsageBatchTest extends TestCase
{
    /**
     * A batch keeps its observations, as plain values that survive being
     * serialised for the queue, and the instant it was flushed at.
     *
     * @return void
     */
    public function testABatchSurvivesTheQueue(): void
    {
        $observation = [
            'grant_key'         => 'k',
            'grant_source'      => 'role',
            'grant_id'          => 'r',
            'authorizable_type' => 'user',
            'authorizable_id'   => 'u',
            'tenant_type'       => null,
            'tenant_id'         => null,
            'application'       => null,
            'grant_created_at'  => 1,
            'last_observed_at'  => 3600,
        ];

        $batch = \unserialize(\serialize(new UsageBatch([$observation], 3700)));

        self::assertInstanceOf(UsageBatch::class, $batch);
        self::assertSame([[$observation], 3700], [$batch->observations, $batch->at]);
    }
}
