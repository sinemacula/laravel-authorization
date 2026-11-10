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
     * A batch holds each stored grant once and each observation as its key, its
     * grant's index and its bucket, survives being serialised for the queue,
     * and gives each observation back whole, with the instant it was flushed at
     * and the earliest bucket dropped before it.
     *
     * @return void
     */
    public function testABatchIsCompactAndSurvivesTheQueue(): void
    {
        $observation = static fn (string $key, string $grantee, int $bucket): array => [
            'grant_key'         => $key,
            'grant_source'      => 'role',
            'grant_id'          => 'r',
            'authorizable_type' => 'user',
            'authorizable_id'   => $grantee,
            'tenant_type'       => null,
            'tenant_id'         => null,
            'application'       => 'web',
            'grant_created_at'  => 1,
            'last_observed_at'  => $bucket,
        ];

        $observations = [$observation('k1', 'u', 3600), $observation('k2', 'v', 3600), $observation('k3', 'u', 7200)];
        $batch        = \unserialize(\serialize(UsageBatch::of($observations, 7300, 0)));

        self::assertInstanceOf(UsageBatch::class, $batch);
        self::assertSame([['role', 'r', 'user', 'u', null, null, 'web', 1], ['role', 'r', 'user', 'v', null, null, 'web', 1]], $batch->grants);
        self::assertSame([['k1', 0, 3600], ['k2', 1, 3600], ['k3', 0, 7200]], $batch->routes);
        self::assertSame([$observations, 7300, 0], [$batch->observations(), $batch->at, $batch->lostSince]);
        self::assertNull(UsageBatch::of([], 1)->lostSince);
        self::assertSame([], UsageBatch::of([], 1)->observations());
    }
}
