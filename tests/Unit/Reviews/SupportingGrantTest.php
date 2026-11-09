<?php

declare(strict_types = 1);

namespace Tests\Unit\Reviews;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Reviews\OriginScope;
use SineMacula\Laravel\Authorization\Reviews\SupportingGrant;

/**
 * Unit tests for one stored row a review row's route rests on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SupportingGrant::class)]
final class SupportingGrantTest extends TestCase
{
    /**
     * Its shape is its key, its scope and its expiry in UTC, none of them null
     * for an edge's scope and a grant that never expires.
     *
     * @return void
     */
    public function testItsShapeIsItsKeyScopeAndExpiry(): void
    {
        $grant = new SupportingGrant('k', new OriginScope('tenant', 't', null, true), CarbonImmutable::create(2030, 1, 1, 1, 0, 0, 'Europe/Paris'));

        self::assertSame(
            [
                'source_key' => 'k',
                'scope'      => ['tenant' => ['type' => 'tenant', 'id' => 't'], 'application' => null, 'include_subtree' => true],
                'expires_at' => '2030-01-01T00:00:00Z',
            ],
            $grant->toArray(),
        );
        self::assertSame(['source_key' => 'e', 'scope' => null, 'expires_at' => null], (new SupportingGrant('e', null, null))->toArray());
        self::assertSame(
            ['tenant' => ['type' => 'tenant', 'id' => null], 'application' => 'web', 'include_subtree' => false],
            (new SupportingGrant('h', new OriginScope('tenant', null, 'web', false), null))->toArray()['scope'],
        );
    }
}
