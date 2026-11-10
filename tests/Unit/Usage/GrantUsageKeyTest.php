<?php

declare(strict_types = 1);

namespace Tests\Unit\Usage;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Reviews\Enums\GrantState;
use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
use SineMacula\Laravel\Authorization\Reviews\OriginScope;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Reviews\Support\GrantRow;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Usage\GrantUsageKey;

/**
 * Unit tests for the key grant usage is recorded under.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantUsageKey::class)]
final class GrantUsageKeyTest extends TestCase
{
    /**
     * The key is a SHA-256 digest of every part, so changing any part changes
     * it, and none can stand in for another; the stored grant's reach and
     * expiry are no part of it.
     *
     * @return void
     */
    public function testEveryPartChangesTheKey(): void
    {
        $target  = new Reference('permission', 'p');
        $grantee = new Reference('user', 'u');
        $key     = GrantUsageKey::of(SourceKind::ROLE_PERMISSION, $target, $grantee, ['tenant', 't', 'web'], ['r1', 'r2']);

        $others = [
            GrantUsageKey::of(SourceKind::PERMISSION_GRANT, $target, $grantee, ['tenant', 't', 'web'], ['r1', 'r2']),
            GrantUsageKey::of(SourceKind::ROLE_PERMISSION, new Reference('permission', 'q'), $grantee, ['tenant', 't', 'web'], ['r1', 'r2']),
            GrantUsageKey::of(SourceKind::ROLE_PERMISSION, $target, new Reference('user', 'v'), ['tenant', 't', 'web'], ['r1', 'r2']),
            GrantUsageKey::of(SourceKind::ROLE_PERMISSION, $target, $grantee, ['tenant', 't', null], ['r1', 'r2']),
            GrantUsageKey::of(SourceKind::ROLE_PERMISSION, $target, $grantee, [null, 't', 'web'], ['r1', 'r2']),
            GrantUsageKey::of(SourceKind::ROLE_PERMISSION, $target, $grantee, ['tenant', 't', 'web'], ['r1']),
            GrantUsageKey::of(SourceKind::ROLE_PERMISSION, $target, $grantee, ['tenant', 't', 'web'], ['r1r2']),
        ];

        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $key);
        self::assertCount(\count($others), \array_unique($others));
        self::assertNotContains($key, $others);
    }

    /**
     * A review row and the stored row it starts from give the route the same
     * key, whatever the row's reach and expiry.
     *
     * @return void
     */
    public function testARowAndItsStoredGrantGiveTheSameKey(): void
    {
        $times  = ['expires_at' => CarbonImmutable::create(2030), 'created_at' => null, 'updated_at' => null];
        $start  = new GrantRow('role', 'r1', new Reference('user', 'u'), new GrantScope(new Reference('tenant', 't'), 'web', false), $times, null);
        $target = new Reference('permission', 'p');
        $row    = new ReviewRow(
            'row',
            new Reference('user', 'u'),
            new Reference('user', 'u'),
            $target,
            SourceKind::ROLE_PERMISSION,
            $start->key(),
            new OriginScope('tenant', 't', 'web', true),
            null,
            [new Reference('role', 'r1'), new Reference('role', 'r2')],
            [],
            [...$times, 'route_expires_at' => null],
            null,
            GrantState::LIVE,
        );

        self::assertSame(GrantUsageKey::ofRow($row), GrantUsageKey::ofStored(SourceKind::ROLE_PERMISSION, $start, $target, ['r1', 'r2']));
        self::assertSame(GrantUsageKey::of(SourceKind::ROLE_PERMISSION, $target, new Reference('user', 'u'), ['tenant', 't', 'web'], ['r1', 'r2']), GrantUsageKey::ofRow($row));
    }
}
