<?php

declare(strict_types = 1);

namespace Tests\Unit\Reviews\Support;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Reviews\Support\GrantRow;
use SineMacula\Laravel\Authorization\Reviews\Support\ReviewOrder;

/**
 * Unit tests for one stored row an access review reads: read from a query's
 * columns, keyed by what makes it unique, live until its expiry, and placed in
 * the review's order.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(GrantRow::class)]
final class GrantRowTest extends TestCase
{
    /**
     * A grant row is read from its columns: its target, grantee and scope,
     * keyed and ordered by them.
     *
     * @return void
     */
    public function testAGrantRowIsReadFromItsColumns(): void
    {
        $row   = self::full();
        $scope = $row->scope;

        self::assertNotNull($scope);
        self::assertSame(['role', 'r1', 'user', '42'], [$row->source, $row->targetId, $row->grantee->type, $row->grantee->id]);
        self::assertSame(['tenant', '7', 'web', false], [$scope->tenant?->type, $scope->tenant?->id, $scope->application, $scope->includeSubtree]);
        self::assertSame(ReviewOrder::key(['role', 'r1', 'user', '42', 'tenant', '7', 'web']), $row->key());
        self::assertSame(['user', '42', 1, 'tenant', 1, '7', 1, 'web', false], $row->orderKey());
    }

    /**
     * A grant row's instants are read in UTC, and its actor by its pair.
     *
     * @return void
     */
    public function testAGrantRowReadsItsTimesAndActor(): void
    {
        $row     = self::full();
        $expires = $row->expiresAt();

        self::assertNotNull($expires);
        self::assertSame(['2040-01-02 03:04:05', 'UTC'], [$expires->format('Y-m-d H:i:s'), $expires->getTimezone()->getName()]);
        self::assertSame('2030-01-01 00:00:00', $row->times['created_at']?->format('Y-m-d H:i:s'));
        self::assertSame('2030-01-02 00:00:00', $row->times['updated_at']?->format('Y-m-d H:i:s'));
        self::assertSame(['user', '1'], [$row->grantedBy?->type, $row->grantedBy?->id]);
    }

    /**
     * A platform-wide row for every application has no tenant, application or
     * actor; a row naming half a tenant is read as the platform's where a check
     * places it; a reach reads as a boolean whatever the driver returns.
     *
     * @return void
     */
    public function testNullColumnsReadAsNone(): void
    {
        $row = GrantRow::from((object) ['target_id' => 'p', 'grantee_type' => 'user', 'grantee_id' => 'u', 'include_subtree' => true], 'permission');

        self::assertSame(
            [null, null, true, null, null, null],
            [$row->scope?->tenant, $row->scope?->application, $row->scope?->includeSubtree, $row->expiresAt(), $row->times['created_at'], $row->grantedBy],
        );
        self::assertSame(['user', 'u', 0, '', 0, '', 0, '', true], $row->orderKey());
        self::assertSame(ReviewOrder::key(['permission', 'p', 'user', 'u', null, null, null]), $row->key());

        $half = GrantRow::from((object) ['target_id' => 'p', 'grantee_type' => 'user', 'grantee_id' => 'u', 'tenant_type' => 'tenant', 'granted_by_type' => 'user'], 'permission');

        self::assertNull($half->scope?->tenant);
        self::assertNull($half->grantedBy);
        self::assertTrue($half->scope?->includeSubtree);

        foreach ([[1, true], ['1', true], ['t', true], ['true', true], [false, false], [0, false], ['0', false], ['f', false]] as [$stored, $read]) {
            self::assertSame(
                $read,
                GrantRow::from((object) ['target_id' => 'p', 'grantee_type' => 'u', 'grantee_id' => 'u', 'include_subtree' => $stored], 'permission')->scope?->includeSubtree,
            );
        }
    }

    /**
     * A row naming half a tenant keeps the half it stores as its origin, keyed
     * and ordered by it as the grant queries order it, and is malformed: a key
     * without a type is read where a check reads it, at the platform, while a
     * type without a key is placed nowhere.
     *
     * @return void
     */
    public function testARowNamingHalfATenantKeepsWhatItStores(): void
    {
        $noType = self::half(null, 't1');
        $noKey  = self::half('tenant', null);
        $whole  = self::half('tenant', 't1');

        self::assertSame([null, 't1', true, true], [$noType->originScope()?->tenantType, $noType->originScope()?->tenantId, $noType->isMalformed(), $noType->isPlaced()]);
        self::assertSame(['tenant', null, true, false], [$noKey->originScope()?->tenantType, $noKey->originScope()?->tenantId, $noKey->isMalformed(), $noKey->isPlaced()]);
        self::assertSame([false, true], [$whole->isMalformed(), $whole->isPlaced()]);
        self::assertNull($noType->scope?->tenant);
        self::assertNull($noKey->scope?->tenant);

        self::assertSame(ReviewOrder::key(['permission', 'p', 'user', 'u', null, 't1', null]), $noType->key());
        self::assertSame(ReviewOrder::key(['permission', 'p', 'user', 'u', 'tenant', null, null]), $noKey->key());
        self::assertSame(['user', 'u', 0, '', 1, 't1', 0, '', true], $noType->orderKey());
        self::assertSame(['user', 'u', 1, 'tenant', 0, '', 0, '', true], $noKey->orderKey());
        self::assertSame(['type' => 'tenant', 'id' => null], $noKey->supporting()->toArray()['scope']['tenant'] ?? null);

        $edge = GrantRow::from((object) ['target_id' => 'p1', 'grantee_id' => 'r1'], GrantRow::EDGE, 'role');

        self::assertSame([false, true, null], [$edge->isMalformed(), $edge->isPlaced(), $edge->originScope()]);
    }

    /**
     * A row placed nowhere meets only a placed row that holds everywhere, never
     * another placed nowhere nor one held in a tenant; any other two can meet.
     *
     * @return void
     */
    public function testARowPlacedNowhereMeetsOnlyARowHeldEverywhere(): void
    {
        $nowhere  = self::half('tenant', null);
        $platform = self::half(null, null);
        $noType   = self::half(null, 't1');
        $tenant   = self::half('tenant', 't1');

        self::assertTrue($nowhere->canMeet($platform));
        self::assertTrue($platform->canMeet($nowhere));
        self::assertTrue($nowhere->canMeet($noType));
        self::assertFalse($nowhere->canMeet($tenant));
        self::assertFalse($tenant->canMeet($nowhere));
        self::assertFalse($nowhere->canMeet(self::half('tenant', null)));
        self::assertTrue($tenant->canMeet($platform));
        self::assertTrue($tenant->canMeet($noType));
    }

    /**
     * An edge's grantee is the role of the type given, and it holds no scope,
     * timestamps or actor; its key names its role and permission.
     *
     * @return void
     */
    public function testAnEdgeIsARolesPermission(): void
    {
        $edge = GrantRow::from((object) ['target_id' => 'p1', 'grantee_id' => 'r1', 'expires_at' => null], GrantRow::EDGE, 'role');

        self::assertSame(['role_permission', 'role', 'r1', null], [$edge->source, $edge->grantee->type, $edge->grantee->id, $edge->scope]);
        self::assertSame(ReviewOrder::key(['role_permission', 'r1', 'p1']), $edge->key());
        self::assertSame(['role', 'r1', 0, '', 0, '', 0, '', false], $edge->orderKey());
        self::assertSame(['source_key' => $edge->key(), 'scope' => null, 'expires_at' => null], $edge->supporting()->toArray());
    }

    /**
     * A row is live while it has no expiry or one after the instant, and
     * expired at the instant itself.
     *
     * @return void
     */
    public function testARowIsLiveUntilItsExpiry(): void
    {
        $now     = CarbonImmutable::create(2030, 1, 1, 0, 0, 0, 'UTC');
        $expires = static fn (?string $at): GrantRow => GrantRow::from(
            (object) ['target_id' => 'p', 'grantee_type' => 'u', 'grantee_id' => 'u', 'expires_at' => $at],
            'permission',
        );

        self::assertTrue($expires(null)->isLiveAt($now));
        self::assertTrue($expires('2030-01-01 00:00:01')->isLiveAt($now));
        self::assertFalse($expires('2030-01-01 00:00:00')->isLiveAt($now));
        self::assertFalse($expires('2029-12-31 23:59:59')->isLiveAt($now));
        self::assertSame('2030-01-01T00:00:01Z', $expires('2030-01-01 00:00:01')->supporting()->toArray()['expires_at']);
    }

    /**
     * Return a permission grant stored with the tenant columns given.
     *
     * @param  string|null  $type
     * @param  string|null  $id
     * @return \SineMacula\Laravel\Authorization\Reviews\Support\GrantRow
     */
    private static function half(?string $type, ?string $id): GrantRow
    {
        $columns = ['target_id' => 'p', 'grantee_type' => 'user', 'grantee_id' => 'u', 'tenant_type' => $type, 'tenant_id' => $id, 'include_subtree' => true];

        return GrantRow::from((object) $columns, 'permission');
    }

    /**
     * Return a role grant read from every column a review reads.
     *
     * @return \SineMacula\Laravel\Authorization\Reviews\Support\GrantRow
     */
    private static function full(): GrantRow
    {
        return GrantRow::from((object) [
            'target_id'       => 'r1',
            'grantee_type'    => 'user',
            'grantee_id'      => 42,
            'tenant_type'     => 'tenant',
            'tenant_id'       => 7,
            'include_subtree' => 0,
            'application'     => 'web',
            'expires_at'      => '2040-01-02 03:04:05',
            'created_at'      => '2030-01-01 00:00:00',
            'updated_at'      => '2030-01-02 00:00:00',
            'granted_by_type' => 'user',
            'granted_by_id'   => 1,
        ], 'role');
    }
}
