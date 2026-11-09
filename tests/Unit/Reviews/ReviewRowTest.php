<?php

declare(strict_types = 1);

namespace Tests\Unit\Reviews;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Reviews\Enums\GrantState;
use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
use SineMacula\Laravel\Authorization\Reviews\Enums\SubjectState;
use SineMacula\Laravel\Authorization\Reviews\OriginScope;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Reviews\SupportingGrant;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for one row of an access review: its versioned shape of references
 * and plain values, and what is known of its subject.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReviewRow::class)]
final class ReviewRowTest extends TestCase
{
    /**
     * The row's shape is version 1, every field a reference, a scope, an
     * instant in UTC or a plain value.
     *
     * @return void
     */
    public function testTheRowHasAVersionedShape(): void
    {
        $row = self::row();

        self::assertSame(1, ReviewRow::VERSION);
        self::assertSame([
            'version'           => 1,
            'row_key'           => 'key',
            'subject'           => ['type' => 'user', 'id' => 'u1'],
            'grantee'           => ['type' => 'person', 'id' => 'p1'],
            'target'            => ['type' => 'permission', 'id' => 'x'],
            'source_kind'       => 'role_permission',
            'source_key'        => 'source',
            'origin_scope'      => ['tenant' => ['type' => 'tenant', 'id' => 't1'], 'application' => 'web', 'include_subtree' => false],
            'via_identity'      => ['type' => 'person', 'id' => 'p1'],
            'role_path'         => [['type' => 'role', 'id' => 'r1'], ['type' => 'role', 'id' => 'r2']],
            'supporting_grants' => [
                [
                    'source_key' => 'source',
                    'scope'      => ['tenant' => ['type' => 'tenant', 'id' => 't1'], 'application' => 'web', 'include_subtree' => false],
                    'expires_at' => '2040-01-02T03:04:05Z',
                ],
                ['source_key' => 'edge', 'scope' => null, 'expires_at' => null],
            ],
            'created_at'       => '2030-01-01T00:00:00Z',
            'updated_at'       => '2030-01-02T00:00:00Z',
            'expires_at'       => '2040-01-02T03:04:05Z',
            'route_expires_at' => '2040-01-02T03:04:05Z',
            'granted_by'       => ['type' => 'user', 'id' => 'admin'],
            'grant_state'      => 'live',
            'subject_state'    => 'unknown',
        ], $row->toArray());

        self::assertSame('2040-01-02T03:04:05Z', ReviewRow::instant($row->routeExpiresAt()));
    }

    /**
     * No scope, instant or reference is null, and a row naming half a tenant
     * shows the half it stores, marked malformed.
     *
     * @return void
     */
    public function testNoneIsNull(): void
    {
        self::assertNull(ReviewRow::instant(null));
        self::assertSame('2030-01-01T05:00:00Z', ReviewRow::instant(CarbonImmutable::create(2030, 1, 1, 0, 0, 0, 'America/New_York')));

        $bare = new ReviewRow(
            'k',
            new Reference('user', 'u'),
            new Reference('user', 'u'),
            new Reference('role', 'r'),
            SourceKind::ROLE_GRANT,
            's',
            null,
            null,
            [],
            [],
            ['created_at' => null, 'updated_at' => null, 'expires_at' => null, 'route_expires_at' => null],
            null,
            GrantState::EXPIRED,
        );

        self::assertSame(
            [null, null, null, 'expired'],
            [$bare->toArray()['via_identity'], $bare->toArray()['granted_by'], $bare->toArray()['origin_scope'], $bare->toArray()['grant_state']],
        );
        self::assertNull($bare->routeExpiresAt());

        $half = new ReviewRow(
            'k',
            new Reference('user', 'u'),
            new Reference('user', 'u'),
            new Reference('role', 'r'),
            SourceKind::ROLE_GRANT,
            's',
            new OriginScope(null, 't1', null, true),
            null,
            [],
            [],
            ['created_at' => null, 'updated_at' => null, 'expires_at' => null, 'route_expires_at' => null],
            null,
            GrantState::MALFORMED,
        );

        self::assertSame(
            [['tenant' => ['type' => null, 'id' => 't1'], 'application' => null, 'include_subtree' => true], 'malformed'],
            [$half->toArray()['origin_scope'], $half->toArray()['grant_state']],
        );
    }

    /**
     * The row is given what is known of its subject, everything else kept.
     *
     * @return void
     */
    public function testTheRowIsGivenItsSubjectsState(): void
    {
        $row    = self::row();
        $active = $row->withSubjectState(SubjectState::ACTIVE);

        self::assertSame(SubjectState::UNKNOWN, $row->subjectState);
        self::assertSame(SubjectState::ACTIVE, $active->subjectState);
        self::assertSame(\array_diff_key($row->toArray(), ['subject_state' => true]), \array_diff_key($active->toArray(), ['subject_state' => true]));
        self::assertSame('active', $active->toArray()['subject_state']);
    }

    /**
     * Return a row with every field set.
     *
     * @return \SineMacula\Laravel\Authorization\Reviews\ReviewRow
     */
    private static function row(): ReviewRow
    {
        $scope   = new OriginScope('tenant', 't1', 'web', false);
        $expires = CarbonImmutable::create(2040, 1, 2, 3, 4, 5, 'UTC');

        return new ReviewRow(
            'key',
            new Reference('user', 'u1'),
            new Reference('person', 'p1'),
            new Reference('permission', 'x'),
            SourceKind::ROLE_PERMISSION,
            'source',
            $scope,
            new Reference('person', 'p1'),
            [new Reference('role', 'r1'), new Reference('role', 'r2')],
            [new SupportingGrant('source', $scope, $expires), new SupportingGrant('edge', null, null)],
            [
                'created_at'       => CarbonImmutable::create(2030, 1, 1, 0, 0, 0, 'UTC'),
                'updated_at'       => CarbonImmutable::create(2030, 1, 2, 0, 0, 0, 'UTC'),
                'expires_at'       => $expires,
                'route_expires_at' => $expires,
            ],
            new Reference('user', 'admin'),
            GrantState::LIVE,
        );
    }
}
