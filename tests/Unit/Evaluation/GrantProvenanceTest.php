<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\GrantSource;
use SineMacula\Laravel\Authorization\Evaluation\GrantProvenance;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for the grant provenance value object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantProvenance::class)]
final class GrantProvenanceTest extends TestCase
{
    /**
     * A provenance defaults to no grantee, the principal, no role and an
     * unknown scope.
     *
     * @return void
     */
    public function testDefaults(): void
    {
        $grant = new GrantProvenance(GrantSource::RESOURCE_POLICY, 'share on posts:*');

        self::assertNull($grant->grantee);
        self::assertFalse($grant->isIdentity);
        self::assertSame([], $grant->roles);
        self::assertFalse($grant->hasScope);
        self::assertNull($grant->tenant);
        self::assertNull($grant->application);
    }

    /**
     * unavailable() names the grant and its grantee, with nothing else known.
     *
     * @return void
     */
    public function testUnavailable(): void
    {
        $user  = new Reference('user', '1');
        $grant = GrantProvenance::unavailable('posts:read', $user, true);

        self::assertEquals(new GrantProvenance(GrantSource::UNAVAILABLE, 'posts:read', $user, true), $grant);
        self::assertEquals(new GrantProvenance(GrantSource::UNAVAILABLE, 'posts:read'), GrantProvenance::unavailable('posts:read'));
    }

    /**
     * named() renames the grant and keeps everything else.
     *
     * @return void
     */
    public function testNamedKeepsEverythingElse(): void
    {
        $grant = new GrantProvenance(GrantSource::ROLE_POLICY, 'key', new Reference('user', '1'), true, ['editor'], true, new Reference('team', '2'), 'web');

        $named = new GrantProvenance(GrantSource::ROLE_POLICY, 'name[key]', new Reference('user', '1'), true, ['editor'], true, new Reference('team', '2'), 'web');

        self::assertEquals($named, $grant->named('name[key]'));
    }

    /**
     * toArray() renders the scope it knows, and `unavailable` for one it does
     * not.
     *
     * @return void
     */
    public function testToArray(): void
    {
        $user    = new Reference('user', '1');
        $known   = new GrantProvenance(GrantSource::ROLE_PERMISSION, 'posts:edit', $user, false, ['editor', 'author'], true, new Reference('team', '2'), 'web');
        $unknown = new GrantProvenance(GrantSource::RESOURCE_POLICY, 'share on posts:*');

        self::assertSame([
            'source'   => 'role_permission',
            'grant'    => 'posts:edit',
            'grantee'  => ['type' => 'user', 'id' => '1'],
            'identity' => false,
            'roles'    => ['editor', 'author'],
            'scope'    => ['tenant' => ['type' => 'team', 'id' => '2'], 'application' => 'web'],
        ], $known->toArray());
        self::assertSame('unavailable', $unknown->toArray()['scope']);
        self::assertNull($unknown->toArray()['grantee']);
        self::assertSame(['tenant' => null, 'application' => null], (new GrantProvenance(GrantSource::PERMISSION, 'p', null, false, [], true))->toArray()['scope']);
    }
}
