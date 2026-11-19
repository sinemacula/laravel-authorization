<?php

declare(strict_types = 1);

namespace Tests\Feature\Cache;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\PrincipalCacheKey;
use SineMacula\Laravel\Authorization\Evaluation\PolicyLimits;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubGrantee;
use Tests\TestCase;

/**
 * Feature tests for the keys of the resolution cache: a principal's, and a
 * persistent entry's, keyed by its kind, its grantee and the scope, and, for
 * the kinds that hold policy documents, the routed policies included, the
 * policy limits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PrincipalCacheKey::class)]
final class PrincipalCacheKeyTest extends TestCase
{
    /**
     * A principal is keyed by its morph type and key, and an object with
     * neither by its hash.
     *
     * @return void
     */
    public function testAPrincipalIsKeyedByItsTypeAndKey(): void
    {
        $user = new StubGrantee(['id' => 'ann']);

        self::assertSame(StubGrantee::class . ':ann', PrincipalCacheKey::for($user));
        self::assertMatchesRegularExpression('/^stdClass:%obj[0-9a-f]{32}$/', PrincipalCacheKey::for(new \stdClass));
    }

    /**
     * A '%' or ':' in a principal's type or key is escaped, so no two
     * principals share a key.
     *
     * @return void
     */
    public function testAPrincipalsTypeAndKeyAreEscaped(): void
    {
        self::assertSame('a%3Ab:c', PrincipalCacheKey::for(new Reference('a:b', 'c')));
        self::assertSame('a:b%3Ac', PrincipalCacheKey::for(new Reference('a', 'b:c')));
        self::assertSame('a%25:b%253A', PrincipalCacheKey::for(new Reference('a%', 'b%3A')));
    }

    /**
     * An entry is keyed by the prefix, its kind, its grantee and the scope, and
     * an entry of policy documents also by the policy limits, the routed
     * policies and an identity's included; any other kind is not.
     *
     * @return void
     */
    public function testAnEntryIsKeyedByItsKindGranteeAndScope(): void
    {
        $grantee = new Reference('user', 'ann');
        $limits  = ':limits:' . PolicyLimits::fromConfig()->fingerprint();
        $scope   = TenantScope::scopeKey();

        self::assertSame('p:permissions:user:ann:' . $scope, PrincipalCacheKey::entry('p', 'permissions', $grantee));
        self::assertSame('p:permissions-routed:user:ann:' . $scope, PrincipalCacheKey::entry('p', 'permissions-routed', $grantee));

        $kinds = ['policies', 'policies-routed', 'boundaries', 'resource-policies', 'resource-type-policies', 'guardrails'];

        foreach ([...$kinds, 'identity-policies', 'identity-policies-routed', 'identity-boundaries'] as $kind) {
            self::assertSame("p:{$kind}:user:ann:" . $scope . $limits, PrincipalCacheKey::entry('p', $kind, $grantee));
        }

        self::assertSame('p:identity-permissions:user:ann:' . $scope, PrincipalCacheKey::entry('p', 'identity-permissions', $grantee));
    }
}
