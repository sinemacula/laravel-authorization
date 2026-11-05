<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;

/**
 * Unit tests for `ResolvedTenant`, the holder of the tenant of the subject
 * resolved for the current request or job and the resolver it came from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResolvedTenant::class)]
final class ResolvedTenantTest extends TestCase
{
    /**
     * `from()` asks the resolver once and keeps both the resolver and the
     * tenant of the subject it returned.
     *
     * @return void
     */
    public function testFromResolvesTheSubjectsTenantOnce(): void
    {
        $tenant   = new \stdClass;
        $resolver = $this->createMock(SubjectResolver::class);
        $resolver->expects(self::once())->method('resolve')->willReturn(new Subject(new \stdClass, tenant: $tenant));

        $resolved = ResolvedTenant::from($resolver);

        self::assertSame($resolver, $resolved->resolver);
        self::assertSame($tenant, $resolved->tenant);
    }

    /**
     * A subject without a tenant yields a holder with a null tenant.
     *
     * @return void
     */
    public function testFromKeepsANullTenant(): void
    {
        $resolver = self::createStub(SubjectResolver::class);
        $resolver->method('resolve')->willReturn(new Subject(new \stdClass));

        self::assertNull(ResolvedTenant::from($resolver)->tenant);
    }

    /**
     * No subject means no tenant, never every tenant.
     *
     * @return void
     */
    public function testFromWithoutASubjectHasNoTenant(): void
    {
        $resolver = self::createStub(SubjectResolver::class);
        $resolver->method('resolve')->willReturn(null);

        self::assertNull(ResolvedTenant::from($resolver)->tenant);
    }

    /**
     * The holder recognises the resolver it came from, and no other resolver,
     * even one of the same class.
     *
     * @return void
     */
    public function testIsFromMatchesOnlyTheSameResolverInstance(): void
    {
        $resolver = self::createStub(SubjectResolver::class);
        $other    = clone $resolver;
        $resolved = new ResolvedTenant($resolver, null);

        self::assertTrue($resolved->isFrom($resolver));
        self::assertFalse($resolved->isFrom($other));
    }
}
