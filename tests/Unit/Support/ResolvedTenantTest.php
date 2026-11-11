<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
use SineMacula\Laravel\Authorization\Diagnostics\PackageState;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
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
        $resolver->expects(self::once())->method('resolve')->willReturn(new Subject(new \stdClass, tenant: $tenant, application: 'admin'));

        $resolved = ResolvedTenant::from($resolver);

        self::assertSame($resolver, $resolved->resolver);
        self::assertSame($tenant, $resolved->tenant);
        self::assertSame('admin', $resolved->application);
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
     * No subject means no tenant, never every tenant, and reading it raises no
     * warning.
     *
     * @return void
     */
    public function testFromWithoutASubjectHasNoTenant(): void
    {
        $resolver = self::createStub(SubjectResolver::class);
        $resolver->method('resolve')->willReturn(null);

        \set_error_handler(static function (int $level, string $message): never {
            throw new \ErrorException($message, 0, $level);
        });

        try {
            self::assertNull(ResolvedTenant::from($resolver)->tenant);
            self::assertNull(ResolvedTenant::from($resolver)->application);
        } finally {
            \restore_error_handler();
        }
    }

    /**
     * The holder recognises the resolver it came from, and no other resolver,
     * even one of the same class, under the default guard it was read under.
     *
     * @return void
     */
    public function testIsFromMatchesOnlyTheSameResolverInstance(): void
    {
        $resolver = self::createStub(SubjectResolver::class);
        $other    = clone $resolver;
        $resolved = new ResolvedTenant($resolver, null);
        $guarded  = ResolvedTenant::from($resolver, 'web');

        self::assertTrue($resolved->isFrom($resolver));
        self::assertFalse($resolved->isFrom($other));
        self::assertFalse($resolved->isFrom($resolver, 'web'));
        self::assertSame('web', $guarded->guard);
        self::assertTrue($guarded->isFrom($resolver, 'web'));
        self::assertFalse($guarded->isFrom($resolver, 'admin'));
    }

    /**
     * The chain is the tenant then its ancestors, read once through a tree and
     * again when another tree is asked or a refresh is; no tenant has the
     * platform's empty chain, without asking the tree.
     *
     * @return void
     */
    public function testTheChainIsReadOncePerTree(): void
    {
        $tenant = new class implements AuthorizableTenant {
            /**
             * Return the tenant's key.
             *
             * @return string
             */
            #[\Override]
            public function getKey(): string
            {
                return 'account';
            }

            /**
             * Return the tenant's type.
             *
             * @return string
             */
            #[\Override]
            public function getMorphClass(): string
            {
                return 'stub_tenant';
            }
        };
        $resolver = self::createStub(SubjectResolver::class);
        $org      = new Reference('stub_tenant', 'org');
        $first    = $this->createMock(TenantTree::class);
        $second   = $this->createMock(TenantTree::class);

        $first->expects(self::exactly(2))->method('ancestors')->with(new Reference('stub_tenant', 'account'))->willReturn([$org]);
        $second->expects(self::once())->method('ancestors')->willReturn([]);

        $resolved = new ResolvedTenant($resolver, $tenant);

        self::assertEquals([new Reference('stub_tenant', 'account'), $org], $resolved->chain($first)->tenants);
        self::assertSame($resolved->chain($first), $resolved->chain($first));
        self::assertEquals([new Reference('stub_tenant', 'account')], $resolved->chain($second)->tenants);
        self::assertEquals([new Reference('stub_tenant', 'account'), $org], $resolved->refreshChain($first)->tenants);

        $unused = $this->createMock(TenantTree::class);
        $unused->expects(self::never())->method('ancestors');

        self::assertSame([], (new ResolvedTenant($resolver, null))->chain($unused)->tenants);
        self::assertFalse($resolved->isBelow);
        self::assertFalse($resolved->chain($first)->isBelow);
    }

    /**
     * A holder put in place to decide just below its tenant reads a chain
     * standing there, refreshed or not.
     *
     * @return void
     */
    public function testAHolderBelowItsTenantReadsAChainStandingThere(): void
    {
        $tree = self::createStub(TenantTree::class);

        $tree->method('ancestors')->willReturn([]);

        $resolved = new ResolvedTenant(self::createStub(SubjectResolver::class), new Reference('stub_tenant', 'org'), null, null, true);

        self::assertTrue($resolved->isBelow);
        self::assertTrue($resolved->chain($tree)->isBelow);
        self::assertTrue($resolved->refreshChain($tree)->isBelow);
        self::assertEquals([new Reference('stub_tenant', 'org')], $resolved->chain($tree)->tenants);
    }

    /**
     * Within a batch of checks, a holder reads the chain the tree already gave
     * for its tenant, and a refresh reads it afresh, in place of the one kept,
     * so a holder made after it reads the fresh one.
     *
     * @return void
     */
    public function testWithinABatchTheChainIsReadOnceAndARefreshReplacesIt(): void
    {
        $previous  = Container::getInstance();
        $container = new Container;
        $cache     = new ResolutionCache;
        $tenant    = new Reference('stub_tenant', 'account');
        $org       = new Reference('stub_tenant', 'org');
        $sibling   = new Reference('stub_tenant', 'sibling');
        $tree      = $this->createMock(TenantTree::class);
        $resolver  = self::createStub(SubjectResolver::class);

        $tree->expects(self::exactly(2))->method('ancestors')->with($tenant)->willReturn([$org], [$sibling]);
        $container->instance(ResolutionCache::class, $cache);

        Container::setInstance($container);

        try {
            $chains = $cache->batch(static fn (): array => [
                (new ResolvedTenant($resolver, $tenant))->chain($tree)->tenants,
                (new ResolvedTenant($resolver, $tenant))->chain($tree)->tenants,
                (new ResolvedTenant($resolver, $tenant))->refreshChain($tree)->tenants,
                (new ResolvedTenant($resolver, $tenant))->chain($tree)->tenants,
            ]);
        } finally {
            Container::setInstance($previous);
        }

        self::assertEquals([[$tenant, $org], [$tenant, $org], [$tenant, $sibling], [$tenant, $sibling]], $chains);
    }

    /**
     * `from()` builds the holder while the package of the current container is
     * pending, as what the boot validates may be handed it, and refuses once it
     * refuses, before the resolver is asked.
     *
     * @return void
     */
    public function testFromRefusesOnlyOnceThePackageRefuses(): void
    {
        $container = new Container;
        $state     = PackageState::start($container);
        $resolver  = $this->createMock(SubjectResolver::class);

        $resolver->expects(self::once())->method('resolve')->willReturn(new Subject(new \stdClass));

        Container::setInstance($container);

        try {
            self::assertSame($resolver, ResolvedTenant::from($resolver)->resolver);

            $state->refuse(new ConfigFindings([new ConfigIssue('authorization.nonsense', IssueCode::UNKNOWN_KEY)], []));

            ResolvedTenant::from($resolver);

            self::fail('The holder was built while the package refuses.');
        } catch (InvalidAuthorizationConfigException $refusal) {
            self::assertSame('authorization.nonsense', $refusal->getConfigKey());
        } finally {
            Container::setInstance(null);
        }
    }
}
