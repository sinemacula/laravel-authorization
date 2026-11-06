<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\ContextSource;
use SineMacula\Laravel\Authorization\Contracts\EnvironmentContext;
use SineMacula\Laravel\Authorization\Contracts\RequestContext;

/**
 * Unit tests for `CheckContextFactory`, which makes the context of each check
 * from the trusted sources, the application's sources and what the caller
 * passes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(CheckContextFactory::class)]
final class CheckContextFactoryTest extends TestCase
{
    /** @var array<string, int> How many times each source has been read. */
    private array $calls = [];

    /**
     * Each namespace comes from its source: `authentication` and the namespaces
     * the authentication context contributes, `request`, `environment` and an
     * application's own.
     *
     * @return void
     */
    public function testEachNamespaceComesFromItsSource(): void
    {
        $context = $this->factory()->make();

        self::assertSame([true, 'web'], $context->lookup('authentication.guard'));
        self::assertSame([true, true], $context->lookup('mfa.enrolled'));
        self::assertSame([true, '10.0.0.1'], $context->lookup('request.ip'));
        self::assertSame([true, '2026-01-31T09:30:00Z'], $context->lookup('environment.time'));
        self::assertSame([true, 'pro'], $context->lookup('tenant.plan'));
        self::assertSame([true, []], $context->lookup('input'));
    }

    /**
     * What the caller passes is held under `input` and never promoted into
     * another namespace, so it can never stand in for a trusted one.
     *
     * @return void
     */
    public function testCallerValuesStayUnderInput(): void
    {
        $context = $this->factory()->make([
            'request'        => ['ip' => '192.0.2.1'],
            'authentication' => ['guard' => 'admin'],
            'tenant'         => ['plan' => 'enterprise'],
            'request.ip'     => '192.0.2.2',
            'post'           => ['status' => 'draft'],
        ]);

        self::assertSame([true, '10.0.0.1'], $context->lookup('request.ip'));
        self::assertSame([true, 'web'], $context->lookup('authentication.guard'));
        self::assertSame([true, 'pro'], $context->lookup('tenant.plan'));
        self::assertSame([true, '192.0.2.1'], $context->lookup('input.request.ip'));
        self::assertSame([true, 'admin'], $context->lookup('input.authentication.guard'));
        self::assertSame([true, 'draft'], $context->lookup('input.post.status'));
        self::assertSame([false, null], $context->lookup('post.status'));
    }

    /**
     * No source is read when the context is made, each is read the first time a
     * check reads one of its namespaces and once for the check, and the
     * authentication context once for every namespace it supplies.
     *
     * @return void
     */
    public function testSourcesAreReadLazilyAndOncePerCheck(): void
    {
        $context = $this->factory()->make(['a' => 1]);

        self::assertSame([], $this->calls);

        $context->lookup('input.a');
        $context->lookup('request.ip');
        $context->lookup('request.method');
        $context->lookup('mfa.enrolled');
        $context->lookup('authentication.guard');

        self::assertSame(['request' => 1, 'authentication' => 1], $this->calls);
    }

    /**
     * Every check's context is new, so the next check reads its sources again.
     *
     * @return void
     */
    public function testEachCheckReadsItsSourcesAgain(): void
    {
        $factory = $this->factory();

        $factory->make()->lookup('environment.time');
        $factory->make()->lookup('environment.time');
        $factory->make()->lookup('tenant.plan');

        self::assertSame(['environment' => 2, 'tenant' => 1], $this->calls);
    }

    /**
     * A source that supplies nothing leaves its namespace absent, so its keys
     * are missing.
     *
     * @return void
     */
    public function testASourceSupplyingNothingLeavesItsNamespaceAbsent(): void
    {
        $context = (new CheckContextFactory(
            $this->authentication([], ['authentication', 'mfa']),
            $this->request([]),
            $this->environment([]),
            [$this->source('tenant', [])],
        ))->make();

        foreach (['authentication', 'mfa', 'request', 'environment', 'tenant'] as $namespace) {
            self::assertSame([false, null], $context->lookup($namespace), $namespace);
        }
    }

    /**
     * Provide the namespaces no context source may claim, with how each is
     * claimed.
     *
     * @return iterable<string, array{string, bool}>
     */
    public static function unclaimableProvider(): iterable
    {
        foreach (ContextSource::RESERVED_NAMESPACES as $namespace) {
            yield "source claiming {$namespace}" => [$namespace, false];
        }

        foreach (\array_diff(ContextSource::RESERVED_NAMESPACES, ['authentication']) as $namespace) {
            yield "authentication context claiming {$namespace}" => [$namespace, true];
        }

        yield 'source claiming a contributed namespace' => ['mfa', false];
        yield 'source claiming another source\'s namespace' => ['tenant', false];
        yield 'an empty namespace' => ['', false];
        yield 'a dotted namespace' => ['tenant.plan', false];
        yield 'a namespace starting with a digit' => ['1tenant', false];
        yield 'a dashed namespace claimed by the authentication context' => ['s-so', true];
    }

    /**
     * A namespace that is not a name, is reserved, or is supplied by another
     * source is refused on construction, so a source can never stand in for a
     * trusted one.
     *
     * @param  string  $namespace
     * @param  bool  $isAuthentication
     * @return void
     */
    #[DataProvider('unclaimableProvider')]
    public function testRefusesAnUnclaimableNamespace(string $namespace, bool $isAuthentication): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("cannot supply the namespace '{$namespace}': it is not a name, is reserved or is supplied by another source.");

        new CheckContextFactory(
            $this->authentication(['authentication' => []], $isAuthentication ? ['authentication', $namespace] : ['authentication', 'mfa']),
            $this->request([]),
            $this->environment([]),
            [$this->source('tenant', []), ...($isAuthentication ? [] : [$this->source($namespace, [])])],
        );
    }

    /**
     * A namespace in the namespace syntax that nothing else supplies may be
     * claimed, and the authentication context naming `authentication` again
     * claims nothing more.
     *
     * @return void
     */
    public function testAcceptsAClaimableNamespace(): void
    {
        $context = (new CheckContextFactory(
            $this->authentication(['authentication' => ['guard' => 'web'], 'sso_2' => ['provider' => 'okta']], ['authentication', 'sso_2', 'authentication']),
            $this->request([]),
            $this->environment([]),
            [$this->source('_device9', ['id' => 'd1'])],
        ))->make();

        self::assertSame([true, 'okta'], $context->lookup('sso_2.provider'));
        self::assertSame([true, 'd1'], $context->lookup('_device9.id'));
    }

    /**
     * Build a factory with a source of every kind, each counting its reads.
     *
     * @return \SineMacula\Laravel\Authorization\Context\CheckContextFactory
     */
    private function factory(): CheckContextFactory
    {
        return new CheckContextFactory(
            $this->authentication(['authentication' => ['guard' => 'web'], 'mfa' => ['enrolled' => true]], ['authentication', 'mfa']),
            $this->request(['ip' => '10.0.0.1', 'method' => 'GET']),
            $this->environment(['time' => '2026-01-31T09:30:00Z']),
            [$this->source('tenant', ['plan' => 'pro'])],
        );
    }

    /**
     * Build an authentication context supplying the given values, counting its
     * reads.
     *
     * @param  array<string, array<string, mixed>>  $values
     * @param  list<string>  $namespaces
     * @return \SineMacula\Laravel\Authorization\Contracts\AuthenticationContext
     */
    private function authentication(array $values, array $namespaces): AuthenticationContext
    {
        $count = $this->counter('authentication');

        return new readonly class ($values, $namespaces, $count) implements AuthenticationContext {
            /**
             * Create the authentication context.
             *
             * @param  array<string, array<string, mixed>>  $values
             * @param  list<string>  $namespaces
             * @param  \Closure(): void  $count
             */
            public function __construct(

                /** The values supplied. */
                private array $values,

                /** The namespaces supplied. */
                private array $namespaces,

                /** Counts each read. */
                private \Closure $count,
            ) {}

            /**
             * Return the namespaces supplied.
             *
             * @return list<string>
             */
            #[\Override]
            public function namespaces(): array
            {
                return $this->namespaces;
            }

            /**
             * Return the values, counting the read.
             *
             * @return array<string, array<string, mixed>>
             */
            #[\Override]
            public function values(): array
            {
                ($this->count)();

                return $this->values;
            }
        };
    }

    /**
     * Build a request context supplying the given values, counting its reads.
     *
     * @param  array<string, mixed>  $values
     * @return \SineMacula\Laravel\Authorization\Contracts\RequestContext
     */
    private function request(array $values): RequestContext
    {
        $count = $this->counter('request');

        return new readonly class ($values, $count) implements RequestContext {
            /**
             * Create the request context.
             *
             * @param  array<string, mixed>  $values
             * @param  \Closure(): void  $count
             */
            public function __construct(

                /** The values supplied. */
                private array $values,

                /** Counts each read. */
                private \Closure $count,
            ) {}

            /**
             * Return the values, counting the read.
             *
             * @return array<string, mixed>
             */
            #[\Override]
            public function values(): array
            {
                ($this->count)();

                return $this->values;
            }
        };
    }

    /**
     * Build an environment context supplying the given values, counting its
     * reads.
     *
     * @param  array<string, mixed>  $values
     * @return \SineMacula\Laravel\Authorization\Contracts\EnvironmentContext
     */
    private function environment(array $values): EnvironmentContext
    {
        $count = $this->counter('environment');

        return new readonly class ($values, $count) implements EnvironmentContext {
            /**
             * Create the environment context.
             *
             * @param  array<string, mixed>  $values
             * @param  \Closure(): void  $count
             */
            public function __construct(

                /** The values supplied. */
                private array $values,

                /** Counts each read. */
                private \Closure $count,
            ) {}

            /**
             * Return the values, counting the read.
             *
             * @return array<string, mixed>
             */
            #[\Override]
            public function values(): array
            {
                ($this->count)();

                return $this->values;
            }
        };
    }

    /**
     * Build an application source supplying the namespace's values, counting
     * its reads.
     *
     * @param  string  $namespace
     * @param  array<string, mixed>  $values
     * @return \SineMacula\Laravel\Authorization\Contracts\ContextSource
     */
    private function source(string $namespace, array $values): ContextSource
    {
        $count = $this->counter($namespace);

        return new readonly class ($namespace, $values, $count) implements ContextSource {
            /**
             * Create the source.
             *
             * @param  string  $namespace
             * @param  array<string, mixed>  $values
             * @param  \Closure(): void  $count
             */
            public function __construct(

                /** The namespace supplied. */
                private string $namespace,

                /** The values supplied. */
                private array $values,

                /** Counts each read. */
                private \Closure $count,
            ) {}

            /**
             * Return the namespace supplied.
             *
             * @return string
             */
            #[\Override]
            public function namespace(): string
            {
                return $this->namespace;
            }

            /**
             * Return the values, counting the read.
             *
             * @return array<string, mixed>
             */
            #[\Override]
            public function values(): array
            {
                ($this->count)();

                return $this->values;
            }
        };
    }

    /**
     * Return a closure counting a read of the named source.
     *
     * @param  string  $name
     * @return \Closure(): void
     */
    private function counter(string $name): \Closure
    {
        return function () use ($name): void {
            $this->calls[$name] = ($this->calls[$name] ?? 0) + 1;
        };
    }
}
