<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator;

/**
 * Unit tests for the context variable interpolator.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContextInterpolator::class)]
final class ContextInterpolatorTest extends TestCase
{
    /** @var \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator The interpolator under test. */
    private ContextInterpolator $interpolator;

    /**
     * Set up the test fixtures.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->interpolator = new ContextInterpolator;
    }

    /**
     * `${principal.id}` resolves to the principal's key via getAttribute.
     *
     * @return void
     */
    public function testPrincipalIdResolvesFromGetAttribute(): void
    {
        $principal = new class {
            /**
             * @param  string  $key
             * @return int|string|null
             */
            public function getAttribute(string $key): int|string|null
            {
                return match ($key) {
                    'id'    => 42,
                    'name'  => 'Alice',
                    default => null,
                };
            }
        };

        $result = $this->interpolator->interpolate('user:${principal.id}', $principal, null, []);

        self::assertSame('user:42', $result);
    }

    /**
     * `${context.tenant_id}` resolves from the context array.
     *
     * @return void
     */
    public function testContextKeyResolvesFromArray(): void
    {
        $result = $this->interpolator->interpolate(
            'tenant:${context.tenant_id}',
            null,
            null,
            ['tenant_id' => 'org-42'],
        );

        self::assertSame('tenant:org-42', $result);
    }

    /**
     * `${resource.id}` extracts the segment after `:` from the resource string.
     *
     * @return void
     */
    public function testResourceIdExtractsAfterColon(): void
    {
        $result = $this->interpolator->interpolate(
            'post:${resource.id}',
            null,
            'posts:99',
            [],
        );

        self::assertSame('post:99', $result);
    }

    /**
     * `${resource.type}` extracts the segment before `:` from the resource string.
     *
     * @return void
     */
    public function testResourceTypeExtractsBeforeColon(): void
    {
        $result = $this->interpolator->interpolate(
            'type:${resource.type}',
            null,
            'posts:99',
            [],
        );

        self::assertSame('type:posts', $result);
    }

    /**
     * Resource without colon returns full string for both id and type.
     *
     * @return void
     */
    public function testResourceWithoutColonReturnsFullString(): void
    {
        $result = $this->interpolator->interpolate(
            '${resource.id}-${resource.type}',
            null,
            'global',
            [],
        );

        self::assertSame('global-global', $result);
    }

    /**
     * Unknown key resolves to empty string.
     *
     * @return void
     */
    public function testUnknownKeyResolvesToEmptyString(): void
    {
        $result = $this->interpolator->interpolate(
            'prefix:${unknown.key}:suffix',
            null,
            null,
            [],
        );

        self::assertSame('prefix::suffix', $result);
    }

    /**
     * `\${escaped}` passes through as literal `${escaped}`.
     *
     * @return void
     */
    public function testEscapedTokenPassesThroughAsLiteral(): void
    {
        $result = $this->interpolator->interpolate(
            'literal:\${not.interpolated}',
            null,
            null,
            [],
        );

        self::assertSame('literal:${not.interpolated}', $result);
    }

    /**
     * Multiple tokens in one string all resolve.
     *
     * @return void
     */
    public function testMultipleTokensAllResolve(): void
    {
        $principal = new class {
            /**
             * @param  string  $key
             * @return int|null
             */
            public function getAttribute(string $key): ?int
            {
                return $key === 'id' ? 7 : null;
            }
        };

        $result = $this->interpolator->interpolate(
            '${principal.id}:${context.env}:${resource.type}',
            $principal,
            'posts:1',
            ['env' => 'prod'],
        );

        self::assertSame('7:prod:posts', $result);
    }

    /**
     * Nested dot-notation `${context.request.ip}` works.
     *
     * @return void
     */
    public function testNestedDotNotationContext(): void
    {
        $result = $this->interpolator->interpolate(
            'ip:${context.request.ip}',
            null,
            null,
            ['request' => ['ip' => '10.0.0.1']],
        );

        self::assertSame('ip:10.0.0.1', $result);
    }

    /**
     * `${principal.type}` returns morphClass when available.
     *
     * @return void
     */
    public function testPrincipalTypeReturnsMorphClass(): void
    {
        $principal = new class {
            /**
             * @return string
             */
            public function getMorphClass(): string
            {
                return 'user';
            }
        };

        $result = $this->interpolator->interpolate(
            'type:${principal.type}',
            $principal,
            null,
            [],
        );

        self::assertSame('type:user', $result);
    }

    /**
     * `${principal.type}` falls back to class name when no morphClass.
     *
     * @return void
     */
    public function testPrincipalTypeFallsBackToClassName(): void
    {
        $principal = new \stdClass;

        $result = $this->interpolator->interpolate(
            '${principal.type}',
            $principal,
            null,
            [],
        );

        self::assertSame(\stdClass::class, $result);
    }

    /**
     * Principal property access works on plain objects.
     *
     * @return void
     */
    public function testPrincipalPropertyAccessOnPlainObject(): void
    {
        $principal     = new \stdClass;
        $principal->id = 'abc';

        $result = $this->interpolator->interpolate(
            'id:${principal.id}',
            $principal,
            null,
            [],
        );

        self::assertSame('id:abc', $result);
    }

    /**
     * Null principal resolves principal tokens to empty string.
     *
     * @return void
     */
    public function testNullPrincipalResolvesToEmptyString(): void
    {
        $result = $this->interpolator->interpolate(
            'user:${principal.id}',
            null,
            null,
            [],
        );

        self::assertSame('user:', $result);
    }

    /**
     * Null resource resolves resource tokens to empty string.
     *
     * @return void
     */
    public function testNullResourceResolvesToEmptyString(): void
    {
        $result = $this->interpolator->interpolate(
            'res:${resource.id}',
            null,
            null,
            [],
        );

        self::assertSame('res:', $result);
    }

    /**
     * Non-scalar getAttribute return resolves to empty string.
     *
     * @return void
     */
    public function testNonScalarGetAttributeResolvesToEmptyString(): void
    {
        $principal = new class {
            /**
             * Return a non-scalar value regardless of the requested key.
             *
             * @param  string  $key
             * @return array<string, string>
             */
            public function getAttribute(string $key): array
            {
                return [$key => 'array'];
            }
        };

        $result = $this->interpolator->interpolate(
            'val:${principal.metadata}',
            $principal,
            null,
            [],
        );

        self::assertSame('val:', $result);
    }

    /**
     * Pattern with no tokens passes through unchanged.
     *
     * @return void
     */
    public function testPatternWithNoTokensPassesThrough(): void
    {
        $result = $this->interpolator->interpolate(
            'static:pattern',
            null,
            null,
            [],
        );

        self::assertSame('static:pattern', $result);
    }

    /**
     * Unknown resource key resolves to empty string.
     *
     * @return void
     */
    public function testUnknownResourceKeyResolvesToEmptyString(): void
    {
        $result = $this->interpolator->interpolate(
            '${resource.unknown}',
            null,
            'posts:1',
            [],
        );

        self::assertSame('', $result);
    }

    /**
     * Empty key within a known namespace resolves to empty string.
     *
     * @return void
     */
    public function testEmptySubkeyResolvesToEmptyString(): void
    {
        // Token without a dot after namespace is a bare namespace — no sub-key
        $result = $this->interpolator->interpolate(
            '${context}',
            null,
            null,
            ['key' => 'value'],
        );

        // 'context' alone (no dot sub-key) should resolve to empty
        self::assertSame('', $result);
    }
}
