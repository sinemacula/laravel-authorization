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

    // ------------------------------------------------------------------
    // Mutation-kill: interpolate method (lines 54, 57)
    // ------------------------------------------------------------------

    /**
     * When preg_replace_callback returns null (regex failure), the
     * coalesce (`$result ?? $pattern`) falls back to the original
     * pattern. Kills the Coalesce mutant on line 57.
     *
     * In practice preg_replace_callback returns a string, so we
     * verify the happy path: the result is the str_replace output,
     * not the raw preg_replace_callback output.
     *
     * @return void
     */
    public function testEscapedAndUnescapedTokensInSameString(): void
    {
        $result = $this->interpolator->interpolate(
            '${context.a}:\${literal}',
            null,
            null,
            ['a' => 'resolved'],
        );

        // The `${context.a}` token resolves, the `\${literal}` unescapes to `${literal}`
        self::assertSame('resolved:${literal}', $result);
    }

    // ------------------------------------------------------------------
    // Mutation-kill: resolveToken namespace/key splitting (lines 72-73)
    // ------------------------------------------------------------------

    /**
     * The dot-position split must correctly extract namespace and key.
     * Decrementing/incrementing the integer offsets (DecrementInteger,
     * IncrementInteger) or unwrapping substr (UnwrapSubstr) would
     * corrupt the namespace or key.
     *
     * @return void
     */
    public function testResolveTokenSplitsNamespaceAndKeyCorrectly(): void
    {
        // "context.tenant_id" should split to namespace="context", key="tenant_id"
        $result = $this->interpolator->interpolate(
            '${context.tenant_id}',
            null,
            null,
            ['tenant_id' => 'org-1'],
        );

        self::assertSame('org-1', $result);
    }

    /**
     * Token without a dot: namespace = full token, key = ''.
     * Kills the Ternary mutant that swaps the branches on line 72/73.
     *
     * @return void
     */
    public function testTokenWithoutDotUsesFullTokenAsNamespace(): void
    {
        // 'context' alone with no dot → namespace='context', key=''
        // Empty key on context → null → empty string
        $result = $this->interpolator->interpolate(
            '${context}',
            null,
            null,
            ['tenant' => 'org-1'],
        );

        self::assertSame('', $result);

        // 'principal' alone with no dot → namespace='principal', key=''
        // Empty key on principal → null → empty string
        $result = $this->interpolator->interpolate(
            '${principal}',
            new \stdClass,
            null,
            [],
        );

        self::assertSame('', $result);
    }

    // ------------------------------------------------------------------
    // Mutation-kill: resolveToken match arms (line 75)
    // ------------------------------------------------------------------

    /**
     * Each namespace arm (principal, context, resource) must route to
     * the correct resolver. Removing any arm (MatchArmRemoval) would
     * cause a `\UnhandledMatchError` or misroute.
     *
     * @return void
     */
    public function testAllNamespaceArmsRoute(): void
    {
        $principal = new class {
            /**
             * @param  string  $key
             * @return string|null
             */
            public function getAttribute(string $key): ?string
            {
                return $key === 'name' ? 'Alice' : null;
            }
        };

        // principal namespace
        $result = $this->interpolator->interpolate('${principal.name}', $principal, null, []);
        self::assertSame('Alice', $result);

        // context namespace
        $result = $this->interpolator->interpolate('${context.env}', null, null, ['env' => 'prod']);
        self::assertSame('prod', $result);

        // resource namespace
        $result = $this->interpolator->interpolate('${resource.id}', null, 'posts:42', []);
        self::assertSame('42', $result);

        // default (unknown) namespace
        $result = $this->interpolator->interpolate('${unknown.key}', null, null, []);
        self::assertSame('', $result);
    }

    // ------------------------------------------------------------------
    // Mutation-kill: resolvePrincipal (lines 100, 104, 115, 123)
    // ------------------------------------------------------------------

    /**
     * Null principal OR empty key → null. Both conditions individually
     * must fail. Kills the Identical/LogicalOr mutants on line 100.
     *
     * @return void
     */
    public function testResolvePrincipalNullPrincipalOrEmptyKeyReturnsNull(): void
    {
        // Null principal → empty
        $result = $this->interpolator->interpolate('${principal.id}', null, null, []);
        self::assertSame('', $result);

        // Non-null principal but empty key → empty (bare `${principal}`)
        $result = $this->interpolator->interpolate('${principal}', new \stdClass, null, []);
        self::assertSame('', $result);

        // Non-null principal and non-empty key → resolves
        $principal     = new \stdClass;
        $principal->id = 'abc';
        $result        = $this->interpolator->interpolate('${principal.id}', $principal, null, []);
        self::assertSame('abc', $result);
    }

    /**
     * `key === 'type'` check on line 104 routes to resolvePrincipalType.
     * Negating the Identical would skip it.
     *
     * @return void
     */
    public function testPrincipalTypeKeyRoutesToTypeResolver(): void
    {
        $principal = new class {
            /**
             * @return string
             */
            public function getMorphClass(): string
            {
                return 'user';
            }

            /**
             * @param  string  $key
             * @return string|null
             */
            public function getAttribute(string $key): ?string
            {
                return $key === 'type' ? 'wrong-path' : null;
            }
        };

        // 'type' key should go through getMorphClass, not getAttribute
        $result = $this->interpolator->interpolate('${principal.type}', $principal, null, []);
        self::assertSame('user', $result);
    }

    /**
     * ElseIfNegation on line 115: when the principal has no getAttribute
     * but has a matching property, property_exists should be used.
     * Negating it would skip property access.
     *
     * @return void
     */
    public function testPlainObjectPropertyAccessPath(): void
    {
        $principal       = new \stdClass;
        $principal->name = 'Bob';

        $result = $this->interpolator->interpolate('${principal.name}', $principal, null, []);
        self::assertSame('Bob', $result);
    }

    /**
     * Ternary on line 123: scalar values return as-is, non-scalar → null.
     *
     * @return void
     */
    public function testNonScalarPropertyResolvesToEmpty(): void
    {
        $principal        = new \stdClass;
        $principal->items = ['a', 'b'];

        $result = $this->interpolator->interpolate('${principal.items}', $principal, null, []);
        self::assertSame('', $result);
    }

    // ------------------------------------------------------------------
    // Mutation-kill: resolveContext (lines 154, 161)
    // ------------------------------------------------------------------

    /**
     * Empty key in context → null. Kills the Identical mutant on line 154.
     *
     * @return void
     */
    public function testResolveContextEmptyKeyReturnsNull(): void
    {
        $result = $this->interpolator->interpolate('${context}', null, null, ['key' => 'val']);
        self::assertSame('', $result);
    }

    /**
     * Non-scalar context value → null → empty string. Kills the
     * Ternary mutant on line 161.
     *
     * @return void
     */
    public function testResolveContextNonScalarReturnsEmpty(): void
    {
        $result = $this->interpolator->interpolate(
            '${context.nested}',
            null,
            null,
            ['nested' => ['a' => 'b']],
        );

        self::assertSame('', $result);
    }

    /**
     * Scalar context value returns correctly.
     *
     * @return void
     */
    public function testResolveContextScalarReturns(): void
    {
        $result = $this->interpolator->interpolate(
            '${context.count}',
            null,
            null,
            ['count' => 42],
        );

        self::assertSame('42', $result);
    }

    // ------------------------------------------------------------------
    // Mutation-kill: resolveResource (lines 177, 183-185)
    // ------------------------------------------------------------------

    /**
     * Null resource OR empty key → null. Kills LogicalOr and Identical
     * mutants on line 177.
     *
     * @return void
     */
    public function testResolveResourceNullOrEmptyKeyReturnsNull(): void
    {
        // Null resource → empty
        $result = $this->interpolator->interpolate('${resource.id}', null, null, []);
        self::assertSame('', $result);

        // Non-null resource but empty key (bare `${resource}`)
        $result = $this->interpolator->interpolate('${resource}', null, 'posts:42', []);
        self::assertSame('', $result);
    }

    /**
     * Resource id/type with colon splits correctly. Without colon,
     * both return full string. Kills MatchArmRemoval on line 183 and
     * the substr mutants on lines 184-185.
     *
     * @return void
     */
    public function testResolveResourceIdAndTypeWithAndWithoutColon(): void
    {
        // With colon: id = after colon, type = before colon
        $resultId = $this->interpolator->interpolate('${resource.id}', null, 'posts:42', []);
        self::assertSame('42', $resultId);

        $resultType = $this->interpolator->interpolate('${resource.type}', null, 'posts:42', []);
        self::assertSame('posts', $resultType);

        // Without colon: both return full string
        $resultId = $this->interpolator->interpolate('${resource.id}', null, 'global', []);
        self::assertSame('global', $resultId);

        $resultType = $this->interpolator->interpolate('${resource.type}', null, 'global', []);
        self::assertSame('global', $resultType);

        // Unknown resource key → empty
        $resultUnknown = $this->interpolator->interpolate('${resource.foo}', null, 'posts:42', []);
        self::assertSame('', $resultUnknown);
    }

    /**
     * The colon-position arithmetic in substr must be exact.
     * `colonPos + 1` for id means the character after the colon.
     * `0, colonPos` for type means everything before the colon.
     * Decrementing/incrementing these would shift the boundary.
     *
     * @return void
     */
    public function testResourceColonSplitBoundaryPrecision(): void
    {
        // Single-char segments around a colon
        $resultId = $this->interpolator->interpolate('${resource.id}', null, 'A:B', []);
        self::assertSame('B', $resultId);

        $resultType = $this->interpolator->interpolate('${resource.type}', null, 'A:B', []);
        self::assertSame('A', $resultType);

        // Colon at start
        $resultId = $this->interpolator->interpolate('${resource.id}', null, ':trailing', []);
        self::assertSame('trailing', $resultId);

        $resultType = $this->interpolator->interpolate('${resource.type}', null, ':trailing', []);
        self::assertSame('', $resultType);

        // Colon at end
        $resultId = $this->interpolator->interpolate('${resource.id}', null, 'leading:', []);
        self::assertSame('', $resultId);

        $resultType = $this->interpolator->interpolate('${resource.type}', null, 'leading:', []);
        self::assertSame('leading', $resultType);
    }

    /**
     * The `$value === null` check on line 82 distinguishes unresolved
     * tokens from resolved empty strings. Negating it would print the
     * null value instead of logging and returning empty.
     *
     * @return void
     */
    public function testNullValueTriggersLogAndReturnsEmpty(): void
    {
        // Unknown namespace → null → empty string
        $result = $this->interpolator->interpolate('${bogus.key}', null, null, []);
        self::assertSame('', $result);

        // Known namespace, valid key → non-null → actual value
        $result = $this->interpolator->interpolate('${context.x}', null, null, ['x' => 'val']);
        self::assertSame('val', $result);
    }
}
