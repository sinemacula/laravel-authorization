<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator;
use SineMacula\Laravel\Authorization\Evaluation\InterpolationScope;

/**
 * Unit tests for the interpolation scope value object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(InterpolationScope::class)]
final class InterpolationScopeTest extends TestCase
{
    /**
     * The constructor defaults to no interpolator, no principal, no resource
     * and an empty context.
     *
     * @return void
     */
    public function testConstructorDefaults(): void
    {
        $scope = new InterpolationScope;

        self::assertNull($scope->interpolator);
        self::assertNull($scope->principal);
        self::assertNull($scope->resource);
        self::assertSame([], $scope->context);
    }

    /**
     * The constructor stores every supplied argument.
     *
     * @return void
     */
    public function testConstructorStoresArguments(): void
    {
        $interpolator = new ContextInterpolator;
        $principal    = new \stdClass;

        $scope = new InterpolationScope($interpolator, $principal, 'posts:9', ['env' => 'prod']);

        self::assertSame($interpolator, $scope->interpolator);
        self::assertSame($principal, $scope->principal);
        self::assertSame('posts:9', $scope->resource);
        self::assertSame(['env' => 'prod'], $scope->context);
    }

    /**
     * Without an interpolator, `literal()` returns the subject unchanged, with
     * its tokens, escapes and backslashes left literal.
     *
     * @return void
     */
    public function testLiteralWithoutInterpolatorReturnsSubjectUnchanged(): void
    {
        $scope = new InterpolationScope(null, null, 'posts:9', ['a' => 'value']);

        self::assertSame('App\Models\Post:${context.a}', $scope->literal('App\Models\Post:${context.a}'));
        self::assertSame('\${context.a}:${context-a}', $scope->literal('\${context.a}:${context-a}'));
        self::assertSame('', $scope->literal(''));
    }

    /**
     * Without an interpolator, `pattern()` doubles backslashes and keeps glob
     * characters and tokens as they are.
     *
     * @return void
     */
    public function testPatternWithoutInterpolatorDoublesBackslashes(): void
    {
        $scope = new InterpolationScope(null, null, 'posts:9', ['a' => 'value']);

        $pattern = $scope->pattern('App\Models\*:${context.a}?[ab]');

        self::assertSame('App\\\Models\\\*:${context.a}?[ab]', $pattern);
        self::assertTrue(\fnmatch($pattern, 'App\Models\Post:${context.a}xa'));
        self::assertFalse(\fnmatch($pattern, 'App\Models\Post:value?[ab]'));
    }

    /**
     * With an interpolator, `literal()` substitutes each token and keeps the
     * literal text, escapes and backslashes as an interpolated string.
     *
     * @return void
     */
    public function testLiteralWithInterpolatorSubstitutesTokens(): void
    {
        $scope = new InterpolationScope(new ContextInterpolator, null, null, ['a' => 'value*']);

        self::assertSame('App\Models\Post:value*', $scope->literal('App\Models\Post:${context.a}'));
        self::assertSame('${context.a}:value*', $scope->literal('\${context.a}:${context.a}'));
    }

    /**
     * With an interpolator, `pattern()` escapes substituted values so they only
     * match themselves, while the pattern's own text keeps its glob meaning.
     *
     * @return void
     */
    public function testPatternWithInterpolatorEscapesSubstitutedValues(): void
    {
        $scope = new InterpolationScope(new ContextInterpolator, null, null, ['a' => 'v*']);

        $pattern = $scope->pattern('App\Models\*:${context.a}');

        self::assertSame('App\\\Models\\\*:v\*', $pattern);
        self::assertTrue(\fnmatch($pattern, 'App\Models\Post:v*'));
        self::assertFalse(\fnmatch($pattern, 'App\Models\Post:vx'));
    }

    /**
     * With an interpolator, an unresolved token makes both `literal()` and
     * `pattern()` return null.
     *
     * @return void
     */
    public function testUnresolvedTokenIsNull(): void
    {
        $scope = new InterpolationScope(new ContextInterpolator, null, 'global', ['a' => 'value']);

        self::assertNull($scope->literal('${context.a}:${context.missing}'));
        self::assertNull($scope->pattern('docs:${resource.id}'));
    }

    /**
     * With an interpolator, a malformed reference makes both `literal()` and
     * `pattern()` return null, even beside a token that resolves.
     *
     * @return void
     */
    public function testMalformedReferenceIsNull(): void
    {
        $scope = new InterpolationScope(new ContextInterpolator, null, null, ['a' => 'value']);

        self::assertNull($scope->literal('${context.a}:${context.tenant-id}'));
        self::assertNull($scope->pattern('${context.a}/${}*'));
    }

    /**
     * The scope's principal, resource and context are each passed to the
     * interpolator, in both literal and pattern mode.
     *
     * @return void
     */
    public function testPrincipalResourceAndContextArePassedThrough(): void
    {
        $principal     = new \stdClass;
        $principal->id = 'p1';

        $scope = new InterpolationScope(new ContextInterpolator, $principal, 'posts:9', ['env' => 'prod']);

        self::assertSame('p1', $scope->literal('${principal.id}'));
        self::assertSame('9', $scope->literal('${resource.id}'));
        self::assertSame('prod', $scope->literal('${context.env}'));
        self::assertSame('p1|posts|prod', $scope->literal('${principal.id}|${resource.type}|${context.env}'));

        self::assertSame('p1', $scope->pattern('${principal.id}'));
        self::assertSame('9', $scope->pattern('${resource.id}'));
        self::assertSame('prod', $scope->pattern('${context.env}'));
        self::assertSame('p1/posts/prod/*', $scope->pattern('${principal.id}/${resource.type}/${context.env}/*'));
    }
}
