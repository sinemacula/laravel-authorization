<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator;

/**
 * Coverage for the missing-key fallback in `ContextInterpolator`: a token whose
 * key is missing, or present with a null value, is unresolved, so
 * `interpolate()` returns null and the statement treats the test as undecidable
 * rather than comparing against an empty string.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ContextInterpolator::class)]
final class ContextInterpolatorMissingKeysTest extends TestCase
{
    /**
     * A subject or resource attribute the namespace does not hold, or holds as
     * null, leaves the token unresolved, in a pattern as in a literal string.
     *
     * @return void
     */
    public function testMissingAndNullAttributesAreUnresolved(): void
    {
        $interpolator = new ContextInterpolator;
        $context      = ['subject' => ['id' => '7', 'team' => null], 'resource' => ['type' => 'post']];

        self::assertNull($interpolator->interpolate('team:${subject.team}', $context));
        self::assertNull($interpolator->interpolate('dept:${subject.department}', $context));
        self::assertNull($interpolator->interpolatePattern('post:${resource.id}', $context));
        self::assertSame('user:7', $interpolator->interpolate('user:${subject.id}', $context));
    }

    /**
     * A context path whose namespace or key is missing, or whose value is a
     * present null, leaves the token unresolved, so a request that was never
     * routed never interpolates `${request.ip}` as an empty string.
     *
     * @return void
     */
    public function testMissingAndNullContextPathsAreUnresolved(): void
    {
        $interpolator = new ContextInterpolator;

        self::assertNull($interpolator->interpolate('ip:${request.ip}', []));
        self::assertNull($interpolator->interpolate('ip:${request.ip}', ['request' => []]));
        self::assertNull($interpolator->interpolate('ip:${request.ip}', ['request' => ['ip' => null]]));
        self::assertNull($interpolator->interpolatePattern('ip:${request.ip}', ['request.ip' => '10.0.0.1']));
        self::assertSame('ip:10.0.0.1', $interpolator->interpolate('ip:${request.ip}', ['request' => ['ip' => '10.0.0.1']]));
    }
}
