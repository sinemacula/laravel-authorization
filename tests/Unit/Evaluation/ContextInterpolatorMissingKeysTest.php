<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator;

/**
 * Coverage for the missing-key fallback in `ContextInterpolator`
 * when the principal is a plain object that exposes neither a
 * `getAttribute()` method nor a matching public property. Consumers
 * who pass an arbitrary DTO as the principal rely on this path to
 * avoid `Undefined property` warnings during interpolation — the
 * interpolator returns null for the token, and the surrounding
 * `interpolate()` renders it as the empty string.
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
     * A plain object principal whose property does not exist
     * resolves the token to the empty string instead of raising.
     *
     * @return void
     */
    public function testUnknownPropertyOnPlainObjectResolvesToEmpty(): void
    {
        $interpolator = new ContextInterpolator;
        $principal    = new \stdClass;
        // No `id` property set.

        $result = $interpolator->interpolate(
            'id:${principal.id}',
            $principal,
            null,
            [],
        );

        self::assertSame('id:', $result);
    }
}
