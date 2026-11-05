<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator;

/**
 * Coverage for the missing-key fallback in `ContextInterpolator` when the
 * principal is a plain object without a matching public property. Consumers who
 * pass an arbitrary DTO as the principal rely on this path to avoid `Undefined
 * property` warnings during interpolation: the token is unresolved, so
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
     * A plain object principal whose property does not exist leaves the token
     * unresolved instead of raising or substituting an empty string.
     *
     * @return void
     */
    public function testUnknownPropertyOnPlainObjectIsUnresolved(): void
    {
        $interpolator = new ContextInterpolator;
        $principal    = new \stdClass;
        // No `id` property set.
        $interpolated = $interpolator->interpolate(
            'id:${principal.id}',
            $principal,
            null,
            [],
        );

        self::assertNull($interpolated);
    }

    /**
     * A plain object principal whose property exists but holds null leaves the
     * token unresolved, in a pattern as in a literal string.
     *
     * @return void
     */
    public function testNullPropertyOnPlainObjectIsUnresolved(): void
    {
        $interpolator  = new ContextInterpolator;
        $principal     = new \stdClass;
        $principal->id = null;

        self::assertNull($interpolator->interpolate('id:${principal.id}', $principal, null, []));
        self::assertNull($interpolator->interpolatePattern('id:${principal.id}', $principal, null, []));
    }
}
