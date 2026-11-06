<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement;

/**
 * Unit tests for a candidate of an insufficient authentication: the requirement
 * and its unmet parts.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UnmetRequirement::class)]
final class UnmetRequirementTest extends TestCase
{
    /**
     * It keeps the requirement and the unmet parts, and gives them as an array
     * of the requirement's options and the part names.
     *
     * @return void
     */
    public function testKeepsTheRequirementAndItsUnmetParts(): void
    {
        $requirement = new AuthenticationRequirement(['multifactor' => 900, 'phishing_resistant' => null]);
        $unmet       = new UnmetRequirement($requirement, ['multifactor']);

        self::assertSame($requirement, $unmet->requirement);
        self::assertSame(['multifactor'], $unmet->unmet);
        self::assertSame([
            'requirement' => ['multifactor' => ['max_age' => 900], 'phishing_resistant' => ['max_age' => null]],
            'unmet'       => ['multifactor'],
        ], $unmet->toArray());
    }
}
