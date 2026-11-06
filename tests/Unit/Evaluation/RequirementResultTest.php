<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;

/**
 * Unit tests for what a requirement checker finds: met, with the instant it
 * stays met until, or unmet, with the parts that are not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequirementResult::class)]
final class RequirementResultTest extends TestCase
{
    /**
     * A met result has no unmet parts, and keeps the instant it is met until.
     *
     * @return void
     */
    public function testMetKeepsTheInstant(): void
    {
        $until  = new \DateTimeImmutable('2026-11-06 12:15:00');
        $result = RequirementResult::met($until);

        self::assertTrue($result->isMet);
        self::assertSame([], $result->unmet);
        self::assertSame($until, $result->metUntil);
    }

    /**
     * A met result may give no instant.
     *
     * @return void
     */
    public function testMetMayGiveNoInstant(): void
    {
        self::assertNull(RequirementResult::met()->metUntil);
    }

    /**
     * An unmet result keeps its unmet parts and has no instant.
     *
     * @return void
     */
    public function testUnmetKeepsTheParts(): void
    {
        $result = RequirementResult::unmet(['multifactor', 'phishing_resistant']);

        self::assertFalse($result->isMet);
        self::assertSame(['multifactor', 'phishing_resistant'], $result->unmet);
        self::assertNull($result->metUntil);
    }

    /**
     * A met result with unmet parts is refused.
     *
     * @return void
     */
    public function testRefusesAMetResultWithUnmetParts(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A met authentication requirement has no unmet parts.');

        new RequirementResult(true, ['multifactor']);
    }

    /**
     * An unmet result with an instant it is met until is refused.
     *
     * @return void
     */
    public function testRefusesAnUnmetResultWithAnInstant(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Only a met authentication requirement stays met until an instant.');

        new RequirementResult(false, ['multifactor'], new \DateTimeImmutable);
    }
}
