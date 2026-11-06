<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;

/**
 * Unit tests for the statement reference value object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StatementReference::class)]
final class StatementReferenceTest extends TestCase
{
    /**
     * The constructor stores the policy's name and the statement's position.
     *
     * @return void
     */
    public function testConstructorStoresPolicyAndIndex(): void
    {
        $reference = new StatementReference('billing', 3);

        self::assertSame('billing', $reference->policy);
        self::assertSame(3, $reference->index);
    }

    /**
     * toString() joins the policy's name and the statement's position with a
     * hash.
     *
     * @return void
     */
    public function testToStringJoinsPolicyAndIndex(): void
    {
        self::assertSame('billing#3', (new StatementReference('billing', 3))->toString());
        self::assertSame('p#0', (new StatementReference('p', 0))->toString());
    }
}
