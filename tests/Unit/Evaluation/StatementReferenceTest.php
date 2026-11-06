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
     * The policy's stored key defaults to null, as for a policy built in code,
     * and is stored when given.
     *
     * @return void
     */
    public function testPolicyIdDefaultsToNullAndIsStored(): void
    {
        self::assertNull((new StatementReference('billing', 3))->policyId);

        $reference = new StatementReference('billing', 3, 'policy-key');

        self::assertSame('billing', $reference->policy);
        self::assertSame(3, $reference->index);
        self::assertSame('policy-key', $reference->policyId);
    }

    /**
     * toString() joins the policy's name and the statement's position with a
     * hash when the policy has no stored key, as for a policy built in code.
     *
     * @return void
     */
    public function testToStringJoinsPolicyAndIndex(): void
    {
        self::assertSame('billing#3', (new StatementReference('billing', 3))->toString());
        self::assertSame('p#0', (new StatementReference('p', 0))->toString());
        self::assertSame('p#0', (new StatementReference('p', 0, null))->toString());
    }

    /**
     * toString() puts the policy's stored key in brackets between its name and
     * the statement's position, so policies of one name are told apart.
     *
     * @return void
     */
    public function testToStringIncludesTheStoredKey(): void
    {
        self::assertSame('billing[policy-key]#3', (new StatementReference('billing', 3, 'policy-key'))->toString());
        self::assertSame('p[0]#0', (new StatementReference('p', 0, '0'))->toString());
    }
}
