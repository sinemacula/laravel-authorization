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

    /**
     * The sid defaults to null and is stored when given.
     *
     * @return void
     */
    public function testSidDefaultsToNullAndIsStored(): void
    {
        self::assertNull((new StatementReference('billing', 3, 'policy-key'))->sid);

        $reference = new StatementReference('billing', 3, 'policy-key', 'AllowRead');

        self::assertSame('policy-key', $reference->policyId);
        self::assertSame('AllowRead', $reference->sid);
        self::assertSame('AllowRead', (new StatementReference('billing', 3, sid: 'AllowRead'))->sid);
    }

    /**
     * toString() appends the sid, JSON-encoded, after the statement's position,
     * with or without the stored key, and nothing when there is no sid.
     *
     * @return void
     */
    public function testToStringAppendsTheSid(): void
    {
        self::assertSame('billing[policy-key]#3 sid="AllowRead"', (new StatementReference('billing', 3, 'policy-key', 'AllowRead'))->toString());
        self::assertSame('billing#3 sid="Allow.read:posts-1"', (new StatementReference('billing', 3, null, 'Allow.read:posts-1'))->toString());
        self::assertSame('billing[policy-key]#3', (new StatementReference('billing', 3, 'policy-key', null))->toString());
    }

    /**
     * toString() encodes a sid of a directly built reference as JSON, so a
     * quote or a backslash in it cannot break the line, while a slash is left
     * as it is.
     *
     * @return void
     */
    public function testToStringEncodesTheSidAsJson(): void
    {
        self::assertSame('p#0 sid="a\"b"', (new StatementReference('p', 0, null, 'a"b'))->toString());
        self::assertSame('p#0 sid="a\\\b"', (new StatementReference('p', 0, null, 'a\b'))->toString());
        self::assertSame('p#0 sid="a/b"', (new StatementReference('p', 0, null, 'a/b'))->toString());
        self::assertSame('p#0 sid="a\ufffd"', (new StatementReference('p', 0, null, "a\xff"))->toString());
    }

    /**
     * A statement of a resource policy names the resource its policy is
     * attached to, JSON-encoded after the sid; any other names none.
     *
     * @return void
     */
    public function testToStringNamesTheResourceOfAResourcePolicy(): void
    {
        self::assertSame('sharing[key]#0 sid="share" on "posts:7"', (new StatementReference('sharing', 0, 'key', 'share', 'posts:7'))->toString());
        self::assertSame('sharing#2 on "App/Post:*"', (new StatementReference('sharing', 2, resource: 'App/Post:*'))->toString());
        self::assertSame('sharing#2', (new StatementReference('sharing', 2))->toString());
        self::assertNull((new StatementReference('sharing', 2))->resource);
    }
}
