<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator;
use SineMacula\Laravel\Authorization\Evaluation\Statement;

/**
 * Unit tests for the policy statement value object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Statement::class)]
#[CoversClass(ConditionEvaluator::class)]
#[CoversClass(ContextInterpolator::class)]
final class StatementTest extends TestCase
{
    /**
     * Round-trip a minimal statement through fromArray/toArray.
     *
     * @return void
     */
    public function testRoundTripsThroughArray(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['posts:create'],
            'resources'  => ['arn:posts:1'],
            'conditions' => ['tenant' => ['eq' => 'org-1']],
        ]);

        self::assertSame(PolicyEffect::ALLOW, $statement->effect);
        self::assertSame(['posts:create'], $statement->actions);
        self::assertSame(['arn:posts:1'], $statement->resources);
        self::assertSame(['tenant' => ['eq' => 'org-1']], $statement->conditions);

        $array = $statement->toArray();
        self::assertSame('allow', $array['effect']);
        self::assertSame(['posts:create'], $array['actions']);
    }

    /**
     * Defaults when resources / conditions are omitted.
     *
     * @return void
     */
    public function testDefaultsResourcesToWildcardAndOmitsEmptyConditions(): void
    {
        $statement = Statement::fromArray([
            'effect'  => 'deny',
            'actions' => ['posts:delete'],
        ]);

        self::assertSame(['*'], $statement->resources);
        self::assertSame([], $statement->conditions);
        self::assertArrayNotHasKey('conditions', $statement->toArray());
    }

    /**
     * Reject a missing effect.
     *
     * @return void
     */
    public function testRejectsMissingEffect(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Statement::fromArray(['actions' => ['x']]);
    }

    /**
     * Reject an invalid effect.
     *
     * @return void
     */
    public function testRejectsInvalidEffect(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Statement::fromArray(['effect' => 'audit', 'actions' => ['x']]);
    }

    /**
     * Reject missing actions.
     *
     * @return void
     */
    public function testRejectsMissingActions(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Statement::fromArray(['effect' => 'allow']);
    }

    /**
     * Reject empty actions.
     *
     * @return void
     */
    public function testRejectsEmptyActions(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Statement::fromArray(['effect' => 'allow', 'actions' => []]);
    }

    /**
     * Reject non-string actions.
     *
     * @return void
     */
    public function testRejectsNonStringActions(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        // @phpstan-ignore-next-line
        Statement::fromArray(['effect' => 'allow', 'actions' => [123]]);
    }

    /**
     * Reject non-array resources.
     *
     * @return void
     */
    public function testRejectsNonArrayResources(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        // @phpstan-ignore-next-line
        Statement::fromArray(['effect' => 'allow', 'actions' => ['x'], 'resources' => 'nope']);
    }

    /**
     * Empty resources collapse to wildcard.
     *
     * @return void
     */
    public function testEmptyResourcesCollapseToWildcard(): void
    {
        $statement = Statement::fromArray([
            'effect'    => 'allow',
            'actions'   => ['posts:create'],
            'resources' => [],
        ]);

        self::assertSame(['*'], $statement->resources);
    }

    /**
     * Reject non-string resources.
     *
     * @return void
     */
    public function testRejectsNonStringResources(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        // @phpstan-ignore-next-line
        Statement::fromArray(['effect' => 'allow', 'actions' => ['x'], 'resources' => [42]]);
    }

    /**
     * Reject non-array conditions.
     *
     * @return void
     */
    public function testRejectsNonArrayConditions(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        // @phpstan-ignore-next-line
        Statement::fromArray(['effect' => 'allow', 'actions' => ['x'], 'conditions' => 'nope']);
    }

    /**
     * Reject non-string condition keys.
     *
     * @return void
     */
    public function testRejectsNonStringConditionKeys(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        // @phpstan-ignore-next-line
        Statement::fromArray(['effect' => 'allow', 'actions' => ['x'], 'conditions' => [42 => 'v']]);
    }

    /**
     * Wildcard action matching.
     *
     * @return void
     */
    public function testMatchesWildcardActions(): void
    {
        $statement = Statement::fromArray(['effect' => 'allow', 'actions' => ['posts:*']]);

        self::assertTrue($statement->matches('posts:create'));
        self::assertTrue($statement->matches('posts:delete'));
        self::assertFalse($statement->matches('users:create'));
    }

    /**
     * Wildcard resource matching.
     *
     * @return void
     */
    public function testMatchesWildcardResources(): void
    {
        $statement = Statement::fromArray([
            'effect'    => 'allow',
            'actions'   => ['posts:read'],
            'resources' => ['arn:posts:*'],
        ]);

        self::assertTrue($statement->matches('posts:read', 'arn:posts:1'));
        self::assertTrue($statement->matches('posts:read', 'arn:posts:99'));
        self::assertFalse($statement->matches('posts:read', 'arn:users:1'));
    }

    /**
     * Resource-less match short-circuits to action match.
     *
     * @return void
     */
    public function testResourcelessMatchSkipsResourceCheck(): void
    {
        $statement = Statement::fromArray([
            'effect'    => 'allow',
            'actions'   => ['posts:read'],
            'resources' => ['arn:posts:1'],
        ]);

        self::assertTrue($statement->matches('posts:read'));
    }

    /**
     * Missing context key fails condition without throwing.
     *
     * @return void
     */
    public function testMissingContextKeyFailsCondition(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['tenant' => ['eq' => 'org-1']],
        ]);

        self::assertFalse($statement->evaluateConditions([]));
    }

    /**
     * Scalar condition compared by identity.
     *
     * @return void
     */
    public function testScalarConditionComparedByIdentity(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['tenant' => 'org-1'],
        ]);

        self::assertTrue($statement->evaluateConditions(['tenant' => 'org-1']));
        self::assertFalse($statement->evaluateConditions(['tenant' => 'org-2']));
    }

    /**
     * Unknown operators short-circuit to false.
     *
     * @return void
     */
    public function testUnknownOperatorFailsClosed(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['tenant' => ['unknown_op' => 'org-1']],
        ]);

        self::assertFalse($statement->evaluateConditions(['tenant' => 'org-1']));
    }

    /**
     * Data provider for operators.
     *
     * @return array<string, array{0: array<string, mixed>, 1: array<string, mixed>, 2: bool}>
     */
    public static function operatorProvider(): array
    {
        return [
            'eq-true'             => [['tenant' => ['eq' => 'org-1']], ['tenant' => 'org-1'], true],
            'eq-false'            => [['tenant' => ['eq' => 'org-1']], ['tenant' => 'org-2'], false],
            'neq-true'            => [['tenant' => ['neq' => 'org-1']], ['tenant' => 'org-2'], true],
            'neq-false'           => [['tenant' => ['neq' => 'org-1']], ['tenant' => 'org-1'], false],
            'in-true'             => [['role' => ['in' => ['admin', 'staff']]], ['role' => 'admin'], true],
            'in-false'            => [['role' => ['in' => ['admin', 'staff']]], ['role' => 'guest'], false],
            'in-non-array'        => [['role' => ['in' => 'admin']], ['role' => 'admin'], false],
            'not_in-true'         => [['role' => ['not_in' => ['admin', 'staff']]], ['role' => 'guest'], true],
            'not_in-false'        => [['role' => ['not_in' => ['admin', 'staff']]], ['role' => 'admin'], false],
            'starts_with-true'    => [['email' => ['starts_with' => 'admin@']], ['email' => 'admin@example'], true],
            'ends_with-true'      => [['email' => ['ends_with' => 'sine.co']], ['email' => 'a@sine.co'], true],
            'cidr-match'          => [['ip' => ['cidr' => '192.168.1.0/24']], ['ip' => '192.168.1.25'], true],
            'cidr-no-match'       => [['ip' => ['cidr' => '192.168.1.0/24']], ['ip' => '10.0.0.1'], false],
            'cidr-exact'          => [['ip' => ['cidr' => '192.168.1.1']], ['ip' => '192.168.1.1'], true],
            'cidr-zero-bits'      => [['ip' => ['cidr' => '0.0.0.0/0']], ['ip' => '1.2.3.4'], true],
            'cidr-mask-32-match'  => [['ip' => ['cidr' => '192.168.1.1/32']], ['ip' => '192.168.1.1'], true],
            'cidr-mask-32-miss'   => [['ip' => ['cidr' => '192.168.1.1/32']], ['ip' => '192.168.1.2'], false],
            'cidr-mask-31-match'  => [['ip' => ['cidr' => '192.168.1.0/31']], ['ip' => '192.168.1.1'], true],
            'cidr-mask-31-miss'   => [['ip' => ['cidr' => '192.168.1.0/31']], ['ip' => '192.168.1.2'], false],
            'between-equal-lower' => [['at' => ['between' => ['2026-04-15', '2026-04-20']]], ['at' => '2026-04-15'], true],
            'between-equal-upper' => [['at' => ['between' => ['2026-04-15', '2026-04-20']]], ['at' => '2026-04-20'], true],
            'between-just-below'  => [['at' => ['between' => ['2026-04-15', '2026-04-20']]], ['at' => '2026-04-14'], false],
            'between-just-above'  => [['at' => ['between' => ['2026-04-15', '2026-04-20']]], ['at' => '2026-04-21'], false],
            'before-equal'        => [['at' => ['before' => '2026-04-15']], ['at' => '2026-04-15'], false],
            'after-equal'         => [['at' => ['after' => '2026-04-15']], ['at' => '2026-04-15'], false],
            'cidr-bad-ip'         => [['ip' => ['cidr' => '192.168.1.0/24']], ['ip' => 'not-an-ip'], false],
            'cidr-bad-bits'       => [['ip' => ['cidr' => '192.168.1.0/abc']], ['ip' => '192.168.1.25'], false],
            'cidr-bits-too-big'   => [['ip' => ['cidr' => '192.168.1.0/64']], ['ip' => '192.168.1.25'], false],
            'before-iso'          => [['at' => ['before' => '2026-04-15']], ['at' => '2026-04-14'], true],
            'before-iso-false'    => [['at' => ['before' => '2026-04-15']], ['at' => '2026-04-16'], false],
            'after-iso'           => [['at' => ['after' => '2026-04-15']], ['at' => '2026-04-16'], true],
            'between-iso'         => [['at' => ['between' => ['2026-04-10', '2026-04-20']]], ['at' => '2026-04-15'], true],
            'between-outside'     => [['at' => ['between' => ['2026-04-10', '2026-04-12']]], ['at' => '2026-04-15'], false],
            'between-bad-shape'   => [['at' => ['between' => ['2026-04-10']]], ['at' => '2026-04-15'], false],
            'between-bad-left'    => [['at' => ['between' => ['bad', '2026-04-20']]], ['at' => '2026-04-15'], false],
            'time-invalid'        => [['at' => ['before' => 'not-a-date']], ['at' => '2026-04-14'], false],
            'time-int'            => [['at' => ['before' => 2000000000]], ['at' => 1000000000], true],
            'time-empty-string'   => [['at' => ['before' => '2026-04-15']], ['at' => ''], false],

            // #38 — string_like operator
            'string_like-match'      => [['name' => ['string_like' => 'admin*']], ['name' => 'admin-user'], true],
            'string_like-miss'       => [['name' => ['string_like' => 'admin*']], ['name' => 'guest-user'], false],
            'string_like-question'   => [['name' => ['string_like' => 'user?']], ['name' => 'user1'], true],
            'string_like-non-string' => [['name' => ['string_like' => 'admin*']], ['name' => 123], false],

            // #38 — null / not_null operators
            'null-true'              => [['field' => ['null' => true]], ['field' => null], true],
            'null-false'             => [['field' => ['null' => true]], ['field' => 'value'], false],
            'null-zero-is-not-null'  => [['field' => ['null' => true]], ['field' => 0], false],
            'null-empty-is-not-null' => [['field' => ['null' => true]], ['field' => ''], false],
            'not_null-true'          => [['field' => ['not_null' => true]], ['field' => 'value'], true],
            'not_null-false'         => [['field' => ['not_null' => true]], ['field' => null], false],

            // #38 — numeric comparison operators
            'gt-true'                => [['age' => ['gt' => 18]], ['age' => 21], true],
            'gt-false-equal'         => [['age' => ['gt' => 18]], ['age' => 18], false],
            'gt-false-less'          => [['age' => ['gt' => 18]], ['age' => 16], false],
            'gte-true-equal'         => [['age' => ['gte' => 18]], ['age' => 18], true],
            'gte-true-greater'       => [['age' => ['gte' => 18]], ['age' => 19], true],
            'gte-false'              => [['age' => ['gte' => 18]], ['age' => 17], false],
            'lt-true'                => [['age' => ['lt' => 18]], ['age' => 16], true],
            'lt-false-equal'         => [['age' => ['lt' => 18]], ['age' => 18], false],
            'lt-false-greater'       => [['age' => ['lt' => 18]], ['age' => 21], false],
            'lte-true-equal'         => [['age' => ['lte' => 18]], ['age' => 18], true],
            'lte-true-less'          => [['age' => ['lte' => 18]], ['age' => 17], true],
            'lte-false'              => [['age' => ['lte' => 18]], ['age' => 19], false],
            'gt-string-numeric'      => [['age' => ['gt' => '18']], ['age' => '21'], true],
            'gt-non-numeric-actual'  => [['age' => ['gt' => 18]], ['age' => 'abc'], false],
            'gt-non-numeric-operand' => [['age' => ['gt' => 'abc']], ['age' => 21], false],
            'gt-float'               => [['val' => ['gt' => 1.5]], ['val' => 2.5], true],

            // #38 — bool operator
            'bool-true-string'       => [['flag' => ['bool' => 'true']], ['flag' => true], true],
            'bool-true-int'          => [['flag' => ['bool' => 1]], ['flag' => 'true'], true],
            'bool-true-string-one'   => [['flag' => ['bool' => '1']], ['flag' => true], true],
            'bool-false-mismatch'    => [['flag' => ['bool' => 'true']], ['flag' => false], false],
            'bool-false-both'        => [['flag' => ['bool' => false]], ['flag' => 0], true],
            'bool-false-zero-string' => [['flag' => ['bool' => '0']], ['flag' => false], true],
        ];
    }

    /**
     * Exercise every supported operator.
     *
     * @param  array<string, mixed>  $conditions
     * @param  array<string, mixed>  $context
     * @param  bool  $expected
     * @return void
     */
    #[DataProvider('operatorProvider')]
    public function testOperatorMatrix(array $conditions, array $context, bool $expected): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => $conditions,
        ]);

        self::assertSame($expected, $statement->evaluateConditions($context));
    }

    /**
     * Resources-not-match short-circuit.
     *
     * @return void
     */
    public function testResourceMatchFailsWhenPatternDoesNotMatch(): void
    {
        $statement = Statement::fromArray([
            'effect'    => 'allow',
            'actions'   => ['posts:*'],
            'resources' => ['arn:posts:1'],
        ]);

        self::assertFalse($statement->matches('posts:create', 'arn:users:1'));
    }

    // ------------------------------------------------------------------
    // #37 — Context variable interpolation wired into Statement
    // ------------------------------------------------------------------

    /**
     * Interpolated resource pattern matches when the principal id is
     * substituted into the resource glob.
     *
     * @return void
     */
    public function testInterpolatedResourcePatternMatchesPrincipal(): void
    {
        $statement = Statement::fromArray([
            'effect'    => 'allow',
            'actions'   => ['posts:read'],
            'resources' => ['posts:${principal.id}:*'],
        ]);

        $principal = new class {
            /**
             * @param  string  $key
             * @return int|null
             */
            public function getAttribute(string $key): ?int
            {
                return $key === 'id' ? 42 : null;
            }
        };

        $interpolator = new ContextInterpolator;

        self::assertTrue($statement->matches('posts:read', 'posts:42:draft', $interpolator, $principal));
        self::assertFalse($statement->matches('posts:read', 'posts:99:draft', $interpolator, $principal));
    }

    /**
     * Interpolated resource pattern using context resolves correctly.
     *
     * @return void
     */
    public function testInterpolatedResourcePatternFromContext(): void
    {
        $statement = Statement::fromArray([
            'effect'    => 'allow',
            'actions'   => ['posts:*'],
            'resources' => ['tenant:${context.tenant_id}:*'],
        ]);

        $interpolator = new ContextInterpolator;

        self::assertTrue($statement->matches(
            'posts:read',
            'tenant:org-5:posts',
            $interpolator,
            null,
            ['tenant_id' => 'org-5'],
        ));

        self::assertFalse($statement->matches(
            'posts:read',
            'tenant:org-9:posts',
            $interpolator,
            null,
            ['tenant_id' => 'org-5'],
        ));
    }

    /**
     * Interpolated condition operand resolves principal id before
     * operator evaluation.
     *
     * @return void
     */
    public function testInterpolatedConditionOperandResolvesPrincipal(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['posts:update'],
            'conditions' => ['owner_id' => ['eq' => '${principal.id}']],
        ]);

        $principal = new class {
            /**
             * @param  string  $key
             * @return string|null
             */
            public function getAttribute(string $key): ?string
            {
                return $key === 'id' ? '42' : null;
            }
        };

        $interpolator = new ContextInterpolator;

        self::assertTrue($statement->evaluateConditions(
            ['owner_id' => '42'],
            $interpolator,
            $principal,
        ));

        self::assertFalse($statement->evaluateConditions(
            ['owner_id' => '99'],
            $interpolator,
            $principal,
        ));
    }

    /**
     * Without an interpolator, `${...}` tokens are treated as literals
     * (backwards compatibility).
     *
     * @return void
     */
    public function testWithoutInterpolatorTokensAreLiteral(): void
    {
        $statement = Statement::fromArray([
            'effect'    => 'allow',
            'actions'   => ['posts:read'],
            'resources' => ['posts:${principal.id}'],
        ]);

        // The literal string `posts:${principal.id}` won't match `posts:42`
        self::assertFalse($statement->matches('posts:read', 'posts:42'));

        // But it will match its own literal form
        self::assertTrue($statement->matches('posts:read', 'posts:${principal.id}'));
    }

    /**
     * Interpolation with resource.type in a resource pattern.
     *
     * @return void
     */
    public function testInterpolatedResourceType(): void
    {
        $statement = Statement::fromArray([
            'effect'    => 'allow',
            'actions'   => ['read'],
            'resources' => ['${resource.type}:*'],
        ]);

        $interpolator = new ContextInterpolator;

        self::assertTrue($statement->matches('read', 'posts:42', $interpolator));
        self::assertTrue($statement->matches('read', 'posts:99', $interpolator));
    }
}
