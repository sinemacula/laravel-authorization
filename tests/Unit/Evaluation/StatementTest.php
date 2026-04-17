<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
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
     * @return \Generator<string, array{0: array<string, mixed>, 1: array<string, mixed>, 2: bool}>
     */
    public static function operatorProvider(): iterable
    {
        yield from [
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

    // ------------------------------------------------------------------
    // Mutation-kill: default resources value contains '*'
    // ------------------------------------------------------------------

    /**
     * The constructor default for resources is `['*']` — removing the
     * `'*'` element (ArrayItemRemoval on line 44) would break the
     * default wildcard behaviour.
     *
     * @return void
     */
    public function testConstructorDefaultResourcesContainsWildcard(): void
    {
        $statement = new Statement(
            effect: PolicyEffect::ALLOW,
            actions: ['posts:create'],
        );

        self::assertSame(['*'], $statement->resources);
        self::assertTrue($statement->matches('posts:create', 'any-resource'));
    }

    // ------------------------------------------------------------------
    // Mutation-kill: evaluateConditions foreach body
    // ------------------------------------------------------------------

    /**
     * When a condition entry fails, evaluateConditions returns false.
     * If the foreach were skipped (Foreach_ mutant on line 138),
     * it would always return true.
     *
     * @return void
     */
    public function testEvaluateConditionsReturnsFalseWhenEntryFails(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['missing_key' => ['eq' => 'value']],
        ]);

        self::assertFalse($statement->evaluateConditions([]));
    }

    /**
     * The `!` before evaluateConditionEntry matters — flipping it
     * (LogicalNot mutant on line 139) would invert the whole result.
     *
     * @return void
     */
    public function testEvaluateConditionsPassesWhenAllEntriesPass(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['a' => ['eq' => 1], 'b' => ['eq' => 2]],
        ]);

        self::assertTrue($statement->evaluateConditions(['a' => 1, 'b' => 2]));
        self::assertFalse($statement->evaluateConditions(['a' => 1, 'b' => 99]));
    }

    // ------------------------------------------------------------------
    // Mutation-kill: evaluateConditionEntry boundary (line 166)
    // ------------------------------------------------------------------

    /**
     * Integer condition keys cause the entry to fail (non-string key).
     * If the `!\is_string($key)` check is negated or the `||` changed
     * to `&&`, the behaviour changes.
     *
     * @return void
     */
    public function testIntegerConditionKeyFailsClosed(): void
    {
        // Build a statement with a numeric key manually
        $statement = new Statement(
            effect: PolicyEffect::ALLOW,
            actions: ['x'],
            conditions: [0 => ['eq' => 'val']],
        );

        // The integer key '0' is not a string, so condition should fail
        self::assertFalse($statement->evaluateConditions(['0' => 'val']));
    }

    /**
     * A string key that exists in context should pass when the value matches.
     * Kills the LogicalOrNegation / LogicalOrAllSubExprNegation mutants.
     *
     * @return void
     */
    public function testStringKeyPresentInContextPasses(): void
    {
        $statement = new Statement(
            effect: PolicyEffect::ALLOW,
            actions: ['x'],
            conditions: ['key' => 'expected'],
        );

        self::assertTrue($statement->evaluateConditions(['key' => 'expected']));
    }

    /**
     * A string key NOT in context should fail. Kills mutants that
     * negate array_key_exists.
     *
     * @return void
     */
    public function testStringKeyAbsentFromContextFails(): void
    {
        $statement = new Statement(
            effect: PolicyEffect::ALLOW,
            actions: ['x'],
            conditions: ['missing' => 'expected'],
        );

        self::assertFalse($statement->evaluateConditions(['other' => 'expected']));
    }

    // ------------------------------------------------------------------
    // Mutation-kill: resolveConditions ArrayItemRemoval (line 232)
    // ------------------------------------------------------------------

    /**
     * resolveConditions preserves every key-value pair from the
     * input — removing the assignment (ArrayItemRemoval on line 232)
     * would produce an empty map.
     *
     * @return void
     */
    public function testResolveConditionsPreservesAllEntries(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['a' => 'one', 'b' => 'two'],
        ]);

        self::assertSame(['a' => 'one', 'b' => 'two'], $statement->conditions);
    }

    // ------------------------------------------------------------------
    // Mutation-kill: normaliseStringList (line 277)
    // ------------------------------------------------------------------

    /**
     * normaliseStringList re-indexes non-sequential keys. Unwrapping
     * array_values or array_map would break validation or indexing.
     *
     * @return void
     */
    public function testNormaliseStringListReindexes(): void
    {
        $statement = Statement::fromArray([
            'effect'    => 'allow',
            'actions'   => ['a', 'b', 'c'],
            'resources' => ['r1', 'r2'],
        ]);

        self::assertSame(['a', 'b', 'c'], $statement->actions);
        self::assertSame(['r1', 'r2'], $statement->resources);

        // Confirm non-string throws — that's the array_map callback
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('actions must be strings');
        // @phpstan-ignore-next-line
        Statement::fromArray(['effect' => 'allow', 'actions' => ['valid', 42]]);
    }

    // ------------------------------------------------------------------
    // Mutation-kill: evaluateCondition (lines 388-398)
    // ------------------------------------------------------------------

    /**
     * Non-array condition where actual === expected.
     * Kills the LogicalNot on line 388 (`!\is_array`) and Foreach_
     * on line 392.
     *
     * @return void
     */
    public function testEvaluateConditionNonArrayMatch(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['key' => 'value'],
        ]);

        self::assertTrue($statement->evaluateConditions(['key' => 'value']));
        self::assertFalse($statement->evaluateConditions(['key' => 'other']));
    }

    /**
     * Non-string operator key in the condition map causes failure.
     * Kills the `!\is_string($operator)` check on line 393.
     *
     * @return void
     */
    public function testNonStringOperatorKeyFailsClosed(): void
    {
        $statement = new Statement(
            effect: PolicyEffect::ALLOW,
            actions: ['x'],
            conditions: ['key' => [0 => 'operand']],
        );

        self::assertFalse($statement->evaluateConditions(['key' => 'operand']));
    }

    /**
     * Multiple operators must all pass — the foreach short-circuits
     * on the first failure. Kills TrueValue on line 398.
     *
     * @return void
     */
    public function testMultipleOperatorsMustAllPass(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['age' => ['gte' => 18, 'lte' => 65]],
        ]);

        self::assertTrue($statement->evaluateConditions(['age' => 30]));
        self::assertFalse($statement->evaluateConditions(['age' => 10]));
        self::assertFalse($statement->evaluateConditions(['age' => 70]));
    }

    // ------------------------------------------------------------------
    // Mutation-kill: evaluateOperator match arms (lines 411-430)
    // ------------------------------------------------------------------

    /**
     * Each operator arm is individually distinguishable when tested
     * against specific values. Removing any arm would cause a
     * `\UnhandledMatchError` or fall through to `default`.
     *
     * @return void
     */
    public function testEveryOperatorArmIsDistinguishable(): void
    {
        // Each sub-array: [conditions, context, expected]
        $cases = [
            // eq vs neq
            ['k' => ['eq' => 'a'], 'ctx' => 'a', 'expect' => true],
            ['k' => ['neq' => 'a'], 'ctx' => 'b', 'expect' => true],
            ['k' => ['neq' => 'a'], 'ctx' => 'a', 'expect' => false],

            // in vs not_in
            ['k' => ['in' => ['a', 'b']], 'ctx' => 'a', 'expect' => true],
            ['k' => ['in' => ['a', 'b']], 'ctx' => 'c', 'expect' => false],
            ['k' => ['not_in' => ['a', 'b']], 'ctx' => 'c', 'expect' => true],
            ['k' => ['not_in' => ['a', 'b']], 'ctx' => 'a', 'expect' => false],

            // in with non-array operand
            ['k' => ['in' => 'not-array'], 'ctx' => 'x', 'expect' => false],
            // not_in with non-array operand
            ['k' => ['not_in' => 'not-array'], 'ctx' => 'x', 'expect' => false],

            // starts_with / ends_with
            ['k' => ['starts_with' => 'he'], 'ctx' => 'hello', 'expect' => true],
            ['k' => ['starts_with' => 'he'], 'ctx' => 'world', 'expect' => false],
            ['k' => ['ends_with' => 'lo'], 'ctx' => 'hello', 'expect' => true],
            ['k' => ['ends_with' => 'lo'], 'ctx' => 'world', 'expect' => false],

            // starts_with / ends_with type guard: non-string actual
            ['k' => ['starts_with' => 'x'], 'ctx' => 123, 'expect' => false],
            ['k' => ['ends_with' => 'x'], 'ctx' => 123, 'expect' => false],
            // starts_with / ends_with type guard: non-string operand
            ['k' => ['starts_with' => 42], 'ctx' => 'hello', 'expect' => false],
            ['k' => ['ends_with' => 42], 'ctx' => 'hello', 'expect' => false],

            // cidr type guards
            ['k' => ['cidr' => 123], 'ctx' => '10.0.0.1', 'expect' => false],
            ['k' => ['cidr' => '10.0.0.0/8'], 'ctx' => 123, 'expect' => false],

            // string_like
            ['k' => ['string_like' => 'foo*'], 'ctx' => 'foobar', 'expect' => true],
            ['k' => ['string_like' => 'foo*'], 'ctx' => 'baz', 'expect' => false],
            // string_like type guards
            ['k' => ['string_like' => 42], 'ctx' => 'foo', 'expect' => false],
            ['k' => ['string_like' => 'foo*'], 'ctx' => 42, 'expect' => false],

            // null / not_null
            ['k' => ['null' => true], 'ctx' => null, 'expect' => true],
            ['k' => ['null' => true], 'ctx' => 'x', 'expect' => false],
            ['k' => ['not_null' => true], 'ctx' => 'x', 'expect' => true],
            ['k' => ['not_null' => true], 'ctx' => null, 'expect' => false],
        ];

        foreach ($cases as $i => $case) {
            $statement = Statement::fromArray([
                'effect'     => 'allow',
                'actions'    => ['x'],
                'conditions' => ['k' => $case['k']],
            ]);

            self::assertSame(
                $case['expect'],
                $statement->evaluateConditions(['k' => $case['ctx']]),
                "Case {$i} failed",
            );
        }
    }

    /**
     * The `in` operator requires is_array(operand) AND in_array check.
     * Negating `\in_array` or the `\is_array` changes the result.
     *
     * @return void
     */
    public function testInOperatorRequiresBothArrayAndMembership(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['role' => ['in' => ['admin', 'editor']]],
        ]);

        // Actual value is in the list
        self::assertTrue($statement->evaluateConditions(['role' => 'admin']));
        // Actual value is NOT in the list
        self::assertFalse($statement->evaluateConditions(['role' => 'guest']));
    }

    /**
     * The `not_in` operator requires is_array(operand) AND !in_array.
     *
     * @return void
     */
    public function testNotInOperatorLogic(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['role' => ['not_in' => ['admin', 'editor']]],
        ]);

        // Value NOT in the list → true
        self::assertTrue($statement->evaluateConditions(['role' => 'guest']));
        // Value IN the list → false
        self::assertFalse($statement->evaluateConditions(['role' => 'admin']));
    }

    /**
     * `cidr` operator needs both actual and operand to be strings.
     * Tests kill the LogicalAnd mutants on line 416.
     *
     * @return void
     */
    public function testCidrOperatorTypeGuards(): void
    {
        // Non-string actual
        $stmt = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['ip' => ['cidr' => '10.0.0.0/8']],
        ]);

        self::assertFalse($stmt->evaluateConditions(['ip' => 123]));
        self::assertTrue($stmt->evaluateConditions(['ip' => '10.0.0.1']));
    }

    /**
     * `starts_with` needs string actual AND string operand AND
     * str_starts_with to match. Tests kill the triple LogicalAnd
     * mutants on line 417.
     *
     * @return void
     */
    public function testStartsWithTypeGuardsAndLogic(): void
    {
        // String match
        $stmt = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['val' => ['starts_with' => 'pre']],
        ]);

        self::assertTrue($stmt->evaluateConditions(['val' => 'prefix']));
        self::assertFalse($stmt->evaluateConditions(['val' => 'suffix']));
        self::assertFalse($stmt->evaluateConditions(['val' => 123]));
    }

    /**
     * `ends_with` needs string actual AND string operand AND
     * str_ends_with to match. Tests kill the triple LogicalAnd
     * mutants on line 418.
     *
     * @return void
     */
    public function testEndsWithTypeGuardsAndLogic(): void
    {
        $stmt = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['val' => ['ends_with' => 'fix']],
        ]);

        self::assertTrue($stmt->evaluateConditions(['val' => 'suffix']));
        self::assertFalse($stmt->evaluateConditions(['val' => 'hello']));
        self::assertFalse($stmt->evaluateConditions(['val' => 123]));
    }

    /**
     * `string_like` needs string actual AND string operand AND
     * fnmatch to match. Tests kill the triple LogicalAnd mutants
     * on line 422.
     *
     * @return void
     */
    public function testStringLikeTypeGuardsAndLogic(): void
    {
        $stmt = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['val' => ['string_like' => 'foo*']],
        ]);

        self::assertTrue($stmt->evaluateConditions(['val' => 'foobar']));
        self::assertFalse($stmt->evaluateConditions(['val' => 'bazbar']));
        self::assertFalse($stmt->evaluateConditions(['val' => 42]));
    }

    /**
     * `null` operator: actual === null must be true iff actual is null.
     * `not_null`: actual !== null must be true iff actual is not null.
     * Kills Identical mutants on lines 423-424.
     *
     * @return void
     */
    public function testNullNotNullOperatorsDistinct(): void
    {
        $stmtNull = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['k' => ['null' => true]],
        ]);

        self::assertTrue($stmtNull->evaluateConditions(['k' => null]));
        self::assertFalse($stmtNull->evaluateConditions(['k' => 0]));
        self::assertFalse($stmtNull->evaluateConditions(['k' => '']));
        self::assertFalse($stmtNull->evaluateConditions(['k' => false]));

        $stmtNotNull = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['k' => ['not_null' => true]],
        ]);

        self::assertTrue($stmtNotNull->evaluateConditions(['k' => 'x']));
        self::assertTrue($stmtNotNull->evaluateConditions(['k' => 0]));
        self::assertFalse($stmtNotNull->evaluateConditions(['k' => null]));
    }

    /**
     * `eq` uses `===` and `neq` uses `!==`. Swapping them produces
     * different results. Kills Identical/NotIdentical mutants on
     * lines 412-413.
     *
     * @return void
     */
    public function testEqNeqAreStrictlyOpposite(): void
    {
        $stmtEq = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['k' => ['eq' => 'a']],
        ]);

        $stmtNeq = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['k' => ['neq' => 'a']],
        ]);

        // eq: true when same, false when different
        self::assertTrue($stmtEq->evaluateConditions(['k' => 'a']));
        self::assertFalse($stmtEq->evaluateConditions(['k' => 'b']));

        // neq: opposite
        self::assertFalse($stmtNeq->evaluateConditions(['k' => 'a']));
        self::assertTrue($stmtNeq->evaluateConditions(['k' => 'b']));
    }

    // ------------------------------------------------------------------
    // Mutation-kill: interpolateOperands (lines 353-377)
    // ------------------------------------------------------------------

    /**
     * Condition operands that are arrays get their string values
     * interpolated while non-strings pass through unchanged.
     * The operator map `['eq' => '${principal.id}']` has a string
     * value that must be interpolated by interpolateOperands.
     *
     * @return void
     */
    public function testInterpolateOperandsInterpolatesArrayStringValues(): void
    {
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

        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['owner' => ['eq' => '${principal.id}']],
        ]);

        $interpolator = new ContextInterpolator;

        // '${principal.id}' interpolates to '42'
        self::assertTrue($statement->evaluateConditions(
            ['owner' => '42'],
            $interpolator,
            $principal,
        ));

        // '99' does not match '42'
        self::assertFalse($statement->evaluateConditions(
            ['owner' => '99'],
            $interpolator,
            $principal,
        ));
    }

    /**
     * Non-string, non-array condition operands pass through the
     * interpolateOperands method unchanged.
     *
     * @return void
     */
    public function testInterpolateOperandsNonStringNonArrayPassesThrough(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['age' => 25],
        ]);

        $interpolator = new ContextInterpolator;

        // Integer condition should match by identity
        self::assertTrue($statement->evaluateConditions(
            ['age' => 25],
            $interpolator,
        ));

        self::assertFalse($statement->evaluateConditions(
            ['age' => 30],
            $interpolator,
        ));
    }
}
