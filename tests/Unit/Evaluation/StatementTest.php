<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator;
use SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\MatchResult;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Evaluation\StatementValidator;

/**
 * Unit tests for the policy statement value object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 * @SuppressWarnings("php:S1448")
 */
#[CoversClass(Statement::class)]
#[CoversClass(StatementValidator::class)]
#[CoversClass(MatchResult::class)]
#[CoversClass(ConditionEvaluator::class)]
#[CoversClass(ContextInterpolator::class)]
final class StatementTest extends TestCase
{
    /** @var string Trace detail for a statement whose patterns do not cover the check. */
    private const string TARGET_MISMATCH = 'action/resource did not match';

    /** @var string Trace detail for a resource pattern whose reference cannot be resolved. */
    private const string UNRESOLVED_RESOURCE = 'a resource pattern references a value that cannot be resolved';

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

        self::assertSame([
            'effect'     => 'allow',
            'actions'    => ['posts:create'],
            'resources'  => ['arn:posts:1'],
            'conditions' => ['tenant' => ['eq' => 'org-1']],
        ], $statement->toArray());
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
        self::assertSame([
            'effect'    => 'deny',
            'actions'   => ['posts:delete'],
            'resources' => ['*'],
        ], $statement->toArray());
    }

    /**
     * Reject a missing effect.
     *
     * @return void
     */
    public function testRejectsMissingEffect(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy statement requires a string effect.');

        Statement::fromArray(['actions' => ['x']]);
    }

    /**
     * Reject an effect that is not a string.
     *
     * @return void
     */
    public function testRejectsNonStringEffect(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy statement requires a string effect.');

        Statement::fromArray(['effect' => 1, 'actions' => ['x']]);
    }

    /**
     * Reject an invalid effect.
     *
     * @return void
     */
    public function testRejectsInvalidEffect(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid policy effect: \'audit\'');

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
        $this->expectExceptionMessage('Policy statement requires at least one action.');

        Statement::fromArray(['effect' => 'allow']);
    }

    /**
     * Reject actions that are not a list.
     *
     * @return void
     */
    public function testRejectsNonArrayActions(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy statement requires at least one action.');

        Statement::fromArray(['effect' => 'allow', 'actions' => 'posts:read']);
    }

    /**
     * Reject empty actions.
     *
     * @return void
     */
    public function testRejectsEmptyActions(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy statement requires at least one action.');

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
        $this->expectExceptionMessage('Policy statement actions must be strings.');

        // @phpstan-ignore-next-line argument.type
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
        $this->expectExceptionMessage('Policy statement resources must be an array of strings.');

        // @phpstan-ignore-next-line argument.type
        Statement::fromArray(['effect' => 'allow', 'actions' => ['x'], 'resources' => 'nope']);
    }

    /**
     * An empty resource list is refused: the key must be omitted to cover every
     * resource, so an empty list never silently widens to `*`.
     *
     * @return void
     */
    public function testRejectsEmptyResources(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy statement resources must not be empty; omit the key to cover every resource.');

        Statement::fromArray([
            'effect'    => 'allow',
            'actions'   => ['posts:create'],
            'resources' => [],
        ]);
    }

    /**
     * Reject non-string resources.
     *
     * @return void
     */
    public function testRejectsNonStringResources(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy statement resources must be strings.');

        // @phpstan-ignore-next-line argument.type
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
        $this->expectExceptionMessage('Policy statement conditions must be an associative array.');

        // @phpstan-ignore-next-line argument.type
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
        $this->expectExceptionMessage('Policy statement conditions must use string keys.');

        // @phpstan-ignore-next-line argument.type
        Statement::fromArray(['effect' => 'allow', 'actions' => ['x'], 'conditions' => [42 => 'v']]);
    }

    /**
     * Data provider for statement keys the document format does not define.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function unknownKeyProvider(): iterable
    {
        yield 'misspelt conditions' => [['condition' => ['tenant' => 'org-1']], 'Policy statement has unknown keys: condition.'];
        yield 'not_resources' => [['not_resources' => ['arn:posts:1']], 'Policy statement has unknown keys: not_resources.'];
        yield 'sid' => [['sid' => 'AllowRead'], 'Policy statement has unknown keys: sid.'];
        yield 'several' => [['sid' => 'AllowRead', 'principal' => '*'], 'Policy statement has unknown keys: sid, principal.'];
    }

    /**
     * A statement carrying a key the format does not define is refused, so a
     * misspelt `conditions` never becomes an unconditional statement.
     *
     * @param  array<string, mixed>  $extra
     * @param  string  $message
     * @return void
     */
    #[DataProvider('unknownKeyProvider')]
    public function testRejectsUnknownStatementKeys(array $extra, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        Statement::fromArray(['effect' => 'allow', 'actions' => ['posts:read'], ...$extra]);
    }

    /**
     * A condition with an empty operator map is refused on hydration.
     *
     * @return void
     */
    public function testRejectsEmptyOperatorMap(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy statement condition \'tenant\' has no operators.');

        Statement::fromArray(['effect' => 'allow', 'actions' => ['x'], 'conditions' => ['tenant' => []]]);
    }

    /**
     * A condition whose operator map uses a non-string key is refused on
     * hydration.
     *
     * @return void
     */
    public function testRejectsNonStringOperatorKey(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy statement condition \'tenant\' must map operator names to operands.');

        Statement::fromArray(['effect' => 'allow', 'actions' => ['x'], 'conditions' => ['tenant' => [0 => 'org-1']]]);
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
     * Action patterns compare backslashes literally, so fully-qualified class
     * names in actions stay intact.
     *
     * @return void
     */
    public function testActionPatternsCompareBackslashesLiterally(): void
    {
        $statement = Statement::fromArray(['effect' => 'allow', 'actions' => ['App\Models\*']]);

        self::assertTrue($statement->matches('App\Models\Post'));
        self::assertFalse($statement->matches('AppModelsPost'));
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
     * A check without a resource is covered only by a statement whose resources
     * include `*`; a statement scoped to particular resources never covers it.
     *
     * @return void
     */
    public function testResourcelessMatchSkipsResourceCheck(): void
    {
        $scoped = Statement::fromArray([
            'effect'    => 'allow',
            'actions'   => ['posts:read'],
            'resources' => ['arn:posts:1'],
        ]);

        $scopedWildcard = Statement::fromArray([
            'effect'    => 'allow',
            'actions'   => ['posts:read'],
            'resources' => ['arn:posts:*'],
        ]);

        $wildcard = Statement::fromArray([
            'effect'    => 'allow',
            'actions'   => ['posts:read'],
            'resources' => ['arn:posts:1', '*'],
        ]);

        self::assertFalse($scoped->matches('posts:read'));
        self::assertFalse($scopedWildcard->matches('posts:read'));
        self::assertTrue($wildcard->matches('posts:read'));
    }

    /**
     * assess() reports a resource-less check against a scoped statement as a
     * definite mismatch and against a wildcard statement as a match.
     *
     * @return void
     */
    public function testAssessResourcelessCheckAgainstScopedAndWildcardStatements(): void
    {
        $scoped = Statement::fromArray([
            'effect'    => 'deny',
            'actions'   => ['posts:read'],
            'resources' => ['arn:posts:1'],
        ]);

        $wildcard = Statement::fromArray([
            'effect'  => 'deny',
            'actions' => ['posts:read'],
        ]);

        self::assertResult(MatchOutcome::DOES_NOT_MATCH, self::TARGET_MISMATCH, $scoped->assess('posts:read'));
        self::assertResult(MatchOutcome::MATCHES, '', $wildcard->assess('posts:read'));
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, self::TARGET_MISMATCH, $wildcard->assess('posts:write'));
    }

    /**
     * assess() reports each condition key the statement tested, in the
     * statement's order, with whether it held: a key that fails, and a key
     * missing from the context, are reported as not held.
     *
     * @return void
     */
    public function testAssessReportsEachConditionKeyWithWhetherItHeld(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['posts:read'],
            'conditions' => [
                'tenant' => ['eq' => 'org-1'],
                'role'   => ['in' => ['admin', 'staff']],
                'ip'     => ['cidr' => '10.0.0.0/8'],
                'active' => true,
            ],
        ]);

        $result = $statement->assess('posts:read', null, ['tenant' => 'org-1', 'role' => 'guest', 'active' => true]);

        self::assertSame(MatchOutcome::DOES_NOT_MATCH, $result->outcome);
        self::assertSame(['tenant' => true, 'role' => false, 'ip' => false, 'active' => true], $result->conditions);
    }

    /**
     * assess() reports every condition key as held when the statement matches,
     * and an empty map, not null, when the statement names the check but has no
     * conditions.
     *
     * @return void
     */
    public function testAssessReportsHeldConditionsAndEmptyMapWhenTargetMatches(): void
    {
        $conditional = Statement::fromArray([
            'effect'     => 'deny',
            'actions'    => ['posts:read'],
            'conditions' => ['tenant' => 'org-1', 'level' => ['gte' => 2]],
        ]);

        $unconditional = Statement::fromArray(['effect' => 'deny', 'actions' => ['posts:read']]);

        $matched = $conditional->assess('posts:read', null, ['tenant' => 'org-1', 'level' => 3]);

        self::assertResult(MatchOutcome::MATCHES, '', $matched);
        self::assertSame(['tenant' => true, 'level' => true], $matched->conditions);
        self::assertSame([], $unconditional->assess('posts:read')->conditions);
    }

    /**
     * assess() reports no condition keys (null) when the statement does not
     * name the action or the resource, without testing its conditions.
     *
     * @return void
     */
    public function testAssessReportsNullConditionsWhenTargetDoesNotMatch(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['posts:read'],
            'resources'  => ['posts/1'],
            'conditions' => ['tenant' => 'org-1'],
        ]);

        $context = ['tenant' => 'org-1'];

        self::assertNull($statement->assess('users:read', 'posts/1', $context)->conditions);
        self::assertNull($statement->assess('posts:read', 'posts/2', $context)->conditions);
        self::assertNull($statement->assess('posts:read', null, $context)->conditions);
        self::assertSame(['tenant' => true], $statement->assess('posts:read', 'posts/1', $context)->conditions);
    }

    /**
     * assess() reports the condition keys of a statement whose resource pattern
     * cannot be resolved, since it names the action, and of a statement whose
     * condition is malformed, the malformed key as not held.
     *
     * @return void
     */
    public function testAssessReportsConditionsForUndecidableAndInvalidStatements(): void
    {
        $unresolved = Statement::fromArray([
            'effect'     => 'deny',
            'actions'    => ['posts:read'],
            'resources'  => ['tenants/${context.tenant}/*'],
            'conditions' => ['level' => ['gte' => 2]],
        ]);

        $undecidable = $unresolved->assess('posts:read', 'tenants/org-1/posts', ['level' => 3], new ContextInterpolator);

        self::assertResult(MatchOutcome::UNDECIDABLE, self::UNRESOLVED_RESOURCE, $undecidable);
        self::assertSame(['level' => true], $undecidable->conditions);

        $malformed = new Statement(
            effect: PolicyEffect::DENY,
            actions: ['posts:read'],
            conditions: ['tenant' => 'org-1', 'k' => ['bogus' => 1]],
        );

        $invalid = $malformed->assess('posts:read', null, ['tenant' => 'org-1', 'k' => 1]);

        self::assertSame(MatchOutcome::INVALID, $invalid->outcome);
        self::assertSame(['tenant' => true, 'k' => false], $invalid->conditions);
    }

    /**
     * Missing context key makes the condition undecidable, naming the key.
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

        self::assertFalse($statement->conditionsSatisfiedBy([]));
        self::assertResult(
            MatchOutcome::UNDECIDABLE,
            'key \'tenant\' is missing from the context',
            $statement->assess('x'),
        );
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

        self::assertTrue($statement->conditionsSatisfiedBy(['tenant' => 'org-1']));
        self::assertFalse($statement->conditionsSatisfiedBy(['tenant' => 'org-2']));
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, '', $statement->assess('x', null, ['tenant' => 'org-2']));
    }

    /**
     * An unknown operator is refused on hydration, and a directly constructed
     * statement carrying one assesses as invalid.
     *
     * @return void
     */
    public function testUnknownOperatorFailsClosed(): void
    {
        $statement = new Statement(
            effect: PolicyEffect::ALLOW,
            actions: ['x'],
            conditions: ['tenant' => ['unknown_op' => 'org-1']],
        );

        self::assertFalse($statement->conditionsSatisfiedBy(['tenant' => 'org-1']));
        self::assertResult(
            MatchOutcome::INVALID,
            'condition \'tenant\' has an unknown operator \'unknown_op\'',
            $statement->assess('x', null, ['tenant' => 'org-1']),
        );

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy statement condition \'tenant\' has an unknown operator \'unknown_op\'.');

        Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['tenant' => ['unknown_op' => 'org-1']],
        ]);
    }

    /**
     * Data provider for operators.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>, 2: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome}>
     */
    public static function operatorProvider(): iterable
    {
        yield from self::equalityAndMembershipCases();
        yield from self::stringAndCidrCases();
        yield from self::temporalCases();
        yield from self::stringLikeAndNullCases();
        yield from self::numericComparisonCases();
        yield from self::boolCases();
    }

    /**
     * Exercise every supported operator.
     *
     * @param  array<string, mixed>  $conditions
     * @param  array<string, mixed>  $context
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome  $expected
     * @return void
     */
    #[DataProvider('operatorProvider')]
    public function testOperatorMatrix(array $conditions, array $context, MatchOutcome $expected): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => $conditions,
        ]);

        self::assertSame($expected, $statement->assess('x', null, $context)->outcome);
        self::assertSame($expected === MatchOutcome::MATCHES, $statement->conditionsSatisfiedBy($context));
    }

    /**
     * Data provider for literal operands that are malformed for their operator.
     *
     * @return iterable<string, array{0: string, 1: array<string, mixed>, 2: string}>
     */
    public static function malformedOperandProvider(): iterable
    {
        yield 'in-non-array' => ['role', ['in' => 'admin'], 'in'];
        yield 'not_in-non-array' => ['role', ['not_in' => 'admin'], 'not_in'];
        yield 'cidr-non-string' => ['ip', ['cidr' => 123], 'cidr'];
        yield 'cidr-bad-address' => ['ip', ['cidr' => 'not-an-ip/24'], 'cidr'];
        yield 'cidr-bad-bits' => ['ip', ['cidr' => '192.168.1.0/abc'], 'cidr'];
        yield 'cidr-empty-bits' => ['ip', ['cidr' => '192.168.1.0/'], 'cidr'];
        yield 'cidr-bits-too-big' => ['ip', ['cidr' => '192.168.1.0/64'], 'cidr'];
        yield 'cidr-ipv4-bits-33' => ['ip', ['cidr' => '192.168.1.0/33'], 'cidr'];
        yield 'cidr-ipv6-bits-129' => ['ip', ['cidr' => '2001:db8::/129'], 'cidr'];
        yield 'starts_with-non-string' => ['val', ['starts_with' => 42], 'starts_with'];
        yield 'starts_with-empty' => ['val', ['starts_with' => ''], 'starts_with'];
        yield 'ends_with-non-string' => ['val', ['ends_with' => 42], 'ends_with'];
        yield 'ends_with-empty' => ['val', ['ends_with' => ''], 'ends_with'];
        yield 'string_like-non-string' => ['val', ['string_like' => 42], 'string_like'];
        yield 'string_like-empty' => ['val', ['string_like' => ''], 'string_like'];
        yield 'between-bad-shape' => ['at', ['between' => ['2026-04-10']], 'between'];
        yield 'between-bad-left' => ['at', ['between' => ['bad', '2026-04-20']], 'between'];
        yield 'between-bad-right' => ['at', ['between' => ['2026-04-10', 'bad']], 'between'];
        yield 'between-non-array' => ['at', ['between' => '2026-04-10'], 'between'];
        yield 'time-invalid' => ['at', ['before' => 'not-a-date'], 'before'];
        yield 'after-invalid' => ['at', ['after' => 'not-a-date'], 'after'];
        yield 'gt-non-numeric-operand' => ['age', ['gt' => 'abc'], 'gt'];
        yield 'lte-non-numeric-operand' => ['age', ['lte' => true], 'lte'];
        yield 'gt-escaped-reference-operand' => ['age', ['gt' => '\${x}'], 'gt'];
        yield 'gt-nan-operand' => ['age', ['gt' => \NAN], 'gt'];
        yield 'gte-infinite-operand' => ['age', ['gte' => \INF], 'gte'];
        yield 'lt-negative-infinite-operand' => ['age', ['lt' => -\INF], 'lt'];
        yield 'bool-unrecognised' => ['flag', ['bool' => 'yes'], 'bool'];
        yield 'bool-int-two' => ['flag', ['bool' => 2], 'bool'];
    }

    /**
     * A literal operand of the wrong type for its operator is refused on
     * hydration.
     *
     * @param  string  $key
     * @param  array<string, mixed>  $condition
     * @param  string  $operator
     * @return void
     */
    #[DataProvider('malformedOperandProvider')]
    public function testMalformedOperandsAreRefused(string $key, array $condition, string $operator): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Policy statement condition '{$key}' has an invalid operand for operator '{$operator}'.");

        Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => [$key => $condition],
        ]);
    }

    /**
     * Operands carrying a `${…}` reference are only type-checked on hydration
     * and are resolved when the statement is assessed.
     *
     * @return void
     */
    public function testValidInterpolatedOperandsAreAccepted(): void
    {
        $conditions = [
            'ip'   => ['cidr' => '${context.range}'],
            'at'   => ['before' => '${context.deadline}', 'after' => '${context.opens}'],
            'size' => ['gt' => '${context.minimum}', 'lte' => '${context.maximum}'],
            'flag' => ['bool' => '${context.expected_flag}'],
            'name' => ['string_like' => '${context.prefix}*'],
        ];

        $statement = Statement::fromArray(['effect' => 'allow', 'actions' => ['x'], 'conditions' => $conditions]);

        self::assertSame($conditions, $statement->conditions);

        $context = [
            'ip'            => '10.1.2.3',
            'at'            => '2026-04-15',
            'size'          => 5,
            'flag'          => true,
            'name'          => 'admin-user',
            'range'         => '10.0.0.0/8',
            'deadline'      => '2026-04-20',
            'opens'         => '2026-04-10',
            'minimum'       => 1,
            'maximum'       => 5,
            'expected_flag' => true,
            'prefix'        => 'admin',
        ];

        $interpolator = new ContextInterpolator;

        self::assertResult(MatchOutcome::MATCHES, '', $statement->assess('x', null, $context, $interpolator));
        self::assertResult(
            MatchOutcome::DOES_NOT_MATCH,
            '',
            $statement->assess('x', null, ['size' => 6] + $context, $interpolator),
        );
    }

    /**
     * Data provider for interpolated operands whose substituted value is of the
     * wrong type for their operator.
     *
     * @return iterable<string, array{0: string, 1: string, 2: mixed, 3: string}>
     */
    public static function interpolatedWrongTypeProvider(): iterable
    {
        yield 'bool' => ['flag', 'bool', true, 'yes'];
        yield 'gt' => ['size', 'gt', 5, 'abc'];
        yield 'before' => ['at', 'before', '2026-04-15', 'not-a-date'];
        yield 'cidr' => ['ip', 'cidr', '10.0.0.1', 'not-a-range'];
    }

    /**
     * An interpolated operand whose substituted value is of the wrong type is
     * undecidable rather than invalid, like any context value of the wrong
     * type, whatever the effect: the evaluator then applies a deny carrying it
     * and skips an allow, which never holds.
     *
     * @param  string  $key
     * @param  string  $operator
     * @param  mixed  $actual
     * @param  string  $substituted
     * @return void
     */
    #[DataProvider('interpolatedWrongTypeProvider')]
    public function testInterpolatedOperandOfWrongTypeIsUndecidable(string $key, string $operator, mixed $actual, string $substituted): void
    {
        $interpolator = new ContextInterpolator;
        $context      = [$key => $actual, 'operand' => $substituted];
        $detail       = "condition '{$key}': the substituted operand is an invalid operand for operator '{$operator}'";

        foreach (['deny', 'allow'] as $effect) {
            $statement = Statement::fromArray([
                'effect'     => $effect,
                'actions'    => ['x'],
                'conditions' => [$key => [$operator => '${context.operand}']],
            ]);

            self::assertResult(MatchOutcome::UNDECIDABLE, $detail, $statement->assess('x', null, $context, $interpolator));
            self::assertFalse($statement->conditionsSatisfiedBy($context, $interpolator));
        }
    }

    /**
     * An interpolated `false` renders as `'false'`, so the `bool` operator
     * compares it with the context value as false.
     *
     * @return void
     */
    public function testInterpolatedFalseBooleanOperandComparesAsFalse(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['flag' => ['bool' => '${context.expected}']],
        ]);

        $interpolator = new ContextInterpolator;

        self::assertResult(
            MatchOutcome::MATCHES,
            '',
            $statement->assess('x', null, ['flag' => false, 'expected' => false], $interpolator),
        );
        self::assertResult(
            MatchOutcome::DOES_NOT_MATCH,
            '',
            $statement->assess('x', null, ['flag' => true, 'expected' => false], $interpolator),
        );
    }

    /**
     * Data provider for empty literal string operands.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function emptyStringOperatorProvider(): iterable
    {
        yield 'starts_with' => ['starts_with'];
        yield 'ends_with' => ['ends_with'];
        yield 'string_like' => ['string_like'];
    }

    /**
     * A directly constructed statement with an empty literal string operand is
     * invalid, while one that becomes empty after interpolation stays
     * undecidable.
     *
     * @param  string  $operator
     * @return void
     */
    #[DataProvider('emptyStringOperatorProvider')]
    public function testEmptyLiteralStringOperandOnConstructedStatementIsInvalid(string $operator): void
    {
        $statement = new Statement(
            effect: PolicyEffect::DENY,
            actions: ['x'],
            conditions: ['k' => [$operator => '']],
        );

        self::assertResult(
            MatchOutcome::INVALID,
            "condition 'k' has an invalid operand for operator '{$operator}'",
            $statement->assess('x', null, ['k' => 'value']),
        );
    }

    /**
     * Data provider for context values that are not finite numbers.
     *
     * @return iterable<string, array{0: float}>
     */
    public static function nonFiniteValueProvider(): iterable
    {
        yield 'nan' => [\NAN];
        yield 'infinity' => [\INF];
        yield 'negative infinity' => [-\INF];
    }

    /**
     * NaN and the infinities are not numbers, so a numeric comparison against
     * one is undecidable.
     *
     * @param  float  $value
     * @return void
     */
    #[DataProvider('nonFiniteValueProvider')]
    public function testNonFiniteContextValueIsUndecidableForGt(float $value): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'deny',
            'actions'    => ['x'],
            'conditions' => ['age' => ['gt' => 1]],
        ]);

        self::assertResult(
            MatchOutcome::UNDECIDABLE,
            'condition \'age\': operator \'gt\' needs a number',
            $statement->assess('x', null, ['age' => $value]),
        );
    }

    /**
     * Data provider for conditions malformed whatever the context holds.
     *
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function malformedConditionProvider(): iterable
    {
        yield 'unknown operator' => [['unknown_op' => 'org-1'], 'condition \'tenant\' has an unknown operator \'unknown_op\''];
        yield 'empty operator map' => [[], 'condition \'tenant\' has no operators'];
        yield 'non-string operator' => [[0 => 'org-1'], 'condition \'tenant\' must map operator names to operands'];
        yield 'malformed value reference' => ['${context.tenant-id}', 'condition \'tenant\' has a malformed ${…} reference'];
        yield 'malformed operand reference' => [['eq' => '${foo'], 'condition \'tenant\' has a malformed ${…} reference'];
    }

    /**
     * A malformed condition on a directly constructed statement is invalid,
     * even when its key is missing from the context, so its shape is never
     * hidden behind an undecidable test.
     *
     * @param  mixed  $condition
     * @param  string  $detail
     * @return void
     */
    #[DataProvider('malformedConditionProvider')]
    public function testMalformedConditionIsInvalidEvenWhenKeyIsMissing(mixed $condition, string $detail): void
    {
        $statement = new Statement(
            effect: PolicyEffect::DENY,
            actions: ['x'],
            conditions: ['tenant' => $condition],
        );

        $interpolator = new ContextInterpolator;

        self::assertResult(MatchOutcome::INVALID, $detail, $statement->assess('x'));
        self::assertResult(MatchOutcome::INVALID, $detail, $statement->assess('x', null, [], $interpolator));
        self::assertResult(MatchOutcome::INVALID, $detail, $statement->assess('x', null, ['tenant' => 'org-1'], $interpolator));
    }

    /**
     * Data provider for statements carrying a malformed `${…}` reference.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function malformedReferenceProvider(): iterable
    {
        yield 'resource' => [
            ['resources' => ['posts:${context.tenant-id}']],
            'Policy statement resource pattern \'posts:${context.tenant-id}\' has a malformed ${…} reference.',
        ];
        yield 'resource unterminated' => [
            ['resources' => ['arn:posts:*', 'posts:${foo']],
            'Policy statement resource pattern \'posts:${foo\' has a malformed ${…} reference.',
        ];
        yield 'equality value' => [
            ['conditions' => ['tenant' => '${}']],
            'Policy statement condition \'tenant\' has a malformed ${…} reference.',
        ];
        yield 'eq operand' => [
            ['conditions' => ['tenant' => ['eq' => '${foo']]],
            'Policy statement condition \'tenant\' has a malformed ${…} reference.',
        ];
        yield 'starts_with operand' => [
            ['conditions' => ['name' => ['starts_with' => '${1x}']]],
            'Policy statement condition \'name\' has a malformed ${…} reference.',
        ];
        yield 'string_like operand' => [
            ['conditions' => ['name' => ['string_like' => 'admin-${context.tenant-id}*']]],
            'Policy statement condition \'name\' has a malformed ${…} reference.',
        ];
    }

    /**
     * A malformed `${…}` reference in a resource pattern, an equality value or
     * a string operand is refused on hydration.
     *
     * @param  array<string, mixed>  $extra
     * @param  string  $message
     * @return void
     */
    #[DataProvider('malformedReferenceProvider')]
    public function testMalformedReferencesAreRefused(array $extra, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        Statement::fromArray(['effect' => 'deny', 'actions' => ['x'], ...$extra]);
    }

    /**
     * A resource pattern with a malformed reference on a directly constructed
     * statement cannot be interpolated, so it is undecidable unless another
     * pattern matches; without an interpolator it is compared literally.
     *
     * @return void
     */
    public function testMalformedResourceReferenceOnConstructedStatementIsUndecidable(): void
    {
        $statement = new Statement(
            effect: PolicyEffect::DENY,
            actions: ['posts:read'],
            resources: ['posts:${context.tenant-id}'],
        );

        $fallback = new Statement(
            effect: PolicyEffect::DENY,
            actions: ['posts:read'],
            resources: ['posts:${context.tenant-id}', 'posts:*'],
        );

        $interpolator = new ContextInterpolator;
        $context      = ['tenant-id' => '1'];

        self::assertResult(MatchOutcome::UNDECIDABLE, self::UNRESOLVED_RESOURCE, $statement->assess('posts:read', 'posts:1', $context, $interpolator));
        self::assertFalse($statement->matches('posts:read', 'posts:1', $interpolator, null, $context));
        self::assertResult(MatchOutcome::MATCHES, '', $fallback->assess('posts:read', 'posts:1', $context, $interpolator));
        self::assertResult(MatchOutcome::MATCHES, '', $statement->assess('posts:read', 'posts:${context.tenant-id}'));
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, self::TARGET_MISMATCH, $statement->assess('posts:read', 'posts:1'));
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
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, self::TARGET_MISMATCH, $statement->assess('posts:create', 'arn:users:1'));
    }

    /**
     * Literal resource patterns keep their backslashes, with or without an
     * interpolator, so fully-qualified class names still match.
     *
     * @return void
     */
    public function testBackslashesInLiteralResourcePatternsStillMatch(): void
    {
        $statement = Statement::fromArray([
            'effect'    => 'allow',
            'actions'   => ['posts:read'],
            'resources' => ['App\Models\Post:*'],
        ]);

        $interpolator = new ContextInterpolator;

        self::assertTrue($statement->matches('posts:read', 'App\Models\Post:42'));
        self::assertTrue($statement->matches('posts:read', 'App\Models\Post:42', $interpolator));
        self::assertFalse($statement->matches('posts:read', 'AppModelsPost:42'));
        self::assertFalse($statement->matches('posts:read', 'AppModelsPost:42', $interpolator));
        self::assertFalse($statement->matches('posts:read', 'App\Models\Comment:42', $interpolator));
    }

    // ------------------------------------------------------------------
    // Context variable interpolation wired into Statement
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

        $principal    = (object) ['id' => 42];
        $interpolator = new ContextInterpolator;

        self::assertTrue($statement->matches('posts:read', 'posts:42:draft', $interpolator, $principal));
        self::assertFalse($statement->matches('posts:read', 'posts:99:draft', $interpolator, $principal));
        self::assertResult(MatchOutcome::MATCHES, '', $statement->assess('posts:read', 'posts:42:draft', [], $interpolator, $principal));
        self::assertResult(
            MatchOutcome::DOES_NOT_MATCH,
            self::TARGET_MISMATCH,
            $statement->assess('posts:read', 'posts:99:draft', [], $interpolator, $principal),
        );
    }

    /**
     * A resource pattern whose reference cannot be resolved makes the target
     * undecidable rather than a mismatch, and matches() does not treat it as a
     * match.
     *
     * @return void
     */
    public function testUnresolvedResourcePatternIsUndecidable(): void
    {
        $statement = Statement::fromArray([
            'effect'    => 'deny',
            'actions'   => ['posts:read'],
            'resources' => ['posts:${principal.id}:*', 'arn:users:*'],
        ]);

        $interpolator = new ContextInterpolator;

        self::assertFalse($statement->matches('posts:read', 'posts:42:draft', $interpolator));
        self::assertResult(
            MatchOutcome::UNDECIDABLE,
            self::UNRESOLVED_RESOURCE,
            $statement->assess('posts:read', 'posts:42:draft', [], $interpolator),
        );
    }

    /**
     * An unresolved resource pattern does not prevent another pattern of the
     * same statement from matching.
     *
     * @return void
     */
    public function testUnresolvedResourcePatternMatchesWhenAnotherPatternMatches(): void
    {
        $statement = Statement::fromArray([
            'effect'    => 'deny',
            'actions'   => ['posts:read'],
            'resources' => ['posts:${principal.id}:*', 'posts:*'],
        ]);

        $interpolator = new ContextInterpolator;

        self::assertTrue($statement->matches('posts:read', 'posts:42:draft', $interpolator));
        self::assertResult(MatchOutcome::MATCHES, '', $statement->assess('posts:read', 'posts:42:draft', [], $interpolator));
    }

    /**
     * A substituted value is escaped, so a principal attribute of `*` only
     * matches a literal `*` and never widens the pattern.
     *
     * @return void
     */
    public function testSubstitutedResourceValueIsEscaped(): void
    {
        $statement = Statement::fromArray([
            'effect'    => 'allow',
            'actions'   => ['files:read'],
            'resources' => ['folder:${principal.username}/*'],
        ]);

        $interpolator = new ContextInterpolator;
        $wildcard     = (object) ['username' => '*'];
        $alice        = (object) ['username' => 'alice'];

        self::assertResult(
            MatchOutcome::DOES_NOT_MATCH,
            self::TARGET_MISMATCH,
            $statement->assess('files:read', 'folder:alice/report', [], $interpolator, $wildcard),
        );
        self::assertResult(MatchOutcome::MATCHES, '', $statement->assess('files:read', 'folder:*/report', [], $interpolator, $wildcard));
        self::assertResult(MatchOutcome::MATCHES, '', $statement->assess('files:read', 'folder:alice/report', [], $interpolator, $alice));
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

        self::assertResult(
            MatchOutcome::MATCHES,
            '',
            $statement->assess('posts:read', 'tenant:org-5:posts', ['tenant_id' => 'org-5'], $interpolator),
        );
    }

    /**
     * Interpolated condition operand resolves principal id before operator
     * evaluation.
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

        $principal    = (object) ['id' => '42'];
        $interpolator = new ContextInterpolator;

        self::assertTrue($statement->conditionsSatisfiedBy(['owner_id' => '42'], $interpolator, $principal));
        self::assertFalse($statement->conditionsSatisfiedBy(['owner_id' => '99'], $interpolator, $principal));
        self::assertResult(
            MatchOutcome::MATCHES,
            '',
            $statement->assess('posts:update', null, ['owner_id' => '42'], $interpolator, $principal),
        );
    }

    /**
     * An operator operand whose reference cannot be resolved is undecidable,
     * never compared as an empty string.
     *
     * @return void
     */
    public function testUnresolvedOperatorOperandIsUndecidable(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'deny',
            'actions'    => ['posts:update'],
            'conditions' => ['owner_id' => ['eq' => '${principal.id}']],
        ]);

        self::assertFalse($statement->conditionsSatisfiedBy(['owner_id' => ''], new ContextInterpolator));
        self::assertResult(
            MatchOutcome::UNDECIDABLE,
            'condition \'owner_id\' references a value that cannot be resolved',
            $statement->assess('posts:update', null, ['owner_id' => ''], new ContextInterpolator),
        );
    }

    /**
     * A plain equality value is interpolated, and is undecidable when its
     * reference cannot be resolved.
     *
     * @return void
     */
    public function testEqualityWithInterpolation(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['posts:update'],
            'conditions' => ['tenant' => '${context.expected}'],
        ]);

        $interpolator = new ContextInterpolator;

        self::assertResult(
            MatchOutcome::MATCHES,
            '',
            $statement->assess('posts:update', null, ['tenant' => 'org-*', 'expected' => 'org-*'], $interpolator),
        );
        self::assertResult(
            MatchOutcome::DOES_NOT_MATCH,
            '',
            $statement->assess('posts:update', null, ['tenant' => 'org-1', 'expected' => 'org-*'], $interpolator),
        );
        self::assertResult(
            MatchOutcome::UNDECIDABLE,
            'condition \'tenant\' references a value that cannot be resolved',
            $statement->assess('posts:update', null, ['tenant' => ''], $interpolator),
        );
    }

    /**
     * Without an interpolator a plain equality value is compared literally.
     *
     * @return void
     */
    public function testEqualityWithoutInterpolatorIsLiteral(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['tenant' => '${context.expected}'],
        ]);

        self::assertResult(MatchOutcome::MATCHES, '', $statement->assess('x', null, ['tenant' => '${context.expected}']));
    }

    /**
     * A non-pattern operand is interpolated verbatim: neither its literal text
     * nor its substituted value is escaped.
     *
     * @return void
     */
    public function testNonPatternOperandIsNotEscaped(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['path' => ['eq' => 'App\Models:${context.suffix}']],
        ]);

        self::assertResult(
            MatchOutcome::MATCHES,
            '',
            $statement->assess('x', null, ['path' => 'App\Models:Po*', 'suffix' => 'Po*'], new ContextInterpolator),
        );

        $literal = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['path' => ['eq' => 'App\Models']],
        ]);

        self::assertResult(MatchOutcome::MATCHES, '', $literal->assess('x', null, ['path' => 'App\Models']));
    }

    /**
     * A `string_like` operand keeps its glob meaning while its substituted
     * value is escaped, so a value of `*` matches only a literal `*`.
     *
     * @return void
     */
    public function testStringLikeEscapesInterpolatedValue(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['name' => ['string_like' => '${context.prefix}*']],
        ]);

        $interpolator = new ContextInterpolator;

        self::assertResult(
            MatchOutcome::DOES_NOT_MATCH,
            '',
            $statement->assess('x', null, ['name' => 'admin-user', 'prefix' => '*'], $interpolator),
        );
        self::assertResult(
            MatchOutcome::MATCHES,
            '',
            $statement->assess('x', null, ['name' => '*-user', 'prefix' => '*'], $interpolator),
        );
        self::assertResult(
            MatchOutcome::MATCHES,
            '',
            $statement->assess('x', null, ['name' => 'admin-user', 'prefix' => 'admin'], $interpolator),
        );
        self::assertResult(
            MatchOutcome::UNDECIDABLE,
            'condition \'name\' references a value that cannot be resolved',
            $statement->assess('x', null, ['name' => 'admin-user'], $interpolator),
        );
    }

    /**
     * A `string_like` operand that interpolates to an empty string is
     * undecidable.
     *
     * @return void
     */
    public function testStringLikeEmptyInterpolatedOperandIsUndecidable(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'deny',
            'actions'    => ['x'],
            'conditions' => ['name' => ['string_like' => '${context.pattern}']],
        ]);

        self::assertResult(
            MatchOutcome::UNDECIDABLE,
            'condition \'name\': operator \'string_like\' has an empty operand',
            $statement->assess('x', null, ['name' => 'admin', 'pattern' => ''], new ContextInterpolator),
        );
    }

    /**
     * Without an interpolator a `string_like` operand keeps its backslashes
     * literal.
     *
     * @return void
     */
    public function testStringLikeWithoutInterpolatorKeepsBackslashesLiteral(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['class' => ['string_like' => 'App\Models\*']],
        ]);

        self::assertResult(MatchOutcome::MATCHES, '', $statement->assess('x', null, ['class' => 'App\Models\Post']));
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, '', $statement->assess('x', null, ['class' => 'AppModelsPost']));
    }

    /**
     * Conditions can reference the resource of the check through both
     * conditionsSatisfiedBy() and assess().
     *
     * @return void
     */
    public function testConditionOperandResolvesResource(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['posts:read'],
            'conditions' => ['post_id' => ['eq' => '${resource.id}']],
        ]);

        $interpolator = new ContextInterpolator;

        self::assertTrue($statement->conditionsSatisfiedBy(['post_id' => '42'], $interpolator, null, 'posts:42'));
        self::assertFalse($statement->conditionsSatisfiedBy(['post_id' => '42'], $interpolator, null, 'posts:7'));
        self::assertResult(MatchOutcome::MATCHES, '', $statement->assess('posts:read', 'posts:42', ['post_id' => '42'], $interpolator));
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
    // Outcome precedence across the statement
    // ------------------------------------------------------------------

    /**
     * A condition that definitely fails beats one that cannot be decided, in
     * either order.
     *
     * @return void
     */
    public function testDoesNotMatchBeatsUndecidableAcrossConditions(): void
    {
        $undecidableFirst = Statement::fromArray([
            'effect'     => 'deny',
            'actions'    => ['x'],
            'conditions' => ['a' => ['eq' => 1], 'b' => ['eq' => 2]],
        ]);

        $failingFirst = Statement::fromArray([
            'effect'     => 'deny',
            'actions'    => ['x'],
            'conditions' => ['b' => ['eq' => 2], 'a' => ['eq' => 1]],
        ]);

        self::assertResult(MatchOutcome::DOES_NOT_MATCH, '', $undecidableFirst->assess('x', null, ['b' => 3]));
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, '', $failingFirst->assess('x', null, ['b' => 3]));
    }

    /**
     * A failing operator beats an undecidable one within the same condition.
     *
     * @return void
     */
    public function testDoesNotMatchBeatsUndecidableAcrossOperators(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'deny',
            'actions'    => ['x'],
            'conditions' => ['n' => ['starts_with' => 'a', 'eq' => 6]],
        ]);

        self::assertResult(MatchOutcome::DOES_NOT_MATCH, '', $statement->assess('x', null, ['n' => 5]));
        self::assertResult(
            MatchOutcome::UNDECIDABLE,
            'condition \'n\': operator \'starts_with\' needs a string value',
            $statement->assess('x', null, ['n' => 6]),
        );
    }

    /**
     * When several conditions cannot be decided, the first one is reported.
     *
     * @return void
     */
    public function testFirstUndecidableConditionIsReported(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'deny',
            'actions'    => ['x'],
            'conditions' => ['a' => ['eq' => 1], 'b' => ['eq' => 2]],
        ]);

        self::assertResult(MatchOutcome::UNDECIDABLE, 'key \'a\' is missing from the context', $statement->assess('x'));
    }

    /**
     * An invalid condition beats every other outcome, wherever it sits.
     *
     * @return void
     */
    public function testInvalidBeatsEverything(): void
    {
        $invalidLast = new Statement(
            effect: PolicyEffect::DENY,
            actions: ['x'],
            conditions: ['a' => ['eq' => 1], 'b' => ['eq' => 1], 'c' => ['bogus' => 1]],
        );

        $invalidFirst = new Statement(
            effect: PolicyEffect::DENY,
            actions: ['x'],
            conditions: ['c' => ['bogus' => 1], 'b' => ['eq' => 1], 'a' => ['eq' => 1]],
        );

        $context = ['b' => 2, 'c' => 1];
        $detail  = 'condition \'c\' has an unknown operator \'bogus\'';

        self::assertResult(MatchOutcome::INVALID, $detail, $invalidLast->assess('x', null, $context));
        self::assertResult(MatchOutcome::INVALID, $detail, $invalidFirst->assess('x', null, $context));
    }

    /**
     * The target and conditions combine: an undecidable resource pattern is
     * beaten by a failing or invalid condition and kept over a matching one.
     *
     * @return void
     */
    public function testTargetOutcomeCombinesWithConditions(): void
    {
        $statement = new Statement(
            effect: PolicyEffect::DENY,
            actions: ['posts:read'],
            resources: ['posts:${principal.id}'],
            conditions: ['tenant' => ['eq' => 'org-1']],
        );

        $invalid = new Statement(
            effect: PolicyEffect::DENY,
            actions: ['posts:read'],
            resources: ['posts:${principal.id}'],
            conditions: ['tenant' => ['bogus' => 'org-1']],
        );

        $interpolator = new ContextInterpolator;

        self::assertResult(
            MatchOutcome::UNDECIDABLE,
            self::UNRESOLVED_RESOURCE,
            $statement->assess('posts:read', 'posts:1', ['tenant' => 'org-1'], $interpolator),
        );
        self::assertResult(
            MatchOutcome::DOES_NOT_MATCH,
            '',
            $statement->assess('posts:read', 'posts:1', ['tenant' => 'org-2'], $interpolator),
        );
        self::assertResult(
            MatchOutcome::INVALID,
            'condition \'tenant\' has an unknown operator \'bogus\'',
            $invalid->assess('posts:read', 'posts:1', ['tenant' => 'org-1'], $interpolator),
        );
    }

    /**
     * A statement whose action or resource does not cover the check reports the
     * mismatch without assessing its conditions, even an invalid one.
     *
     * @return void
     */
    public function testTargetMismatchShortCircuitsConditions(): void
    {
        $statement = new Statement(
            effect: PolicyEffect::DENY,
            actions: ['posts:read'],
            resources: ['posts:1'],
            conditions: ['tenant' => ['bogus' => 'org-1']],
        );

        self::assertResult(MatchOutcome::DOES_NOT_MATCH, self::TARGET_MISMATCH, $statement->assess('users:read', 'posts:1', ['tenant' => 'org-1']));
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, self::TARGET_MISMATCH, $statement->assess('posts:read', 'posts:2', ['tenant' => 'org-1']));
        self::assertResult(MatchOutcome::INVALID, 'condition \'tenant\' has an unknown operator \'bogus\'', $statement->assess('posts:read', 'posts:1', ['tenant' => 'org-1']));
    }

    // ------------------------------------------------------------------
    // Mutation-kill: default resources value contains '*'
    // ------------------------------------------------------------------

    /**
     * The constructor default for resources is `['*']` — removing the `'*'`
     * element would break the default wildcard behaviour.
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
        self::assertTrue($statement->matches('posts:create'));
    }

    // ------------------------------------------------------------------
    // Mutation-kill: condition loop
    // ------------------------------------------------------------------

    /**
     * When a condition entry fails, conditionsSatisfiedBy returns false.
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

        self::assertFalse($statement->conditionsSatisfiedBy([]));
    }

    /**
     * Every condition must pass for the statement to match.
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

        self::assertTrue($statement->conditionsSatisfiedBy(['a' => 1, 'b' => 2]));
        self::assertFalse($statement->conditionsSatisfiedBy(['a' => 1, 'b' => 99]));
        self::assertFalse($statement->conditionsSatisfiedBy(['a' => 99, 'b' => 2]));
    }

    // ------------------------------------------------------------------
    // Mutation-kill: malformed directly constructed conditions
    // ------------------------------------------------------------------

    /**
     * A directly constructed statement with an integer condition key is
     * invalid.
     *
     * @return void
     */
    public function testIntegerConditionKeyFailsClosed(): void
    {
        $statement = new Statement(
            effect: PolicyEffect::ALLOW,
            actions: ['x'],
            conditions: [0 => ['eq' => 'val']],
        );

        self::assertFalse($statement->conditionsSatisfiedBy(['0' => 'val']));
        self::assertResult(MatchOutcome::INVALID, 'a condition key is not a string', $statement->assess('x', null, ['0' => 'val']));
    }

    /**
     * A directly constructed statement with an empty operator map is invalid.
     *
     * @return void
     */
    public function testEmptyOperatorMapIsInvalid(): void
    {
        $statement = new Statement(
            effect: PolicyEffect::ALLOW,
            actions: ['x'],
            conditions: ['tenant' => []],
        );

        self::assertResult(MatchOutcome::INVALID, 'condition \'tenant\' has no operators', $statement->assess('x', null, ['tenant' => 'org-1']));
    }

    /**
     * A string key that exists in context should pass when the value matches.
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

        self::assertTrue($statement->conditionsSatisfiedBy(['key' => 'expected']));
    }

    /**
     * A string key absent from the context is undecidable.
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

        self::assertFalse($statement->conditionsSatisfiedBy(['other' => 'expected']));
        self::assertResult(
            MatchOutcome::UNDECIDABLE,
            'key \'missing\' is missing from the context',
            $statement->assess('x', null, ['other' => 'expected']),
        );
    }

    // ------------------------------------------------------------------
    // Mutation-kill: hydration preserves entries
    // ------------------------------------------------------------------

    /**
     * resolveConditions preserves every key-value pair from the input.
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

    /**
     * normaliseStringList re-indexes non-sequential keys and refuses non-string
     * members.
     *
     * @return void
     */
    public function testNormaliseStringListReindexes(): void
    {
        $statement = Statement::fromArray([
            'effect'    => 'allow',
            'actions'   => [3 => 'a', 7 => 'b', 9 => 'c'],
            'resources' => [2 => 'r1', 5 => 'r2'],
        ]);

        self::assertSame(['a', 'b', 'c'], $statement->actions);
        self::assertSame(['r1', 'r2'], $statement->resources);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('actions must be strings');
        // @phpstan-ignore-next-line argument.type
        Statement::fromArray(['effect' => 'allow', 'actions' => ['valid', 42]]);
    }

    // ------------------------------------------------------------------
    // Mutation-kill: condition operator maps
    // ------------------------------------------------------------------

    /**
     * Non-array condition compared by identity.
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

        self::assertTrue($statement->conditionsSatisfiedBy(['key' => 'value']));
        self::assertFalse($statement->conditionsSatisfiedBy(['key' => 'other']));
    }

    /**
     * A directly constructed statement whose operator map uses a non-string key
     * is invalid.
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

        self::assertFalse($statement->conditionsSatisfiedBy(['key' => 'operand']));
        self::assertResult(
            MatchOutcome::INVALID,
            'condition \'key\' must map operator names to operands',
            $statement->assess('x', null, ['key' => 'operand']),
        );
    }

    /**
     * Multiple operators must all pass.
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

        self::assertTrue($statement->conditionsSatisfiedBy(['age' => 30]));
        self::assertFalse($statement->conditionsSatisfiedBy(['age' => 10]));
        self::assertFalse($statement->conditionsSatisfiedBy(['age' => 70]));
    }

    /**
     * Each operator arm is individually distinguishable when tested against
     * specific values, with the exact outcome and trace detail.
     *
     * @return void
     */
    public function testEveryOperatorArmIsDistinguishable(): void
    {
        foreach (self::operatorArmCases() as $i => $case) {
            $statement = Statement::fromArray([
                'effect'     => 'allow',
                'actions'    => ['x'],
                'conditions' => ['k' => $case['k']],
            ]);

            $result = $statement->assess('x', null, ['k' => $case['ctx']]);

            self::assertSame($case['outcome'], $result->outcome, "Case {$i} outcome");
            self::assertSame($case['detail'], $result->detail, "Case {$i} detail");
        }
    }

    /**
     * The `in` operator checks membership.
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

        self::assertTrue($statement->conditionsSatisfiedBy(['role' => 'admin']));
        self::assertFalse($statement->conditionsSatisfiedBy(['role' => 'guest']));
        self::assertTrue($statement->conditionsSatisfiedBy(['role' => 'admin'], new ContextInterpolator));
    }

    /**
     * The `not_in` operator checks non-membership.
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

        self::assertTrue($statement->conditionsSatisfiedBy(['role' => 'guest']));
        self::assertFalse($statement->conditionsSatisfiedBy(['role' => 'admin']));
    }

    /**
     * `cidr` decides only for a string IP address.
     *
     * @return void
     */
    public function testCidrOperatorTypeGuards(): void
    {
        $stmt = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['ip' => ['cidr' => '10.0.0.0/8']],
        ]);

        self::assertFalse($stmt->conditionsSatisfiedBy(['ip' => 123]));
        self::assertTrue($stmt->conditionsSatisfiedBy(['ip' => '10.0.0.1']));
        self::assertResult(
            MatchOutcome::UNDECIDABLE,
            'condition \'ip\': operator \'cidr\' needs an IP address',
            $stmt->assess('x', null, ['ip' => 123]),
        );
    }

    /**
     * `starts_with` matches a string prefix and is undecidable for a non-string
     * value.
     *
     * @return void
     */
    public function testStartsWithTypeGuardsAndLogic(): void
    {
        $stmt = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['val' => ['starts_with' => 'pre']],
        ]);

        self::assertTrue($stmt->conditionsSatisfiedBy(['val' => 'prefix']));
        self::assertFalse($stmt->conditionsSatisfiedBy(['val' => 'suffix']));
        self::assertFalse($stmt->conditionsSatisfiedBy(['val' => 123]));
    }

    /**
     * `ends_with` matches a string suffix and is undecidable for a non-string
     * value.
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

        self::assertTrue($stmt->conditionsSatisfiedBy(['val' => 'suffix']));
        self::assertFalse($stmt->conditionsSatisfiedBy(['val' => 'hello']));
        self::assertFalse($stmt->conditionsSatisfiedBy(['val' => 123]));
    }

    /**
     * `string_like` matches a glob and is undecidable for a non-string value.
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

        self::assertTrue($stmt->conditionsSatisfiedBy(['val' => 'foobar']));
        self::assertFalse($stmt->conditionsSatisfiedBy(['val' => 'bazbar']));
        self::assertFalse($stmt->conditionsSatisfiedBy(['val' => 42]));
    }

    /**
     * `null` is true iff the value is null; `not_null` is its opposite.
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

        self::assertTrue($stmtNull->conditionsSatisfiedBy(['k' => null]));
        self::assertFalse($stmtNull->conditionsSatisfiedBy(['k' => 0]));
        self::assertFalse($stmtNull->conditionsSatisfiedBy(['k' => '']));
        self::assertFalse($stmtNull->conditionsSatisfiedBy(['k' => false]));

        $stmtNotNull = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['k' => ['not_null' => true]],
        ]);

        self::assertTrue($stmtNotNull->conditionsSatisfiedBy(['k' => 'x']));
        self::assertTrue($stmtNotNull->conditionsSatisfiedBy(['k' => 0]));
        self::assertFalse($stmtNotNull->conditionsSatisfiedBy(['k' => null]));
    }

    /**
     * `eq` uses `===` and `neq` uses `!==`.
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

        self::assertTrue($stmtEq->conditionsSatisfiedBy(['k' => 'a']));
        self::assertFalse($stmtEq->conditionsSatisfiedBy(['k' => 'b']));

        self::assertFalse($stmtNeq->conditionsSatisfiedBy(['k' => 'a']));
        self::assertTrue($stmtNeq->conditionsSatisfiedBy(['k' => 'b']));
    }

    // ------------------------------------------------------------------
    // Mutation-kill: operand interpolation
    // ------------------------------------------------------------------

    /**
     * Only string operands are interpolated: the strings inside an array
     * operand are compared literally.
     *
     * @return void
     */
    public function testInterpolateOperandsInterpolatesArrayStringValues(): void
    {
        $principal = (object) ['id' => '42'];

        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['owner' => ['in' => ['${principal.id}', 'admin']]],
        ]);

        $interpolator = new ContextInterpolator;

        self::assertResult(
            MatchOutcome::DOES_NOT_MATCH,
            '',
            $statement->assess('x', null, ['owner' => '42'], $interpolator, $principal),
        );
        self::assertResult(
            MatchOutcome::MATCHES,
            '',
            $statement->assess('x', null, ['owner' => '${principal.id}'], $interpolator, $principal),
        );
    }

    /**
     * Non-string condition values pass through interpolation unchanged.
     *
     * @return void
     */
    public function testInterpolateOperandsNonStringNonArrayPassesThrough(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'conditions' => ['age' => 25, 'size' => ['gt' => 3]],
        ]);

        $interpolator = new ContextInterpolator;

        self::assertTrue($statement->conditionsSatisfiedBy(['age' => 25, 'size' => 4], $interpolator));
        self::assertFalse($statement->conditionsSatisfiedBy(['age' => 30, 'size' => 4], $interpolator));
    }

    /**
     * Assert a match result's outcome and trace detail.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome  $outcome
     * @param  string  $detail
     * @param  \SineMacula\Laravel\Authorization\Evaluation\MatchResult  $result
     * @return void
     */
    private static function assertResult(MatchOutcome $outcome, string $detail, MatchResult $result): void
    {
        self::assertSame($outcome, $result->outcome);
        self::assertSame($detail, $result->detail);
    }

    /**
     * eq / neq / in / not_in cases.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>, 2: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome}>
     */
    private static function equalityAndMembershipCases(): iterable
    {
        yield 'eq-true' => [['tenant' => ['eq' => 'org-1']], ['tenant' => 'org-1'], MatchOutcome::MATCHES];
        yield 'eq-false' => [['tenant' => ['eq' => 'org-1']], ['tenant' => 'org-2'], MatchOutcome::DOES_NOT_MATCH];
        yield 'neq-true' => [['tenant' => ['neq' => 'org-1']], ['tenant' => 'org-2'], MatchOutcome::MATCHES];
        yield 'neq-false' => [['tenant' => ['neq' => 'org-1']], ['tenant' => 'org-1'], MatchOutcome::DOES_NOT_MATCH];
        yield 'in-true' => [['role' => ['in' => ['admin', 'staff']]], ['role' => 'admin'], MatchOutcome::MATCHES];
        yield 'in-false' => [['role' => ['in' => ['admin', 'staff']]], ['role' => 'guest'], MatchOutcome::DOES_NOT_MATCH];
        yield 'not_in-true' => [['role' => ['not_in' => ['admin', 'staff']]], ['role' => 'guest'], MatchOutcome::MATCHES];
        yield 'not_in-false' => [['role' => ['not_in' => ['admin', 'staff']]], ['role' => 'admin'], MatchOutcome::DOES_NOT_MATCH];
    }

    /**
     * starts_with / ends_with / cidr cases.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>, 2: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome}>
     */
    private static function stringAndCidrCases(): iterable
    {
        yield 'starts_with-true' => [['email' => ['starts_with' => 'admin@']], ['email' => 'admin@example'], MatchOutcome::MATCHES];
        yield 'ends_with-true' => [['email' => ['ends_with' => 'sine.co']], ['email' => 'a@sine.co'], MatchOutcome::MATCHES];
        yield 'cidr-match' => [['ip' => ['cidr' => '192.168.1.0/24']], ['ip' => '192.168.1.25'], MatchOutcome::MATCHES];
        yield 'cidr-no-match' => [['ip' => ['cidr' => '192.168.1.0/24']], ['ip' => '10.0.0.1'], MatchOutcome::DOES_NOT_MATCH];
        yield 'cidr-exact' => [['ip' => ['cidr' => '192.168.1.1']], ['ip' => '192.168.1.1'], MatchOutcome::MATCHES];
        yield 'cidr-exact-miss' => [['ip' => ['cidr' => '192.168.1.1']], ['ip' => '192.168.1.2'], MatchOutcome::DOES_NOT_MATCH];
        yield 'cidr-zero-bits' => [['ip' => ['cidr' => '0.0.0.0/0']], ['ip' => '1.2.3.4'], MatchOutcome::MATCHES];
        yield 'cidr-mask-32-match' => [['ip' => ['cidr' => '192.168.1.1/32']], ['ip' => '192.168.1.1'], MatchOutcome::MATCHES];
        yield 'cidr-mask-32-miss' => [['ip' => ['cidr' => '192.168.1.1/32']], ['ip' => '192.168.1.2'], MatchOutcome::DOES_NOT_MATCH];
        yield 'cidr-mask-31-match' => [['ip' => ['cidr' => '192.168.1.0/31']], ['ip' => '192.168.1.1'], MatchOutcome::MATCHES];
        yield 'cidr-mask-31-miss' => [['ip' => ['cidr' => '192.168.1.0/31']], ['ip' => '192.168.1.2'], MatchOutcome::DOES_NOT_MATCH];
        yield 'cidr-ipv6-match' => [['ip' => ['cidr' => '2001:db8::/32']], ['ip' => '2001:db8::1'], MatchOutcome::MATCHES];
        yield 'cidr-ipv6-miss' => [['ip' => ['cidr' => '2001:db8::/32']], ['ip' => '2001:db9::1'], MatchOutcome::DOES_NOT_MATCH];
        yield 'cidr-other-family' => [['ip' => ['cidr' => '0.0.0.0/0']], ['ip' => '::1'], MatchOutcome::DOES_NOT_MATCH];
        yield 'cidr-bad-ip' => [['ip' => ['cidr' => '192.168.1.0/24']], ['ip' => 'not-an-ip'], MatchOutcome::UNDECIDABLE];
    }

    /**
     * before / after / between cases.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>, 2: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome}>
     */
    private static function temporalCases(): iterable
    {
        yield 'between-equal-lower' => [['at' => ['between' => ['2026-04-15', '2026-04-20']]], ['at' => '2026-04-15'], MatchOutcome::MATCHES];
        yield 'between-equal-upper' => [['at' => ['between' => ['2026-04-15', '2026-04-20']]], ['at' => '2026-04-20'], MatchOutcome::MATCHES];
        yield 'between-just-below' => [['at' => ['between' => ['2026-04-15', '2026-04-20']]], ['at' => '2026-04-14'], MatchOutcome::DOES_NOT_MATCH];
        yield 'between-just-above' => [['at' => ['between' => ['2026-04-15', '2026-04-20']]], ['at' => '2026-04-21'], MatchOutcome::DOES_NOT_MATCH];
        yield 'before-equal' => [['at' => ['before' => '2026-04-15']], ['at' => '2026-04-15'], MatchOutcome::DOES_NOT_MATCH];
        yield 'after-equal' => [['at' => ['after' => '2026-04-15']], ['at' => '2026-04-15'], MatchOutcome::DOES_NOT_MATCH];
        yield 'before-iso' => [['at' => ['before' => '2026-04-15']], ['at' => '2026-04-14'], MatchOutcome::MATCHES];
        yield 'before-iso-false' => [['at' => ['before' => '2026-04-15']], ['at' => '2026-04-16'], MatchOutcome::DOES_NOT_MATCH];
        yield 'after-iso' => [['at' => ['after' => '2026-04-15']], ['at' => '2026-04-16'], MatchOutcome::MATCHES];
        yield 'between-iso' => [['at' => ['between' => ['2026-04-10', '2026-04-20']]], ['at' => '2026-04-15'], MatchOutcome::MATCHES];
        yield 'between-outside' => [['at' => ['between' => ['2026-04-10', '2026-04-12']]], ['at' => '2026-04-15'], MatchOutcome::DOES_NOT_MATCH];
        yield 'time-int' => [['at' => ['before' => 2000000000]], ['at' => 1000000000], MatchOutcome::MATCHES];
        yield 'time-datetime' => [['at' => ['after' => '2026-04-15']], ['at' => new \DateTimeImmutable('2026-04-16')], MatchOutcome::MATCHES];
        yield 'time-empty-string' => [['at' => ['before' => '2026-04-15']], ['at' => ''], MatchOutcome::UNDECIDABLE];
        yield 'time-unparseable' => [['at' => ['between' => ['2026-04-10', '2026-04-20']]], ['at' => 'garbage'], MatchOutcome::UNDECIDABLE];
    }

    /**
     * string_like / null / not_null cases.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>, 2: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome}>
     */
    private static function stringLikeAndNullCases(): iterable
    {
        yield 'string_like-match' => [['name' => ['string_like' => 'admin*']], ['name' => 'admin-user'], MatchOutcome::MATCHES];
        yield 'string_like-miss' => [['name' => ['string_like' => 'admin*']], ['name' => 'guest-user'], MatchOutcome::DOES_NOT_MATCH];
        yield 'string_like-question' => [['name' => ['string_like' => 'user?']], ['name' => 'user1'], MatchOutcome::MATCHES];
        yield 'string_like-non-string' => [['name' => ['string_like' => 'admin*']], ['name' => 123], MatchOutcome::UNDECIDABLE];
        yield 'null-true' => [['field' => ['null' => true]], ['field' => null], MatchOutcome::MATCHES];
        yield 'null-false' => [['field' => ['null' => true]], ['field' => 'value'], MatchOutcome::DOES_NOT_MATCH];
        yield 'null-zero-is-not-null' => [['field' => ['null' => true]], ['field' => 0], MatchOutcome::DOES_NOT_MATCH];
        yield 'null-empty-is-not-null' => [['field' => ['null' => true]], ['field' => ''], MatchOutcome::DOES_NOT_MATCH];
        yield 'not_null-true' => [['field' => ['not_null' => true]], ['field' => 'value'], MatchOutcome::MATCHES];
        yield 'not_null-false' => [['field' => ['not_null' => true]], ['field' => null], MatchOutcome::DOES_NOT_MATCH];
    }

    /**
     * gt / gte / lt / lte cases.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>, 2: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome}>
     */
    private static function numericComparisonCases(): iterable
    {
        yield 'gt-true' => [['age' => ['gt' => 18]], ['age' => 21], MatchOutcome::MATCHES];
        yield 'gt-false-equal' => [['age' => ['gt' => 18]], ['age' => 18], MatchOutcome::DOES_NOT_MATCH];
        yield 'gt-false-less' => [['age' => ['gt' => 18]], ['age' => 16], MatchOutcome::DOES_NOT_MATCH];
        yield 'gte-true-equal' => [['age' => ['gte' => 18]], ['age' => 18], MatchOutcome::MATCHES];
        yield 'gte-true-greater' => [['age' => ['gte' => 18]], ['age' => 19], MatchOutcome::MATCHES];
        yield 'gte-false' => [['age' => ['gte' => 18]], ['age' => 17], MatchOutcome::DOES_NOT_MATCH];
        yield 'lt-true' => [['age' => ['lt' => 18]], ['age' => 16], MatchOutcome::MATCHES];
        yield 'lt-false-equal' => [['age' => ['lt' => 18]], ['age' => 18], MatchOutcome::DOES_NOT_MATCH];
        yield 'lt-false-greater' => [['age' => ['lt' => 18]], ['age' => 21], MatchOutcome::DOES_NOT_MATCH];
        yield 'lte-true-equal' => [['age' => ['lte' => 18]], ['age' => 18], MatchOutcome::MATCHES];
        yield 'lte-true-less' => [['age' => ['lte' => 18]], ['age' => 17], MatchOutcome::MATCHES];
        yield 'lte-false' => [['age' => ['lte' => 18]], ['age' => 19], MatchOutcome::DOES_NOT_MATCH];
        yield 'gt-string-numeric' => [['age' => ['gt' => '18']], ['age' => '21'], MatchOutcome::MATCHES];
        yield 'gt-non-numeric-actual' => [['age' => ['gt' => 18]], ['age' => 'abc'], MatchOutcome::UNDECIDABLE];
        yield 'gt-float' => [['val' => ['gt' => 1.5]], ['val' => 2.5], MatchOutcome::MATCHES];
    }

    /**
     * bool operator cases.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>, 2: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome}>
     */
    private static function boolCases(): iterable
    {
        yield 'bool-true-string' => [['flag' => ['bool' => 'true']], ['flag' => true], MatchOutcome::MATCHES];
        yield 'bool-true-int' => [['flag' => ['bool' => 1]], ['flag' => 'true'], MatchOutcome::MATCHES];
        yield 'bool-true-string-one' => [['flag' => ['bool' => '1']], ['flag' => true], MatchOutcome::MATCHES];
        yield 'bool-false-mismatch' => [['flag' => ['bool' => 'true']], ['flag' => false], MatchOutcome::DOES_NOT_MATCH];
        yield 'bool-false-both' => [['flag' => ['bool' => false]], ['flag' => 0], MatchOutcome::MATCHES];
        yield 'bool-false-zero-string' => [['flag' => ['bool' => '0']], ['flag' => false], MatchOutcome::MATCHES];
        yield 'bool-false-string' => [['flag' => ['bool' => 'false']], ['flag' => '0'], MatchOutcome::MATCHES];
        yield 'bool-unrecognised-actual' => [['flag' => ['bool' => true]], ['flag' => 'yes'], MatchOutcome::UNDECIDABLE];
    }

    /**
     * Fixture list driving `testEveryOperatorArmIsDistinguishable`. Each row
     * carries the per-operator condition, the actual context value, and the
     * expected outcome and trace detail.
     *
     * @return list<array{k: array<string, mixed>, ctx: mixed, outcome: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, detail: string}>
     */
    private static function operatorArmCases(): array
    {
        $matches     = MatchOutcome::MATCHES;
        $fails       = MatchOutcome::DOES_NOT_MATCH;
        $undecidable = MatchOutcome::UNDECIDABLE;

        return [
            // eq vs neq
            ['k' => ['eq' => 'a'], 'ctx' => 'a', 'outcome' => $matches, 'detail' => ''],
            ['k' => ['neq' => 'a'], 'ctx' => 'b', 'outcome' => $matches, 'detail' => ''],
            ['k' => ['neq' => 'a'], 'ctx' => 'a', 'outcome' => $fails, 'detail' => ''],

            // in vs not_in
            ['k' => ['in' => ['a', 'b']], 'ctx' => 'a', 'outcome' => $matches, 'detail' => ''],
            ['k' => ['in' => ['a', 'b']], 'ctx' => 'c', 'outcome' => $fails, 'detail' => ''],
            ['k' => ['not_in' => ['a', 'b']], 'ctx' => 'c', 'outcome' => $matches, 'detail' => ''],
            ['k' => ['not_in' => ['a', 'b']], 'ctx' => 'a', 'outcome' => $fails, 'detail' => ''],

            // starts_with / ends_with
            ['k' => ['starts_with' => 'he'], 'ctx' => 'hello', 'outcome' => $matches, 'detail' => ''],
            ['k' => ['starts_with' => 'he'], 'ctx' => 'world', 'outcome' => $fails, 'detail' => ''],
            ['k' => ['ends_with' => 'lo'], 'ctx' => 'hello', 'outcome' => $matches, 'detail' => ''],
            ['k' => ['ends_with' => 'lo'], 'ctx' => 'world', 'outcome' => $fails, 'detail' => ''],

            // starts_with / ends_with with a non-string value
            ['k' => ['starts_with' => 'x'], 'ctx' => 123, 'outcome' => $undecidable, 'detail' => 'condition \'k\': operator \'starts_with\' needs a string value'],
            ['k' => ['ends_with' => 'x'], 'ctx' => 123, 'outcome' => $undecidable, 'detail' => 'condition \'k\': operator \'ends_with\' needs a string value'],

            // cidr
            ['k' => ['cidr' => '10.0.0.0/8'], 'ctx' => '10.1.2.3', 'outcome' => $matches, 'detail' => ''],
            ['k' => ['cidr' => '10.0.0.0/8'], 'ctx' => 123, 'outcome' => $undecidable, 'detail' => 'condition \'k\': operator \'cidr\' needs an IP address'],

            // string_like
            ['k' => ['string_like' => 'foo*'], 'ctx' => 'foobar', 'outcome' => $matches, 'detail' => ''],
            ['k' => ['string_like' => 'foo*'], 'ctx' => 'baz', 'outcome' => $fails, 'detail' => ''],
            ['k' => ['string_like' => 'foo*'], 'ctx' => 42, 'outcome' => $undecidable, 'detail' => 'condition \'k\': operator \'string_like\' needs a string value'],

            // null / not_null
            ['k' => ['null' => true], 'ctx' => null, 'outcome' => $matches, 'detail' => ''],
            ['k' => ['null' => true], 'ctx' => 'x', 'outcome' => $fails, 'detail' => ''],
            ['k' => ['not_null' => true], 'ctx' => 'x', 'outcome' => $matches, 'detail' => ''],
            ['k' => ['not_null' => true], 'ctx' => null, 'outcome' => $fails, 'detail' => ''],

            // times
            ['k' => ['before' => '2026-04-15'], 'ctx' => 'garbage', 'outcome' => $undecidable, 'detail' => 'condition \'k\': operator \'before\' needs a time'],
            ['k' => ['after' => '2026-04-15'], 'ctx' => 'garbage', 'outcome' => $undecidable, 'detail' => 'condition \'k\': operator \'after\' needs a time'],
            ['k' => ['between' => ['2026-04-10', '2026-04-20']], 'ctx' => 'garbage', 'outcome' => $undecidable, 'detail' => 'condition \'k\': operator \'between\' needs a time'],

            // numbers
            ['k' => ['gt' => 1], 'ctx' => 'abc', 'outcome' => $undecidable, 'detail' => 'condition \'k\': operator \'gt\' needs a number'],
            ['k' => ['lte' => 1], 'ctx' => 'abc', 'outcome' => $undecidable, 'detail' => 'condition \'k\': operator \'lte\' needs a number'],

            // bool
            ['k' => ['bool' => true], 'ctx' => 'yes', 'outcome' => $undecidable, 'detail' => 'condition \'k\': operator \'bool\' needs a boolean'],
        ];
    }
}
