<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome;

/**
 * Unit tests for the condition operator evaluator.
 *
 * Every case pins the exact outcome and trace detail, so a mutant that changes
 * a comparator, a bound, a type guard or a detail string fails.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 * @SuppressWarnings("php:S1448")
 */
#[CoversClass(ConditionEvaluator::class)]
final class ConditionEvaluatorTest extends TestCase
{
    /**
     * Provide every operator case for evaluate().
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: mixed, 3: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 4: string}>
     */
    public static function evaluateProvider(): iterable
    {
        yield from self::equalityCases();
        yield from self::membershipCases();
        yield from self::nullCases();
        yield from self::ipv4CidrCases();
        yield from self::ipv6CidrCases();
        yield from self::invalidCidrCases();
        yield from self::stringCases();
        yield from self::stringLikeCases();
        yield from self::timeComparisonCases();
        yield from self::betweenCases();
        yield from self::numericComparisonCases();
        yield from self::boolCases();
        yield from self::unknownOperatorCases();
    }

    /**
     * evaluate() returns the expected outcome and detail for each case.
     *
     * @param  string  $operator
     * @param  mixed  $operand
     * @param  mixed  $actual
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome  $outcome
     * @param  string  $detail
     * @return void
     */
    #[DataProvider('evaluateProvider')]
    public function testEvaluate(string $operator, mixed $operand, mixed $actual, MatchOutcome $outcome, string $detail): void
    {
        $result = ConditionEvaluator::evaluate($operator, $operand, $actual);

        self::assertSame($outcome, $result->outcome);
        self::assertSame($detail, $result->detail);
    }

    /**
     * Provide every operator case for operandError().
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: string|null}>
     */
    public static function operandErrorProvider(): iterable
    {
        yield from self::untypedOperandCases();
        yield from self::membershipOperandCases();
        yield from self::cidrOperandCases();
        yield from self::stringOperandCases();
        yield from self::timeOperandCases();
        yield from self::numericOperandCases();
        yield from self::boolOperandCases();
    }

    /**
     * operandError() returns null for a valid operand and the exact reason for
     * an invalid one.
     *
     * @param  string  $operator
     * @param  mixed  $operand
     * @param  string|null  $expected
     * @return void
     */
    #[DataProvider('operandErrorProvider')]
    public function testOperandError(string $operator, mixed $operand, ?string $expected): void
    {
        self::assertSame($expected, ConditionEvaluator::operandError($operator, $operand));
    }

    /**
     * OPERATORS lists exactly the eighteen supported operators, in order.
     *
     * @return void
     */
    public function testOperatorsListsEverySupportedOperator(): void
    {
        self::assertSame([
            'eq',
            'neq',
            'in',
            'not_in',
            'null',
            'not_null',
            'cidr',
            'starts_with',
            'ends_with',
            'string_like',
            'before',
            'after',
            'between',
            'gt',
            'gte',
            'lt',
            'lte',
            'bool',
        ], ConditionEvaluator::OPERATORS);
    }

    /**
     * PATTERN_OPERATORS lists only string_like.
     *
     * @return void
     */
    public function testPatternOperatorsListsStringLikeOnly(): void
    {
        self::assertSame(['string_like'], ConditionEvaluator::PATTERN_OPERATORS);
    }

    /**
     * Every listed operator is known to operandError(), and every one but the
     * unknown arm is evaluated without reporting an unknown operator.
     *
     * @return void
     */
    public function testEveryListedOperatorIsKnown(): void
    {
        foreach (ConditionEvaluator::OPERATORS as $operator) {
            self::assertNotSame("unknown operator '{$operator}'", ConditionEvaluator::operandError($operator, null));
            self::assertNotSame("unknown operator '{$operator}'", ConditionEvaluator::evaluate($operator, null, null)->detail);
        }
    }

    /**
     * An unknown operator logs a debug line naming it and evaluates as invalid.
     *
     * @return void
     */
    public function testUnknownOperatorLogsAtDebugLevel(): void
    {
        /** @var \ArrayObject<int, array{0: mixed, 1: string}> $records */
        $records = new \ArrayObject;
        $logger  = self::recordingLogger($records);

        $result = self::withLog(static fn (): mixed => $logger, static fn () => ConditionEvaluator::evaluate('bogus', 'x', 'x'));

        self::assertSame(MatchOutcome::INVALID, $result->outcome);
        self::assertSame('unknown operator \'bogus\'', $result->detail);
        self::assertSame([
            ['debug', 'Unknown authorization condition operator \'bogus\': the statement is invalid.'],
        ], $records->getArrayCopy());
    }

    /**
     * logUnknownOperator() writes the debug line when called directly.
     *
     * @return void
     */
    public function testLogUnknownOperatorWritesDebugLine(): void
    {
        /** @var \ArrayObject<int, array{0: mixed, 1: string}> $records */
        $records = new \ArrayObject;
        $logger  = self::recordingLogger($records);

        self::withLog(static fn (): mixed => $logger, static function (): null {
            ConditionEvaluator::logUnknownOperator('nope');

            return null;
        });

        self::assertSame([
            ['debug', 'Unknown authorization condition operator \'nope\': the statement is invalid.'],
        ], $records->getArrayCopy());
    }

    /**
     * A failing logger never aborts the check: the unknown operator still
     * evaluates as invalid.
     *
     * @return void
     */
    public function testUnknownOperatorSurvivesFailingLogger(): void
    {
        $result = self::withLog(static function (): never {
            throw new \RuntimeException('logging back-end unavailable');
        }, static fn () => ConditionEvaluator::evaluate('bogus', 'x', 'x'));

        self::assertSame(MatchOutcome::INVALID, $result->outcome);
        self::assertSame('unknown operator \'bogus\'', $result->detail);
    }

    /**
     * A container with no logger bound never aborts the check either.
     *
     * @return void
     */
    public function testUnknownOperatorSurvivesMissingLogger(): void
    {
        $previous = Container::getInstance();

        Container::setInstance(new Container);

        try {
            $result = ConditionEvaluator::evaluate('bogus', 'x', 'x');
        } finally {
            Container::setInstance($previous);
        }

        self::assertSame(MatchOutcome::INVALID, $result->outcome);
        self::assertSame('unknown operator \'bogus\'', $result->detail);
    }

    /**
     * Cases for eq and neq, which compare strictly.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: mixed, 3: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 4: string}>
     */
    private static function equalityCases(): iterable
    {
        yield 'eq identical' => ['eq', 'a', 'a', MatchOutcome::MATCHES, ''];
        yield 'eq different' => ['eq', 'a', 'b', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'eq strict int string' => ['eq', 1, '1', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'neq different' => ['neq', 'a', 'b', MatchOutcome::MATCHES, ''];
        yield 'neq identical' => ['neq', 'a', 'a', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'neq strict int string' => ['neq', 1, '1', MatchOutcome::MATCHES, ''];
    }

    /**
     * Cases for in and not_in, which compare members strictly.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: mixed, 3: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 4: string}>
     */
    private static function membershipCases(): iterable
    {
        yield 'in member' => ['in', ['a', 'b'], 'b', MatchOutcome::MATCHES, ''];
        yield 'in non-member' => ['in', ['a', 'b'], 'c', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'in strict' => ['in', ['1'], 1, MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'in without list' => ['in', 'a', 'a', MatchOutcome::INVALID, 'invalid operand for operator \'in\''];
        yield 'not_in non-member' => ['not_in', ['a'], 'c', MatchOutcome::MATCHES, ''];
        yield 'not_in member' => ['not_in', ['a'], 'a', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'not_in strict' => ['not_in', ['1'], 1, MatchOutcome::MATCHES, ''];
        yield 'not_in without list' => ['not_in', 'a', 'x', MatchOutcome::INVALID, 'invalid operand for operator \'not_in\''];
    }

    /**
     * Cases for null and not_null.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: mixed, 3: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 4: string}>
     */
    private static function nullCases(): iterable
    {
        yield 'null on null' => ['null', true, null, MatchOutcome::MATCHES, ''];
        yield 'null on empty string' => ['null', true, '', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'not_null on value' => ['not_null', true, 'x', MatchOutcome::MATCHES, ''];
        yield 'not_null on false' => ['not_null', true, false, MatchOutcome::MATCHES, ''];
        yield 'not_null on null' => ['not_null', true, null, MatchOutcome::DOES_NOT_MATCH, ''];
    }

    /**
     * Cases for cidr with IPv4 ranges, including the prefix boundaries.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: mixed, 3: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 4: string}>
     */
    private static function ipv4CidrCases(): iterable
    {
        yield 'ipv4 /8 inside' => ['cidr', '10.0.0.0/8', '10.1.2.3', MatchOutcome::MATCHES, ''];
        yield 'ipv4 /8 outside' => ['cidr', '10.0.0.0/8', '11.0.0.0', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'ipv4 /8 left-padded bits' => ['cidr', '10.0.0.0/8', '160.0.0.0', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'ipv4 /7 sub-byte inside' => ['cidr', '10.0.0.0/7', '11.0.0.0', MatchOutcome::MATCHES, ''];
        yield 'ipv4 /9 sub-byte inside' => ['cidr', '10.0.0.0/9', '10.127.255.255', MatchOutcome::MATCHES, ''];
        yield 'ipv4 /9 sub-byte outside' => ['cidr', '10.0.0.0/9', '10.128.0.0', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'ipv4 /24 last address' => ['cidr', '192.168.1.0/24', '192.168.1.255', MatchOutcome::MATCHES, ''];
        yield 'ipv4 /24 next block' => ['cidr', '192.168.1.0/24', '192.168.2.0', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'ipv4 /0 low' => ['cidr', '0.0.0.0/0', '8.8.8.8', MatchOutcome::MATCHES, ''];
        yield 'ipv4 /0 high' => ['cidr', '0.0.0.0/0', '255.255.255.255', MatchOutcome::MATCHES, ''];
        yield 'ipv4 /32 same' => ['cidr', '1.2.3.4/32', '1.2.3.4', MatchOutcome::MATCHES, ''];
        yield 'ipv4 /32 neighbour' => ['cidr', '1.2.3.4/32', '1.2.3.5', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'ipv4 exact without prefix' => ['cidr', '10.0.0.1', '10.0.0.1', MatchOutcome::MATCHES, ''];
        yield 'ipv4 exact other address' => ['cidr', '10.0.0.1', '10.0.0.2', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'ipv4 range, ipv6 address' => ['cidr', '0.0.0.0/0', '::1', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'ipv4 value not an address' => ['cidr', '10.0.0.0/8', 'not-an-ip', MatchOutcome::UNDECIDABLE, 'operator \'cidr\' needs an IP address'];
        yield 'ipv4 value empty' => ['cidr', '10.0.0.0/8', '', MatchOutcome::UNDECIDABLE, 'operator \'cidr\' needs an IP address'];
        yield 'ipv4 value not a string' => ['cidr', '10.0.0.0/8', 167772161, MatchOutcome::UNDECIDABLE, 'operator \'cidr\' needs an IP address'];
    }

    /**
     * Cases for cidr with IPv6 ranges, including the prefix boundaries.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: mixed, 3: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 4: string}>
     */
    private static function ipv6CidrCases(): iterable
    {
        yield 'ipv6 /32 inside' => ['cidr', '2001:db8::/32', '2001:db8::1', MatchOutcome::MATCHES, ''];
        yield 'ipv6 /32 outside' => ['cidr', '2001:db8::/32', '2001:db9::1', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'ipv6 /33 sub-group inside' => ['cidr', '2001:db8::/33', '2001:db8:7fff::1', MatchOutcome::MATCHES, ''];
        yield 'ipv6 /33 sub-group outside' => ['cidr', '2001:db8::/33', '2001:db8:8000::', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'ipv6 /0' => ['cidr', '::/0', 'ffff::1', MatchOutcome::MATCHES, ''];
        yield 'ipv6 /128 same' => ['cidr', '::1/128', '::1', MatchOutcome::MATCHES, ''];
        yield 'ipv6 /128 neighbour' => ['cidr', '::1/128', '::2', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'ipv6 exact without prefix' => ['cidr', '2001:db8::1', '2001:db8::1', MatchOutcome::MATCHES, ''];
        yield 'ipv6 exact other address' => ['cidr', '2001:db8::1', '2001:db8::2', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'ipv6 range, ipv4 address' => ['cidr', '::/0', '10.0.0.1', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'ipv6 value not an address' => ['cidr', '::/0', 'zz::1', MatchOutcome::UNDECIDABLE, 'operator \'cidr\' needs an IP address'];
    }

    /**
     * Cases for cidr with a malformed range.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: mixed, 3: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 4: string}>
     */
    private static function invalidCidrCases(): iterable
    {
        $detail = 'invalid operand for operator \'cidr\'';

        yield 'cidr ipv4 prefix 33' => ['cidr', '10.0.0.0/33', '10.0.0.1', MatchOutcome::INVALID, $detail];
        yield 'cidr ipv6 prefix 129' => ['cidr', '::1/129', '::1', MatchOutcome::INVALID, $detail];
        yield 'cidr empty prefix' => ['cidr', '10.0.0.0/', '10.0.0.1', MatchOutcome::INVALID, $detail];
        yield 'cidr non-digit prefix' => ['cidr', '10.0.0.0/abc', '10.0.0.1', MatchOutcome::INVALID, $detail];
        yield 'cidr negative prefix' => ['cidr', '10.0.0.0/-1', '10.0.0.1', MatchOutcome::INVALID, $detail];
        yield 'cidr malformed network' => ['cidr', 'not-an-ip/8', '10.0.0.1', MatchOutcome::INVALID, $detail];
        yield 'cidr malformed address' => ['cidr', 'nonsense', '10.0.0.1', MatchOutcome::INVALID, $detail];
        yield 'cidr non-string operand' => ['cidr', 42, '10.0.0.1', MatchOutcome::INVALID, $detail];
        yield 'cidr invalid before value' => ['cidr', '10.0.0.0/33', 'not-an-ip', MatchOutcome::INVALID, $detail];
        yield 'cidr double prefix' => ['cidr', '10.0.0.0/8/8', '10.0.0.1', MatchOutcome::INVALID, $detail];
    }

    /**
     * Cases for starts_with and ends_with.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: mixed, 3: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 4: string}>
     */
    private static function stringCases(): iterable
    {
        foreach (['starts_with' => ['ab', 'bc'], 'ends_with' => ['bc', 'ab']] as $operator => [$hit, $miss]) {
            yield "{$operator} matches" => [$operator, $hit, 'abc', MatchOutcome::MATCHES, ''];
            yield "{$operator} does not match" => [$operator, $miss, 'abc', MatchOutcome::DOES_NOT_MATCH, ''];
            yield "{$operator} non-string operand" => [$operator, 5, 'abc', MatchOutcome::INVALID, "invalid operand for operator '{$operator}'"];
            yield "{$operator} invalid before value" => [$operator, 5, 5, MatchOutcome::INVALID, "invalid operand for operator '{$operator}'"];
            yield "{$operator} empty operand" => [$operator, '', 'abc', MatchOutcome::UNDECIDABLE, "operator '{$operator}' has an empty operand"];
            yield "{$operator} empty operand first" => [$operator, '', 5, MatchOutcome::UNDECIDABLE, "operator '{$operator}' has an empty operand"];
            yield "{$operator} non-string value" => [$operator, $hit, 5, MatchOutcome::UNDECIDABLE, "operator '{$operator}' needs a string value"];
            yield "{$operator} null value" => [$operator, $hit, null, MatchOutcome::UNDECIDABLE, "operator '{$operator}' needs a string value"];
        }
    }

    /**
     * Cases for string_like, whose operand is a glob for fnmatch() with
     * backslash escapes honoured.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: mixed, 3: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 4: string}>
     */
    private static function stringLikeCases(): iterable
    {
        yield 'string_like star' => ['string_like', 'a*c', 'abbbc', MatchOutcome::MATCHES, ''];
        yield 'string_like question mark' => ['string_like', 'a?c', 'abc', MatchOutcome::MATCHES, ''];
        yield 'string_like miss' => ['string_like', 'a?c', 'abbc', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'string_like escaped star hit' => ['string_like', 'a\*', 'a*', MatchOutcome::MATCHES, ''];
        yield 'string_like escaped star miss' => ['string_like', 'a\*', 'ab', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'string_like non-string' => ['string_like', ['a*'], 'abc', MatchOutcome::INVALID, 'invalid operand for operator \'string_like\''];
        yield 'string_like empty operand' => ['string_like', '', 'abc', MatchOutcome::UNDECIDABLE, 'operator \'string_like\' has an empty operand'];
        yield 'string_like non-string value' => ['string_like', 'a*', 5, MatchOutcome::UNDECIDABLE, 'operator \'string_like\' needs a string value'];
    }

    /**
     * Cases for before and after, across every accepted time form.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: mixed, 3: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 4: string}>
     */
    private static function timeComparisonCases(): iterable
    {
        $instant = new \DateTimeImmutable('@1000');

        yield 'before earlier string' => ['before', '2026-06-01', '2026-01-01', MatchOutcome::MATCHES, ''];
        yield 'before later string' => ['before', '2026-01-01', '2026-06-01', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'before same instant' => ['before', 1000, 1000, MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'before one second earlier' => ['before', 1000, 999, MatchOutcome::MATCHES, ''];
        yield 'before epoch int' => ['before', '1970-01-02 00:00:00 UTC', 0, MatchOutcome::MATCHES, ''];
        yield 'before date-time value' => ['before', 1001, $instant, MatchOutcome::MATCHES, ''];
        yield 'before date-time operand' => ['before', $instant, 1000, MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'before float truncated' => ['before', 1000, 999.9, MatchOutcome::MATCHES, ''];
        yield 'after later string' => ['after', '2026-01-01', '2026-06-01', MatchOutcome::MATCHES, ''];
        yield 'after earlier string' => ['after', '2026-06-01', '2026-01-01', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'after same instant' => ['after', 1000, 1000, MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'after one second later' => ['after', 1000, 1001, MatchOutcome::MATCHES, ''];
        yield 'after float truncated' => ['after', 1000, 1000.9, MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'after float operand' => ['after', 999.9, 1000, MatchOutcome::MATCHES, ''];
        yield 'after date-time value' => ['after', 999, $instant, MatchOutcome::MATCHES, ''];

        foreach (['before', 'after'] as $operator) {
            $invalid     = "invalid operand for operator '{$operator}'";
            $undecidable = "operator '{$operator}' needs a time";

            yield "{$operator} unparseable operand" => [$operator, 'not-a-time', 1000, MatchOutcome::INVALID, $invalid];
            yield "{$operator} empty operand" => [$operator, '', 1000, MatchOutcome::INVALID, $invalid];
            yield "{$operator} null operand" => [$operator, null, 1000, MatchOutcome::INVALID, $invalid];
            yield "{$operator} list operand" => [$operator, [1000], 1000, MatchOutcome::INVALID, $invalid];
            yield "{$operator} invalid before value" => [$operator, 'not-a-time', 'not-a-time', MatchOutcome::INVALID, $invalid];
            yield "{$operator} unparseable value" => [$operator, 1000, 'not-a-time', MatchOutcome::UNDECIDABLE, $undecidable];
            yield "{$operator} empty value" => [$operator, 1000, '', MatchOutcome::UNDECIDABLE, $undecidable];
            yield "{$operator} null value" => [$operator, 1000, null, MatchOutcome::UNDECIDABLE, $undecidable];
            yield "{$operator} bool value" => [$operator, 1000, true, MatchOutcome::UNDECIDABLE, $undecidable];

            foreach (['NaN' => \NAN, 'INF' => \INF, '-INF' => -\INF] as $label => $number) {
                yield "{$operator} {$label} operand" => [$operator, $number, 1000, MatchOutcome::INVALID, $invalid];
                yield "{$operator} {$label} value" => [$operator, 1000, $number, MatchOutcome::UNDECIDABLE, $undecidable];
            }
        }
    }

    /**
     * Cases for between, which is inclusive of both bounds.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: mixed, 3: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 4: string}>
     */
    private static function betweenCases(): iterable
    {
        $june    = ['2026-06-01', '2026-06-30'];
        $invalid = 'invalid operand for operator \'between\'';

        yield 'between inside dates' => ['between', $june, '2026-06-15', MatchOutcome::MATCHES, ''];
        yield 'between lower date' => ['between', $june, '2026-06-01', MatchOutcome::MATCHES, ''];
        yield 'between upper date' => ['between', $june, '2026-06-30', MatchOutcome::MATCHES, ''];
        yield 'between before dates' => ['between', $june, '2026-05-31', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'between after dates' => ['between', $june, '2026-07-01', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'between lower int' => ['between', [100, 200], 100, MatchOutcome::MATCHES, ''];
        yield 'between upper int' => ['between', [100, 200], 200, MatchOutcome::MATCHES, ''];
        yield 'between below int' => ['between', [100, 200], 99, MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'between above int' => ['between', [100, 200], 201, MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'between zero lower bound' => ['between', [0, 10], 0, MatchOutcome::MATCHES, ''];
        yield 'between float value' => ['between', [100, 200], 200.9, MatchOutcome::MATCHES, ''];
        yield 'between float bounds' => ['between', [100.5, 199.5], 199, MatchOutcome::MATCHES, ''];
        yield 'between date-time bounds' => ['between', [new \DateTimeImmutable('@100'), new \DateTimeImmutable('@200')], 150, MatchOutcome::MATCHES, ''];
        yield 'between date-time value' => ['between', [100, 200], new \DateTimeImmutable('@201'), MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'between one bound' => ['between', ['2026-06-01'], '2026-06-15', MatchOutcome::INVALID, $invalid];
        yield 'between missing lower key' => ['between', [1 => 100, 2 => 200], 150, MatchOutcome::INVALID, $invalid];
        yield 'between missing upper key' => ['between', [0 => 100, 2 => 200], 150, MatchOutcome::INVALID, $invalid];
        yield 'between not a list' => ['between', 'not-array', '2026-06-15', MatchOutcome::INVALID, $invalid];
        yield 'between bad lower bound' => ['between', ['bad', '2026-06-30'], '2026-06-15', MatchOutcome::INVALID, $invalid];
        yield 'between bad upper bound' => ['between', ['2026-06-01', 'bad'], '2026-06-15', MatchOutcome::INVALID, $invalid];
        yield 'between invalid before value' => ['between', ['bad', 'bad'], 'not-a-time', MatchOutcome::INVALID, $invalid];
        yield 'between unparseable value' => ['between', $june, 'not-a-time', MatchOutcome::UNDECIDABLE, 'operator \'between\' needs a time'];
        yield 'between null value' => ['between', $june, null, MatchOutcome::UNDECIDABLE, 'operator \'between\' needs a time'];
        yield 'between NaN lower bound' => ['between', [\NAN, 200], 150, MatchOutcome::INVALID, $invalid];
        yield 'between INF upper bound' => ['between', [100, \INF], 150, MatchOutcome::INVALID, $invalid];
        yield 'between INF value' => ['between', [100, 200], \INF, MatchOutcome::UNDECIDABLE, 'operator \'between\' needs a time'];
        yield 'between -INF value' => ['between', [100, 200], -\INF, MatchOutcome::UNDECIDABLE, 'operator \'between\' needs a time'];
    }

    /**
     * Cases for gt, gte, lt and lte at and around the equality boundary.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: mixed, 3: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 4: string}>
     */
    private static function numericComparisonCases(): iterable
    {
        $expectations = [
            'gt'  => [4 => false, 5 => false, 6 => true],
            'gte' => [4 => false, 5 => true, 6 => true],
            'lt'  => [4 => true, 5 => false, 6 => false],
            'lte' => [4 => true, 5 => true, 6 => false],
        ];

        foreach ($expectations as $operator => $byValue) {
            foreach ($byValue as $value => $holds) {
                $outcome = $holds ? MatchOutcome::MATCHES : MatchOutcome::DOES_NOT_MATCH;

                yield "{$operator} {$value} against 5" => [$operator, 5, $value, $outcome, ''];
            }

            yield "{$operator} non-numeric operand" => [$operator, 'abc', 5, MatchOutcome::INVALID, "invalid operand for operator '{$operator}'"];
            yield "{$operator} invalid before value" => [$operator, 'abc', 'abc', MatchOutcome::INVALID, "invalid operand for operator '{$operator}'"];
            yield "{$operator} non-numeric value" => [$operator, 5, 'abc', MatchOutcome::UNDECIDABLE, "operator '{$operator}' needs a number"];
            yield "{$operator} null value" => [$operator, 5, null, MatchOutcome::UNDECIDABLE, "operator '{$operator}' needs a number"];
            yield "{$operator} escaped reference operand" => [$operator, '\${x}', 5, MatchOutcome::INVALID, "invalid operand for operator '{$operator}'"];

            foreach (['NaN' => \NAN, 'INF' => \INF, '-INF' => -\INF, 'overflowing string' => '1e999'] as $label => $number) {
                yield "{$operator} {$label} operand" => [$operator, $number, 5, MatchOutcome::INVALID, "invalid operand for operator '{$operator}'"];
                yield "{$operator} {$label} value" => [$operator, 5, $number, MatchOutcome::UNDECIDABLE, "operator '{$operator}' needs a number"];
            }
        }

        yield 'gt numeric strings compare as numbers' => ['gt', '9', '10', MatchOutcome::MATCHES, ''];
        yield 'gt fractional value below' => ['gt', '10', '9.5', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'gt fractional value above' => ['gt', 10, '10.5', MatchOutcome::MATCHES, ''];
        yield 'gte float operand' => ['gte', 1.5, 1.5, MatchOutcome::MATCHES, ''];
        yield 'lt float operand' => ['lt', 1.5, 1.49, MatchOutcome::MATCHES, ''];
        yield 'lte fractional above' => ['lte', 1, 1.01, MatchOutcome::DOES_NOT_MATCH, ''];
    }

    /**
     * Cases for bool, with every recognised form on both sides.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: mixed, 3: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 4: string}>
     */
    private static function boolCases(): iterable
    {
        $truthy = [true, 1, '1', 'true'];
        $falsy  = [false, 0, '0', 'false'];

        foreach ([...$truthy, ...$falsy] as $operand) {
            foreach ([...$truthy, ...$falsy] as $actual) {
                $same    = \in_array($operand, $truthy, true) === \in_array($actual, $truthy, true);
                $outcome = $same ? MatchOutcome::MATCHES : MatchOutcome::DOES_NOT_MATCH;

                yield 'bool ' . \var_export($operand, true) . ' against ' . \var_export($actual, true) => ['bool', $operand, $actual, $outcome, ''];
            }
        }

        foreach (['yes', 'TRUE', 2, -1, 1.0, null, ''] as $form) {
            yield 'bool operand ' . \var_export($form, true) => ['bool', $form, true, MatchOutcome::INVALID, 'invalid operand for operator \'bool\''];
            yield 'bool value ' . \var_export($form, true) => ['bool', true, $form, MatchOutcome::UNDECIDABLE, 'operator \'bool\' needs a boolean'];
        }

        yield 'bool invalid before value' => ['bool', 'yes', 'no', MatchOutcome::INVALID, 'invalid operand for operator \'bool\''];
        yield 'bool list value' => ['bool', true, [true], MatchOutcome::UNDECIDABLE, 'operator \'bool\' needs a boolean'];
    }

    /**
     * Cases for operators that are not supported.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: mixed, 3: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 4: string}>
     */
    private static function unknownOperatorCases(): iterable
    {
        yield 'unknown operator' => ['bogus', 'x', 'x', MatchOutcome::INVALID, 'unknown operator \'bogus\''];
        yield 'operator case-sensitive' => ['EQ', 'x', 'x', MatchOutcome::INVALID, 'unknown operator \'EQ\''];
        yield 'empty operator' => ['', 'x', 'x', MatchOutcome::INVALID, 'unknown operator \'\''];
    }

    /**
     * Operand cases for unknown operators and the operators whose operand takes
     * any type.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: string|null}>
     */
    private static function untypedOperandCases(): iterable
    {
        yield 'unknown operator' => ['bogus', 'x', 'unknown operator \'bogus\''];
        yield 'unknown upper-case' => ['EQ', 'x', 'unknown operator \'EQ\''];
        yield 'eq any string' => ['eq', 'x', null];
        yield 'eq list' => ['eq', ['x'], null];
        yield 'neq null' => ['neq', null, null];
        yield 'null flag' => ['null', true, null];
        yield 'not_null flag' => ['not_null', false, null];
    }

    /**
     * Operand cases for in and not_in.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: string|null}>
     */
    private static function membershipOperandCases(): iterable
    {
        yield 'in list' => ['in', ['a'], null];
        yield 'in empty list' => ['in', [], null];
        yield 'in string' => ['in', 'a', 'invalid operand for operator \'in\''];
        yield 'in interpolated string' => ['in', '${context.list}', 'invalid operand for operator \'in\''];
        yield 'not_in list' => ['not_in', ['a'], null];
        yield 'not_in string' => ['not_in', 'a', 'invalid operand for operator \'not_in\''];
    }

    /**
     * Operand cases for cidr.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: string|null}>
     */
    private static function cidrOperandCases(): iterable
    {
        $error = 'invalid operand for operator \'cidr\'';

        yield 'cidr ipv4 range' => ['cidr', '10.0.0.0/8', null];
        yield 'cidr ipv4 /0' => ['cidr', '0.0.0.0/0', null];
        yield 'cidr ipv4 /32' => ['cidr', '1.2.3.4/32', null];
        yield 'cidr ipv4 address' => ['cidr', '1.2.3.4', null];
        yield 'cidr ipv6 /128' => ['cidr', '::1/128', null];
        yield 'cidr ipv6 address' => ['cidr', '2001:db8::1', null];
        yield 'cidr interpolated' => ['cidr', '${context.network}', null];
        yield 'cidr interpolated prefix' => ['cidr', '${context.network}/8', null];
        yield 'cidr ipv4 /33' => ['cidr', '10.0.0.0/33', $error];
        yield 'cidr ipv6 /129' => ['cidr', '::1/129', $error];
        yield 'cidr empty prefix' => ['cidr', '10.0.0.0/', $error];
        yield 'cidr non-digit prefix' => ['cidr', '10.0.0.0/x', $error];
        yield 'cidr malformed' => ['cidr', 'bad', $error];
        yield 'cidr non-string' => ['cidr', 42, $error];
        yield 'cidr double prefix' => ['cidr', '10.0.0.0/8/8', $error];
        yield 'cidr escaped reference' => ['cidr', '\${context.network}', $error];
    }

    /**
     * Operand cases for starts_with, ends_with and string_like.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: string|null}>
     */
    private static function stringOperandCases(): iterable
    {
        foreach (['starts_with', 'ends_with', 'string_like'] as $operator) {
            $error = "invalid operand for operator '{$operator}'";

            yield "{$operator} string" => [$operator, 'a', null];
            yield "{$operator} interpolated" => [$operator, '${principal.id}', null];
            yield "{$operator} empty" => [$operator, '', $error];
            yield "{$operator} int" => [$operator, 5, $error];
            yield "{$operator} list" => [$operator, ['a'], $error];
            yield "{$operator} escaped reference" => [$operator, '\${principal.id}', null];
            yield "{$operator} malformed reference" => [$operator, '${principal.tenant-id}', null];
        }
    }

    /**
     * Operand cases for before, after and between.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: string|null}>
     */
    private static function timeOperandCases(): iterable
    {
        foreach (['before', 'after'] as $operator) {
            $error = "invalid operand for operator '{$operator}'";

            yield "{$operator} date string" => [$operator, '2026-01-01', null];
            yield "{$operator} int" => [$operator, 1000, null];
            yield "{$operator} float" => [$operator, 1000.5, null];
            yield "{$operator} date-time" => [$operator, new \DateTimeImmutable('@1000'), null];
            yield "{$operator} interpolated" => [$operator, '${context.deadline}', null];
            yield "{$operator} unparseable" => [$operator, 'not-a-time', $error];
            yield "{$operator} empty" => [$operator, '', $error];
            yield "{$operator} null" => [$operator, null, $error];
            yield "{$operator} list" => [$operator, ['2026-01-01'], $error];
            yield "{$operator} escaped reference" => [$operator, '\${context.deadline}', $error];
            yield "{$operator} NaN" => [$operator, \NAN, $error];
            yield "{$operator} INF" => [$operator, \INF, $error];
            yield "{$operator} -INF" => [$operator, -\INF, $error];
        }

        $error = 'invalid operand for operator \'between\'';

        yield 'between dates' => ['between', ['2026-01-01', '2026-02-01'], null];
        yield 'between ints' => ['between', [100, 200], null];
        yield 'between one bound' => ['between', ['2026-01-01'], $error];
        yield 'between missing lower key' => ['between', [1 => 100, 2 => 200], $error];
        yield 'between missing upper key' => ['between', [0 => 100, 2 => 200], $error];
        yield 'between bad lower bound' => ['between', ['bad', 200], $error];
        yield 'between bad upper bound' => ['between', [100, 'bad'], $error];
        yield 'between string' => ['between', '2026-01-01', $error];
        yield 'between interpolated list' => ['between', ['${context.from}', '${context.to}'], $error];
        yield 'between interpolated string' => ['between', '${context.window}', 'invalid operand for operator \'between\''];
        yield 'between NaN lower bound' => ['between', [\NAN, 200], $error];
        yield 'between INF upper bound' => ['between', [100, \INF], $error];
    }

    /**
     * Operand cases for gt, gte, lt and lte.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: string|null}>
     */
    private static function numericOperandCases(): iterable
    {
        foreach (['gt', 'gte', 'lt', 'lte'] as $operator) {
            $error = "invalid operand for operator '{$operator}'";

            yield "{$operator} int" => [$operator, 5, null];
            yield "{$operator} float" => [$operator, 1.5, null];
            yield "{$operator} numeric string" => [$operator, '5.5', null];
            yield "{$operator} interpolated" => [$operator, '${context.limit}', null];
            yield "{$operator} word" => [$operator, 'abc', $error];
            yield "{$operator} bool" => [$operator, true, $error];
            yield "{$operator} null" => [$operator, null, $error];
            yield "{$operator} list" => [$operator, [5], $error];
            yield "{$operator} NaN" => [$operator, \NAN, $error];
            yield "{$operator} INF" => [$operator, \INF, $error];
            yield "{$operator} -INF" => [$operator, -\INF, $error];
            yield "{$operator} overflowing string" => [$operator, '1e999', $error];
            yield "{$operator} escaped reference" => [$operator, '\${context.limit}', $error];
            yield "{$operator} escaped reference beside one" => [$operator, '\${x}${context.limit}', null];
            yield "{$operator} embedded reference" => [$operator, '1${context.digits}', null];
            yield "{$operator} malformed reference" => [$operator, '${context.tenant-id}', $error];
        }
    }

    /**
     * Operand cases for bool.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: string|null}>
     */
    private static function boolOperandCases(): iterable
    {
        foreach ([true, false, 1, 0, '1', '0', 'true', 'false', '${context.flag}'] as $form) {
            yield 'bool ' . \var_export($form, true) => ['bool', $form, null];
        }

        foreach (['yes', 'TRUE', 2, 1.0, null, '', '\${context.flag}'] as $form) {
            yield 'bool ' . \var_export($form, true) => ['bool', $form, 'invalid operand for operator \'bool\''];
        }
    }

    /**
     * Build a logger that appends every line written to it to the given record.
     *
     * @param  \ArrayObject<int, array{0: mixed, 1: string}>  $records
     * @return \Psr\Log\AbstractLogger
     */
    private static function recordingLogger(\ArrayObject $records): AbstractLogger
    {
        return new class ($records) extends AbstractLogger {
            /**
             * Create a new recording logger.
             *
             * @param  \ArrayObject<int, array{0: mixed, 1: string}>  $records
             */
            public function __construct(

                /** The lines written so far. */
                private readonly \ArrayObject $records,
            ) {}

            /**
             * Record a log line.
             *
             * @param  mixed  $level
             * @param  string|\Stringable  $message
             * @param  array<array-key, mixed>  $context
             * @return void
             */
            #[\Override]
            public function log(mixed $level, string|\Stringable $message, array $context = []): void
            {
                $this->records->append([$level, (string) $message]);
            }
        };
    }

    /**
     * Run the callback against a bare container whose `log` binding is the
     * given factory, restoring the previous container afterwards.
     *
     * @template TResult
     *
     * @param  \Closure(): mixed  $log
     * @param  \Closure(): TResult  $callback
     * @return TResult
     */
    private static function withLog(\Closure $log, \Closure $callback): mixed
    {
        $previous  = Container::getInstance();
        $container = new Container;

        $container->bind('log', $log);

        Container::setInstance($container);

        try {
            return $callback();
        } finally {
            Container::setInstance($previous);
        }
    }
}
