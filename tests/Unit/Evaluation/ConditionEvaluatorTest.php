<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\ConditionOperands;
use SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome;
use SineMacula\Laravel\Authorization\Evaluation\IpRanges;

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
#[CoversClass(ConditionOperands::class)]
#[CoversClass(IpRanges::class)]
final class ConditionEvaluatorTest extends TestCase
{
    /** @var string Trace detail for an `ip_in` value that is not an address. */
    private const string IP_IN_NEEDS_ADDRESS = 'operator \'ip_in\' needs an IP address';

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
        yield from self::ipv4RangeCases();
        yield from self::ipv6RangeCases();
        yield from self::ipRangeSetCases();
        yield from self::invalidRangeCases();
        yield from self::stringCases();
        yield from self::likeCases();
        yield from self::timeComparisonCases();
        yield from self::betweenCases();
        yield from self::numericComparisonCases();
        yield from self::boolCases();
        yield from self::valueSetCases();
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
        yield from self::scalarOperandCases();
        yield from self::setOperandCases();
        yield from self::ipOperandCases();
        yield from self::stringOperandCases();
        yield from self::timeOperandCases();
        yield from self::numericOperandCases();
        yield from self::boolOperandCases();
        yield from self::nullOperandCases();
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
     * OPERATORS lists exactly the twenty supported operators, in order, and
     * none of the names they replaced.
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
            'starts_with',
            'ends_with',
            'like',
            'gt',
            'gte',
            'lt',
            'lte',
            'before',
            'after',
            'between',
            'bool',
            'null',
            'ip_in',
            'ip_not_in',
            'any_value_in',
            'all_values_in',
        ], ConditionEvaluator::OPERATORS);
    }

    /**
     * PATTERN_OPERATORS lists only like, and IF_EXISTS is the suffix.
     *
     * @return void
     */
    public function testPatternOperatorsAndSuffix(): void
    {
        self::assertSame(['like'], ConditionEvaluator::PATTERN_OPERATORS);
        self::assertSame('_if_exists', ConditionEvaluator::IF_EXISTS);
    }

    /**
     * Provide operator names with the operator each tests with.
     *
     * @return \Generator<string, array{0: string, 1: string|null}>
     */
    public static function operatorNameProvider(): iterable
    {
        foreach (ConditionEvaluator::OPERATORS as $operator) {
            yield $operator => [$operator, $operator];

            if ($operator === 'null') {
                continue;
            }

            yield "{$operator}_if_exists" => ["{$operator}_if_exists", $operator];
        }

        yield 'null_if_exists' => ['null_if_exists', null];
        yield 'cidr' => ['cidr', null];
        yield 'string_like' => ['string_like', null];
        yield 'not_null' => ['not_null', null];
        yield 'cidr_if_exists' => ['cidr_if_exists', null];
        yield 'suffix alone' => ['_if_exists', null];
        yield 'suffix twice' => ['eq_if_exists_if_exists', null];
        yield 'upper case' => ['EQ', null];
        yield 'upper-case suffix' => ['eq_IF_EXISTS', null];
        yield 'empty' => ['', null];
        yield 'key-first key' => ['tenant', null];
    }

    /**
     * operatorOf() returns the operator a name tests with, stripping the
     * `_if_exists` suffix, and null for an unknown name or `null_if_exists`.
     *
     * @param  string  $name
     * @param  string|null  $expected
     * @return void
     */
    #[DataProvider('operatorNameProvider')]
    public function testOperatorOf(string $name, ?string $expected): void
    {
        self::assertSame($expected, ConditionEvaluator::operatorOf($name));
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
     * The names the operators replaced are unknown, both as operands are
     * checked and as they are evaluated.
     *
     * @return void
     */
    public function testReplacedOperatorNamesAreUnknown(): void
    {
        foreach (['cidr', 'string_like', 'not_null', 'null_if_exists'] as $name) {
            self::assertSame("unknown operator '{$name}'", ConditionEvaluator::operandError($name, 'x'));

            $result = ConditionEvaluator::evaluate($name, 'x', 'x');

            self::assertSame(MatchOutcome::INVALID, $result->outcome);
            self::assertSame("unknown operator '{$name}'", $result->detail);
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
     * Cases for eq and neq, which compare one scalar strictly.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: mixed, 3: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 4: string}>
     */
    private static function equalityCases(): iterable
    {
        yield 'eq identical' => ['eq', 'a', 'a', MatchOutcome::MATCHES, ''];
        yield 'eq different' => ['eq', 'a', 'b', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'eq strict int string' => ['eq', 1, '1', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'eq bool' => ['eq', false, false, MatchOutcome::MATCHES, ''];
        yield 'eq float' => ['eq', 1.5, 1.5, MatchOutcome::MATCHES, ''];
        yield 'eq null value' => ['eq', 'a', null, MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'eq list value' => ['eq', 'a', ['a'], MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'neq different' => ['neq', 'a', 'b', MatchOutcome::MATCHES, ''];
        yield 'neq identical' => ['neq', 'a', 'a', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'neq strict int string' => ['neq', 1, '1', MatchOutcome::MATCHES, ''];
        yield 'neq null value' => ['neq', 'a', null, MatchOutcome::MATCHES, ''];

        foreach (['eq', 'neq'] as $operator) {
            yield "{$operator} list operand" => [$operator, ['a'], 'a', MatchOutcome::INVALID, "invalid operand for operator '{$operator}'"];
            yield "{$operator} null operand" => [$operator, null, null, MatchOutcome::INVALID, "invalid operand for operator '{$operator}'"];
        }
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
        yield 'in null value' => ['in', ['a'], null, MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'not_in non-member' => ['not_in', ['a'], 'c', MatchOutcome::MATCHES, ''];
        yield 'not_in member' => ['not_in', ['a'], 'a', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'not_in strict' => ['not_in', ['1'], 1, MatchOutcome::MATCHES, ''];

        foreach (['in', 'not_in'] as $operator) {
            $invalid = "invalid operand for operator '{$operator}'";

            yield "{$operator} without list" => [$operator, 'a', 'a', MatchOutcome::INVALID, $invalid];
            yield "{$operator} empty list" => [$operator, [], 'a', MatchOutcome::INVALID, $invalid];
            yield "{$operator} null member" => [$operator, ['a', null], 'a', MatchOutcome::INVALID, $invalid];
            yield "{$operator} nested member" => [$operator, [['a']], 'a', MatchOutcome::INVALID, $invalid];
            yield "{$operator} map" => [$operator, ['x' => 'a'], 'a', MatchOutcome::INVALID, $invalid];
        }
    }

    /**
     * Cases for null, whose operand is strictly true or false, against a key
     * the context carries.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: mixed, 3: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 4: string}>
     */
    private static function nullCases(): iterable
    {
        yield 'null true on null' => ['null', true, null, MatchOutcome::MATCHES, ''];
        yield 'null true on value' => ['null', true, 'x', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'null true on empty string' => ['null', true, '', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'null false on value' => ['null', false, 'x', MatchOutcome::MATCHES, ''];
        yield 'null false on false' => ['null', false, false, MatchOutcome::MATCHES, ''];
        yield 'null false on null' => ['null', false, null, MatchOutcome::DOES_NOT_MATCH, ''];

        foreach (['string true' => 'true', 'int' => 1, 'null' => null, 'list' => [true]] as $label => $operand) {
            yield "null {$label} operand" => ['null', $operand, null, MatchOutcome::INVALID, 'invalid operand for operator \'null\''];
        }
    }

    /**
     * Cases for ip_in and ip_not_in with IPv4 ranges, including the prefix
     * boundaries.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: mixed, 3: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 4: string}>
     */
    private static function ipv4RangeCases(): iterable
    {
        $cases = [
            '/8 inside'           => ['10.0.0.0/8', '10.1.2.3', true],
            '/8 outside'          => ['10.0.0.0/8', '11.0.0.0', false],
            '/8 left-padded bits' => ['10.0.0.0/8', '160.0.0.0', false],
            '/7 sub-byte inside'  => ['10.0.0.0/7', '11.0.0.0', true],
            '/9 sub-byte inside'  => ['10.0.0.0/9', '10.127.255.255', true],
            '/9 sub-byte outside' => ['10.0.0.0/9', '10.128.0.0', false],
            '/24 last address'    => ['192.168.1.0/24', '192.168.1.255', true],
            '/24 next block'      => ['192.168.1.0/24', '192.168.2.0', false],
            '/0 low'              => ['0.0.0.0/0', '8.8.8.8', true],
            '/0 high'             => ['0.0.0.0/0', '255.255.255.255', true],
            '/32 same'            => ['1.2.3.4/32', '1.2.3.4', true],
            '/32 neighbour'       => ['1.2.3.4/32', '1.2.3.5', false],
            'exact'               => ['10.0.0.1', '10.0.0.1', true],
            'exact other address' => ['10.0.0.1', '10.0.0.2', false],
            'ipv6 address'        => ['0.0.0.0/0', '::1', false],
        ];

        foreach ($cases as $label => [$range, $address, $isWithin]) {
            yield "ip_in ipv4 {$label}" => ['ip_in', $range, $address, $isWithin ? MatchOutcome::MATCHES : MatchOutcome::DOES_NOT_MATCH, ''];
            yield "ip_not_in ipv4 {$label}" => ['ip_not_in', $range, $address, $isWithin ? MatchOutcome::DOES_NOT_MATCH : MatchOutcome::MATCHES, ''];
        }

        foreach (['ip_in', 'ip_not_in'] as $operator) {
            $undecidable = "operator '{$operator}' needs an IP address";

            yield "{$operator} value not an address" => [$operator, '10.0.0.0/8', 'not-an-ip', MatchOutcome::UNDECIDABLE, $undecidable];
            yield "{$operator} value empty" => [$operator, '10.0.0.0/8', '', MatchOutcome::UNDECIDABLE, $undecidable];
            yield "{$operator} value a range" => [$operator, '10.0.0.0/8', '10.0.0.0/8', MatchOutcome::UNDECIDABLE, $undecidable];
            yield "{$operator} value not a string" => [$operator, '10.0.0.0/8', 167772161, MatchOutcome::UNDECIDABLE, $undecidable];
            yield "{$operator} value null" => [$operator, '10.0.0.0/8', null, MatchOutcome::UNDECIDABLE, $undecidable];
            yield "{$operator} value with a nul byte" => [$operator, '1.2.3.0/24', "1.2.3.4\0", MatchOutcome::UNDECIDABLE, $undecidable];
            yield "{$operator} value with a zone id" => [$operator, 'fe80::/10', 'fe80::1%en0', MatchOutcome::UNDECIDABLE, $undecidable];
            yield "{$operator} value with a leading zero" => [$operator, '10.0.0.0/8', '010.0.0.1', MatchOutcome::UNDECIDABLE, $undecidable];
        }
    }

    /**
     * Cases for ip_in and ip_not_in with IPv6 ranges, including the prefix
     * boundaries.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: mixed, 3: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 4: string}>
     */
    private static function ipv6RangeCases(): iterable
    {
        yield 'ipv6 /32 inside' => ['ip_in', '2001:db8::/32', '2001:db8::1', MatchOutcome::MATCHES, ''];
        yield 'ipv6 /32 outside' => ['ip_in', '2001:db8::/32', '2001:db9::1', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'ipv6 /33 sub-group inside' => ['ip_in', '2001:db8::/33', '2001:db8:7fff::1', MatchOutcome::MATCHES, ''];
        yield 'ipv6 /33 sub-group outside' => ['ip_in', '2001:db8::/33', '2001:db8:8000::', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'ipv6 /0' => ['ip_in', '::/0', 'ffff::1', MatchOutcome::MATCHES, ''];
        yield 'ipv6 /128 same' => ['ip_in', '::1/128', '::1', MatchOutcome::MATCHES, ''];
        yield 'ipv6 /128 neighbour' => ['ip_in', '::1/128', '::2', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'ipv6 exact' => ['ip_in', '2001:db8::1', '2001:db8::1', MatchOutcome::MATCHES, ''];
        yield 'ipv6 range, ipv4 address' => ['ip_in', '::/0', '10.0.0.1', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'ipv6 mapped ipv4 address' => ['ip_in', '10.0.0.0/8', '::ffff:10.0.0.1', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'ipv6 not_in outside' => ['ip_not_in', '2001:db8::/32', '2001:db9::1', MatchOutcome::MATCHES, ''];
        yield 'ipv6 not_in inside' => ['ip_not_in', '2001:db8::/32', '2001:db8::1', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'ipv6 value not an address' => ['ip_in', '::/0', 'zz::1', MatchOutcome::UNDECIDABLE, self::IP_IN_NEEDS_ADDRESS];
    }

    /**
     * Cases for ip_in and ip_not_in with a list of ranges, read as one set.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: mixed, 3: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 4: string}>
     */
    private static function ipRangeSetCases(): iterable
    {
        $ranges = ['10.0.0.0/8', '192.168.0.0/16', '2001:db8::/32'];

        yield 'ip_in set first range' => ['ip_in', $ranges, '10.1.1.1', MatchOutcome::MATCHES, ''];
        yield 'ip_in set later range' => ['ip_in', $ranges, '192.168.4.4', MatchOutcome::MATCHES, ''];
        yield 'ip_in set ipv6 range' => ['ip_in', $ranges, '2001:db8::5', MatchOutcome::MATCHES, ''];
        yield 'ip_in set no range' => ['ip_in', $ranges, '172.16.0.1', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'ip_not_in set no range' => ['ip_not_in', $ranges, '172.16.0.1', MatchOutcome::MATCHES, ''];
        yield 'ip_not_in set later range' => ['ip_not_in', $ranges, '192.168.4.4', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'ip_in set of one' => ['ip_in', ['1.2.3.4'], '1.2.3.4', MatchOutcome::MATCHES, ''];
        yield 'ip_not_in set invalid address' => ['ip_not_in', $ranges, 'not-an-ip', MatchOutcome::UNDECIDABLE, 'operator \'ip_not_in\' needs an IP address'];
    }

    /**
     * Cases for ip_in and ip_not_in with a malformed range or range set.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: mixed, 3: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 4: string}>
     */
    private static function invalidRangeCases(): iterable
    {
        $operands = [
            'ipv4 prefix 33'       => '10.0.0.0/33',
            'ipv6 prefix 129'      => '::1/129',
            'empty prefix'         => '10.0.0.0/',
            'non-digit prefix'     => '10.0.0.0/abc',
            'negative prefix'      => '10.0.0.0/-1',
            'malformed network'    => 'not-an-ip/8',
            'malformed address'    => 'nonsense',
            'non-string operand'   => 42,
            'double prefix'        => '10.0.0.0/8/8',
            'empty list'           => [],
            'list with bad range'  => ['10.0.0.0/8', 'bad'],
            'list with non-string' => ['10.0.0.0/8', 10],
            'list with null'       => ['10.0.0.0/8', null],
            'map'                  => ['a' => '10.0.0.0/8'],
            'zone id'              => 'fe80::%en0/10',
            'leading zero'         => '010.0.0.0/8',
            'nul byte'             => "10.0.0.0\0/8",
        ];

        foreach (['ip_in', 'ip_not_in'] as $operator) {
            foreach ($operands as $label => $operand) {
                yield "{$operator} {$label}" => [$operator, $operand, '10.0.0.1', MatchOutcome::INVALID, "invalid operand for operator '{$operator}'"];
            }

            yield "{$operator} invalid before value" => [$operator, '10.0.0.0/33', 'not-an-ip', MatchOutcome::INVALID, "invalid operand for operator '{$operator}'"];
        }
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
            yield "{$operator} list operand" => [$operator, [$hit], 'abc', MatchOutcome::INVALID, "invalid operand for operator '{$operator}'"];
            yield "{$operator} invalid before value" => [$operator, 5, 5, MatchOutcome::INVALID, "invalid operand for operator '{$operator}'"];
            yield "{$operator} empty operand" => [$operator, '', 'abc', MatchOutcome::UNDECIDABLE, "operator '{$operator}' has an empty operand"];
            yield "{$operator} empty operand first" => [$operator, '', 5, MatchOutcome::UNDECIDABLE, "operator '{$operator}' has an empty operand"];
            yield "{$operator} non-string value" => [$operator, $hit, 5, MatchOutcome::UNDECIDABLE, "operator '{$operator}' needs a string value"];
            yield "{$operator} null value" => [$operator, $hit, null, MatchOutcome::UNDECIDABLE, "operator '{$operator}' needs a string value"];
            yield "{$operator} value with a nul byte" => [$operator, $hit, "ab\0c", MatchOutcome::UNDECIDABLE, "operator '{$operator}' cannot test a NUL byte"];
            yield "{$operator} operand with a nul byte" => [$operator, "a\0", 'abc', MatchOutcome::UNDECIDABLE, "operator '{$operator}' cannot test a NUL byte"];
        }
    }

    /**
     * Cases for like, whose operand is a glob for fnmatch() with backslash
     * escapes honoured.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: mixed, 3: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 4: string}>
     */
    private static function likeCases(): iterable
    {
        yield 'like star' => ['like', 'a*c', 'abbbc', MatchOutcome::MATCHES, ''];
        yield 'like question mark' => ['like', 'a?c', 'abc', MatchOutcome::MATCHES, ''];
        yield 'like miss' => ['like', 'a?c', 'abbc', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'like escaped star hit' => ['like', 'a\*', 'a*', MatchOutcome::MATCHES, ''];
        yield 'like escaped star miss' => ['like', 'a\*', 'ab', MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'like list operand' => ['like', ['a*'], 'abc', MatchOutcome::INVALID, 'invalid operand for operator \'like\''];
        yield 'like empty operand' => ['like', '', 'abc', MatchOutcome::UNDECIDABLE, 'operator \'like\' has an empty operand'];
        yield 'like non-string value' => ['like', 'a*', 5, MatchOutcome::UNDECIDABLE, 'operator \'like\' needs a string value'];
        yield 'like value with a nul byte' => ['like', 'curl*', "curl\0", MatchOutcome::UNDECIDABLE, 'operator \'like\' cannot test a NUL byte'];
        yield 'like operand with a nul byte' => ['like', "curl\0*", 'curl', MatchOutcome::UNDECIDABLE, 'operator \'like\' cannot test a NUL byte'];
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
            yield "{$operator} value with a nul byte" => [$operator, 1000, "2026-01-01\0", MatchOutcome::UNDECIDABLE, $undecidable];
            yield "{$operator} operand with a nul byte" => [$operator, "2026-01-01\0", '2026-01-01', MatchOutcome::INVALID, "invalid operand for operator '{$operator}'"];
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
        $june        = ['2026-06-01', '2026-06-30'];
        $invalid     = 'invalid operand for operator \'between\'';
        $undecidable = 'operator \'between\' needs a time';

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
        yield 'between unparseable value' => ['between', $june, 'not-a-time', MatchOutcome::UNDECIDABLE, $undecidable];
        yield 'between value with a nul byte' => ['between', $june, "2026-06-15\0", MatchOutcome::UNDECIDABLE, $undecidable];
        yield 'between null value' => ['between', $june, null, MatchOutcome::UNDECIDABLE, $undecidable];
        yield 'between NaN lower bound' => ['between', [\NAN, 200], 150, MatchOutcome::INVALID, $invalid];
        yield 'between INF upper bound' => ['between', [100, \INF], 150, MatchOutcome::INVALID, $invalid];
        yield 'between INF value' => ['between', [100, 200], \INF, MatchOutcome::UNDECIDABLE, $undecidable];
        yield 'between -INF value' => ['between', [100, 200], -\INF, MatchOutcome::UNDECIDABLE, $undecidable];
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
            yield "{$operator} list operand" => [$operator, [5], 5, MatchOutcome::INVALID, "invalid operand for operator '{$operator}'"];
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
     * Cases for any_value_in and all_values_in, whose value is a list of
     * scalars.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: mixed, 3: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 4: string}>
     */
    private static function valueSetCases(): iterable
    {
        $set = ['a', 'b', 1];

        yield 'any_value_in one member' => ['any_value_in', $set, ['x', 'b'], MatchOutcome::MATCHES, ''];
        yield 'any_value_in every member' => ['any_value_in', $set, ['a', 'b'], MatchOutcome::MATCHES, ''];
        yield 'any_value_in no member' => ['any_value_in', $set, ['x', 'y'], MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'any_value_in strict' => ['any_value_in', $set, ['1'], MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'any_value_in empty list' => ['any_value_in', $set, [], MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'all_values_in every member' => ['all_values_in', $set, ['a', 1], MatchOutcome::MATCHES, ''];
        yield 'all_values_in repeated member' => ['all_values_in', $set, ['a', 'a'], MatchOutcome::MATCHES, ''];
        yield 'all_values_in one outsider' => ['all_values_in', $set, ['a', 'x'], MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'all_values_in strict' => ['all_values_in', $set, ['a', '1'], MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'all_values_in empty list' => ['all_values_in', $set, [], MatchOutcome::DOES_NOT_MATCH, ''];

        foreach (['any_value_in', 'all_values_in'] as $operator) {
            $invalid     = "invalid operand for operator '{$operator}'";
            $undecidable = "operator '{$operator}' needs a list of values";

            yield "{$operator} scalar value" => [$operator, $set, 'a', MatchOutcome::UNDECIDABLE, $undecidable];
            yield "{$operator} null value" => [$operator, $set, null, MatchOutcome::UNDECIDABLE, $undecidable];
            yield "{$operator} map value" => [$operator, $set, ['k' => 'a'], MatchOutcome::UNDECIDABLE, $undecidable];
            yield "{$operator} nested value" => [$operator, $set, [['a']], MatchOutcome::UNDECIDABLE, $undecidable];
            yield "{$operator} null element" => [$operator, $set, ['a', null], MatchOutcome::UNDECIDABLE, $undecidable];
            yield "{$operator} scalar operand" => [$operator, 'a', ['a'], MatchOutcome::INVALID, $invalid];
            yield "{$operator} empty operand" => [$operator, [], ['a'], MatchOutcome::INVALID, $invalid];
            yield "{$operator} null member" => [$operator, ['a', null], ['a'], MatchOutcome::INVALID, $invalid];
            yield "{$operator} invalid before value" => [$operator, 'a', 'a', MatchOutcome::INVALID, $invalid];
        }
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
        yield 'suffixed name' => ['eq_if_exists', 'x', 'x', MatchOutcome::INVALID, 'unknown operator \'eq_if_exists\''];
    }

    /**
     * Operand cases for unknown operators, eq and neq.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: string|null}>
     */
    private static function scalarOperandCases(): iterable
    {
        yield 'unknown operator' => ['bogus', 'x', 'unknown operator \'bogus\''];
        yield 'unknown upper-case' => ['EQ', 'x', 'unknown operator \'EQ\''];
        yield 'suffixed name' => ['eq_if_exists', 'x', 'unknown operator \'eq_if_exists\''];

        foreach (['eq', 'neq'] as $operator) {
            $error = "invalid operand for operator '{$operator}'";

            yield "{$operator} string" => [$operator, 'x', null];
            yield "{$operator} int" => [$operator, 1, null];
            yield "{$operator} float" => [$operator, 1.5, null];
            yield "{$operator} bool" => [$operator, false, null];
            yield "{$operator} interpolated" => [$operator, '${input.tenant}', null];
            yield "{$operator} list" => [$operator, ['x'], $error];
            yield "{$operator} null" => [$operator, null, $error];
            yield "{$operator} object" => [$operator, new \stdClass, $error];
        }
    }

    /**
     * Operand cases for in, not_in, any_value_in and all_values_in.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: string|null}>
     */
    private static function setOperandCases(): iterable
    {
        foreach (['in', 'not_in', 'any_value_in', 'all_values_in'] as $operator) {
            $error = "invalid operand for operator '{$operator}'";

            yield "{$operator} list" => [$operator, ['a', 1, 1.5, true], null];
            yield "{$operator} empty list" => [$operator, [], $error];
            yield "{$operator} string" => [$operator, 'a', $error];
            yield "{$operator} interpolated string" => [$operator, '${input.list}', $error];
            yield "{$operator} null member" => [$operator, ['a', null], $error];
            yield "{$operator} nested member" => [$operator, ['a', ['b']], $error];
            yield "{$operator} map" => [$operator, ['x' => 'a'], $error];
        }
    }

    /**
     * Operand cases for ip_in and ip_not_in.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: string|null}>
     */
    private static function ipOperandCases(): iterable
    {
        foreach (['ip_in', 'ip_not_in'] as $operator) {
            $error = "invalid operand for operator '{$operator}'";

            yield "{$operator} ipv4 range" => [$operator, '10.0.0.0/8', null];
            yield "{$operator} ipv4 /0" => [$operator, '0.0.0.0/0', null];
            yield "{$operator} ipv4 address" => [$operator, '1.2.3.4', null];
            yield "{$operator} ipv6 /128" => [$operator, '::1/128', null];
            yield "{$operator} ipv6 address" => [$operator, '2001:db8::1', null];
            yield "{$operator} range set" => [$operator, ['10.0.0.0/8', '2001:db8::/32'], null];
            yield "{$operator} interpolated" => [$operator, '${input.network}', null];
            yield "{$operator} interpolated prefix" => [$operator, '${input.network}/8', null];
            yield "{$operator} ipv4 /33" => [$operator, '10.0.0.0/33', $error];
            yield "{$operator} ipv6 /129" => [$operator, '::1/129', $error];
            yield "{$operator} empty prefix" => [$operator, '10.0.0.0/', $error];
            yield "{$operator} non-digit prefix" => [$operator, '10.0.0.0/x', $error];
            yield "{$operator} malformed" => [$operator, 'bad', $error];
            yield "{$operator} non-string" => [$operator, 42, $error];
            yield "{$operator} double prefix" => [$operator, '10.0.0.0/8/8', $error];
            yield "{$operator} escaped reference" => [$operator, '\${input.network}', $error];
            yield "{$operator} empty set" => [$operator, [], $error];
            yield "{$operator} set with a bad range" => [$operator, ['10.0.0.0/8', 'bad'], $error];
            yield "{$operator} set with an interpolated range" => [$operator, ['${input.network}'], $error];
            yield "{$operator} zone id" => [$operator, 'fe80::1%en0', $error];
            yield "{$operator} leading-zero address" => [$operator, '010.0.0.1', $error];
            yield "{$operator} leading-zero range" => [$operator, '010.0.0.0/8', $error];
            yield "{$operator} nul byte" => [$operator, "10.0.0.0\0/8", $error];
            yield "{$operator} interpolated with a nul byte" => [$operator, "\${input.network}\0", $error];
        }
    }

    /**
     * Operand cases for starts_with, ends_with and like.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: string|null}>
     */
    private static function stringOperandCases(): iterable
    {
        foreach (['starts_with', 'ends_with', 'like'] as $operator) {
            $error = "invalid operand for operator '{$operator}'";

            yield "{$operator} string" => [$operator, 'a', null];
            yield "{$operator} interpolated" => [$operator, '${subject.id}', null];
            yield "{$operator} empty" => [$operator, '', $error];
            yield "{$operator} int" => [$operator, 5, $error];
            yield "{$operator} list" => [$operator, ['a'], $error];
            yield "{$operator} escaped reference" => [$operator, '\${subject.id}', null];
            yield "{$operator} malformed reference" => [$operator, '${subject.tenant-id}', null];
            yield "{$operator} nul byte" => [$operator, "a\0b", $error];
            yield "{$operator} interpolated with a nul byte" => [$operator, "\${subject.id}\0", $error];
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
            yield "{$operator} interpolated" => [$operator, '${input.deadline}', null];
            yield "{$operator} unparseable" => [$operator, 'not-a-time', $error];
            yield "{$operator} empty" => [$operator, '', $error];
            yield "{$operator} null" => [$operator, null, $error];
            yield "{$operator} list" => [$operator, ['2026-01-01'], $error];
            yield "{$operator} escaped reference" => [$operator, '\${input.deadline}', $error];
            yield "{$operator} NaN" => [$operator, \NAN, $error];
            yield "{$operator} INF" => [$operator, \INF, $error];
            yield "{$operator} -INF" => [$operator, -\INF, $error];
            yield "{$operator} nul byte" => [$operator, "2026-01-01\0", $error];
            yield "{$operator} interpolated with a nul byte" => [$operator, "\${input.deadline}\0", $error];
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
        yield 'between interpolated list' => ['between', ['${input.from}', '${input.to}'], $error];
        yield 'between interpolated string' => ['between', '${input.window}', $error];
        yield 'between NaN lower bound' => ['between', [\NAN, 200], $error];
        yield 'between INF upper bound' => ['between', [100, \INF], $error];
        yield 'between nul byte in a bound' => ['between', ['2026-01-01', "2026-02-01\0"], $error];
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
            yield "{$operator} interpolated" => [$operator, '${input.limit}', null];
            yield "{$operator} word" => [$operator, 'abc', $error];
            yield "{$operator} bool" => [$operator, true, $error];
            yield "{$operator} null" => [$operator, null, $error];
            yield "{$operator} list" => [$operator, [5], $error];
            yield "{$operator} NaN" => [$operator, \NAN, $error];
            yield "{$operator} INF" => [$operator, \INF, $error];
            yield "{$operator} -INF" => [$operator, -\INF, $error];
            yield "{$operator} overflowing string" => [$operator, '1e999', $error];
            yield "{$operator} escaped reference" => [$operator, '\${input.limit}', $error];
            yield "{$operator} escaped reference beside one" => [$operator, '\${x}${input.limit}', null];
            yield "{$operator} embedded reference" => [$operator, '1${input.digits}', null];
            yield "{$operator} malformed reference" => [$operator, '${input.tenant-id}', $error];
        }
    }

    /**
     * Operand cases for bool.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: string|null}>
     */
    private static function boolOperandCases(): iterable
    {
        foreach ([true, false, 1, 0, '1', '0', 'true', 'false', '${input.flag}'] as $form) {
            yield 'bool ' . \var_export($form, true) => ['bool', $form, null];
        }

        foreach (['yes', 'TRUE', 2, 1.0, null, '', '\${input.flag}'] as $form) {
            yield 'bool ' . \var_export($form, true) => ['bool', $form, 'invalid operand for operator \'bool\''];
        }
    }

    /**
     * Operand cases for null, which takes strictly true or false and is never
     * interpolated.
     *
     * @return \Generator<string, array{0: string, 1: mixed, 2: string|null}>
     */
    private static function nullOperandCases(): iterable
    {
        yield 'null true' => ['null', true, null];
        yield 'null false' => ['null', false, null];

        foreach (['string true' => 'true', 'one' => 1, 'zero' => 0, 'null' => null, 'interpolated' => '${input.flag}', 'list' => [true]] as $label => $operand) {
            yield "null {$label}" => ['null', $operand, 'invalid operand for operator \'null\''];
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
