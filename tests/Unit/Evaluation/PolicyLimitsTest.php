<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Evaluation\PolicyLimits;
use Tests\TestCase;

/**
 * Unit tests for `PolicyLimits`, the size limits of a policy document: each one
 * at its boundary and one over, read from the configuration.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PolicyLimits::class)]
final class PolicyLimitsTest extends TestCase
{
    /**
     * The limits default to 65536 bytes, 100 statements, 50 conditions and 512
     * characters, and the configuration names the four keys.
     *
     * @return void
     */
    public function testHasTheDefaultLimits(): void
    {
        $limits = new PolicyLimits;

        self::assertSame([65536, 100, 50, 512], [$limits->documentBytes, $limits->statements, $limits->conditions, $limits->patternLength]);
        self::assertSame(['document_bytes', 'statements', 'conditions', 'pattern_length'], PolicyLimits::KEYS);
    }

    /**
     * The limits are read from `authorization.policies.limits`.
     *
     * @return void
     */
    public function testReadsTheLimitsFromTheConfiguration(): void
    {
        $this->config()->set('authorization.policies.limits', ['document_bytes' => 10, 'statements' => 20, 'conditions' => 30, 'pattern_length' => 40]);

        self::assertEquals(new PolicyLimits(10, 20, 30, 40), PolicyLimits::fromConfig());
    }

    /**
     * The shipped configuration gives the default limits.
     *
     * @return void
     */
    public function testTheShippedConfigurationGivesTheDefaults(): void
    {
        self::assertEquals(new PolicyLimits, PolicyLimits::fromConfig());
    }

    /**
     * A limit that is not set, or is not a whole number of at least one, takes
     * its default, and so does every limit when the limits are not an array.
     *
     * @return void
     */
    public function testALimitNotSetTakesItsDefault(): void
    {
        $this->config()->set('authorization.policies.limits', ['document_bytes' => 0, 'statements' => '5', 'conditions' => 1]);

        self::assertEquals(new PolicyLimits(conditions: 1), PolicyLimits::fromConfig());

        $this->config()->set('authorization.policies.limits', 'none');

        self::assertEquals(new PolicyLimits, PolicyLimits::fromConfig());
    }

    /**
     * A document of exactly as many bytes as allowed is within the limit, and
     * one byte more is over it, measured on its JSON encoding with the default
     * escapes, as it is stored.
     *
     * @return void
     */
    public function testLimitsTheDocumentBytes(): void
    {
        $document = ['name' => 'é/', 'statements' => []];
        $bytes    = \strlen((string) \json_encode($document));

        self::assertSame(35, $bytes);
        self::assertSame([], (new PolicyLimits(documentBytes: $bytes))->violations($document));
        self::assertSame(['Policy document is 35 bytes, more than the 34 allowed.'], (new PolicyLimits(documentBytes: $bytes - 1))->violations($document));
    }

    /**
     * A document of exactly as many statements as allowed is within the limit,
     * and one more is over it.
     *
     * @return void
     */
    public function testLimitsTheStatements(): void
    {
        $document = ['statements' => [['effect' => 'allow'], ['effect' => 'deny']]];

        self::assertSame([], (new PolicyLimits(statements: 2))->violations($document));
        self::assertSame(['Policy document has 2 statements, more than the 1 allowed.'], (new PolicyLimits(statements: 1))->violations($document));
    }

    /**
     * A statement of exactly as many key tests as allowed is within the limit,
     * and one more is over it: each key of each operator counts once.
     *
     * @return void
     */
    public function testLimitsTheConditionsOfEachStatement(): void
    {
        $document = ['statements' => [
            ['conditions' => ['eq' => ['a' => 1, 'b' => 2], 'in' => ['a' => [1, 2, 3]]]],
            ['conditions' => ['eq' => ['a' => 1]]],
        ]];

        self::assertSame([], (new PolicyLimits(conditions: 3))->violations($document));
        self::assertSame(['Policy statement #0 has 3 conditions, more than the 2 allowed.'], (new PolicyLimits(conditions: 2))->violations($document));
    }

    /**
     * An operator entry that does not map keys to operands counts as one test.
     *
     * @return void
     */
    public function testAMalformedOperatorEntryCountsAsOneTest(): void
    {
        $document = ['statements' => [['conditions' => ['eq' => 'x', 'neq' => ['a' => 1]]]]];

        self::assertSame([], (new PolicyLimits(conditions: 2))->violations($document));
        self::assertSame(['Policy statement #0 has 2 conditions, more than the 1 allowed.'], (new PolicyLimits(conditions: 1))->violations($document));
    }

    /**
     * Return a statement holding one string of the given length in each place a
     * pattern or string operand may be.
     *
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function longStrings(): iterable
    {
        foreach (['actions', 'not_actions', 'resources', 'not_resources'] as $key) {
            yield $key => [[$key => ['@@@@']]];
        }

        yield 'a string operand' => [['conditions' => ['eq' => ['a' => '@@@@']]]];
        yield 'a string in a list operand' => [['conditions' => ['in' => ['a' => [1, '@@@@']]]]];
        yield 'a multibyte string operand' => [['conditions' => ['like' => ['a' => 'éééé']]]];
        yield 'a string in a map operand' => [['conditions' => ['in' => ['a' => ['k' => '@@@@']]]]];
        yield 'a map of actions' => [['actions' => ['x' => '@@@@']]];
    }

    /**
     * Any pattern or string operand of exactly as many characters as allowed is
     * within the limit, and one of a character more is over it.
     *
     * @param  array<string, mixed>  $statement
     * @return void
     */
    #[DataProvider('longStrings')]
    public function testLimitsThePatternLength(array $statement): void
    {
        $document = ['statements' => [$statement]];

        self::assertSame([], (new PolicyLimits(patternLength: 4))->violations($document));
        self::assertSame(['Policy statement #0 has 1 patterns or operands longer than the 3 characters allowed.'], (new PolicyLimits(patternLength: 3))->violations($document));
    }

    /**
     * Every pattern and operand over the length is counted, in one reason for
     * its statement; values that are not strings are not measured.
     *
     * @return void
     */
    public function testCountsEveryLongStringOfAStatement(): void
    {
        $document = ['statements' => [
            ['actions' => ['abcd', 'ab'], 'resources' => ['abcd'], 'conditions' => ['gt' => ['a' => 12345], 'eq' => ['b' => 'abcd']]],
            ['actions' => ['ab']],
            ['actions' => ['abcd'], 'conditions' => ['in' => ['a' => [true, 'abcd']]]],
        ]];

        self::assertSame([
            'Policy statement #0 has 3 patterns or operands longer than the 3 characters allowed.',
            'Policy statement #2 has 2 patterns or operands longer than the 3 characters allowed.',
        ], (new PolicyLimits(patternLength: 3))->violations($document));
    }

    /**
     * Every limit a document is over is reported, in order.
     *
     * @return void
     */
    public function testReportsEveryLimitTheDocumentIsOver(): void
    {
        $document = ['statements' => [['actions' => ['abcd'], 'conditions' => ['eq' => ['a' => 1, 'b' => 2]]], ['actions' => ['a']]]];

        self::assertSame([
            'Policy document is 89 bytes, more than the 1 allowed.',
            'Policy document has 2 statements, more than the 1 allowed.',
            'Policy statement #0 has 2 conditions, more than the 1 allowed.',
            'Policy statement #0 has 1 patterns or operands longer than the 1 characters allowed.',
        ], (new PolicyLimits(1, 1, 1, 1))->violations($document));
    }

    /**
     * A document that is not a valid policy is measured as far as it can be:
     * statements that are not a list, a statement that is not an array, and
     * pattern lists and conditions of the wrong type are left alone.
     *
     * @return void
     */
    public function testMeasuresAMalformedDocumentAsFarAsItCan(): void
    {
        $limits = new PolicyLimits(statements: 1, conditions: 1, patternLength: 1);

        self::assertSame([], $limits->violations(['statements' => 'many']));
        self::assertSame([], $limits->violations(['statements' => ['statement']]));
        self::assertSame([], $limits->violations(['statements' => [['actions' => 'long', 'conditions' => 'many']]]));
        self::assertSame([], $limits->violations([]));
    }

    /**
     * Provide documents that cannot be encoded as JSON, with the reason.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function unencodableDocuments(): iterable
    {
        $statement = static fn (mixed $operand): array => ['statements' => [['effect' => 'allow', 'actions' => ['a'], 'conditions' => ['eq' => ['x' => $operand]]]]];

        yield 'nan' => [$statement(\NAN), 'Inf and NaN cannot be JSON encoded'];
        yield 'infinity' => [$statement(\INF), 'Inf and NaN cannot be JSON encoded'];
        yield 'invalid utf-8' => [['name' => "\xff", 'statements' => []], 'Malformed UTF-8 characters, possibly incorrectly encoded'];
    }

    /**
     * A document that cannot be encoded as JSON can be neither measured nor
     * stored, so it is a violation rather than measured as no bytes at all.
     *
     * @param  array<string, mixed>  $document
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('unencodableDocuments')]
    public function testADocumentThatCannotBeEncodedIsAViolation(array $document, string $reason): void
    {
        self::assertSame(["Policy document cannot be encoded as JSON: {$reason}."], (new PolicyLimits)->violations($document));
    }

    /**
     * The fingerprint names every limit, so it changes whenever any of them
     * does.
     *
     * @return void
     */
    public function testTheFingerprintChangesWithEveryLimit(): void
    {
        $fingerprints = [
            (new PolicyLimits)->fingerprint(),
            (new PolicyLimits(documentBytes: 1))->fingerprint(),
            (new PolicyLimits(statements: 1))->fingerprint(),
            (new PolicyLimits(conditions: 1))->fingerprint(),
            (new PolicyLimits(patternLength: 1))->fingerprint(),
        ];

        self::assertSame('65536.100.50.512', $fingerprints[0]);
        self::assertSame($fingerprints, \array_unique($fingerprints));
        self::assertSame((new PolicyLimits)->fingerprint(), PolicyLimits::fromConfig()->fingerprint());
    }

    /**
     * Return the configuration repository.
     *
     * @return \Illuminate\Config\Repository
     */
    private function config(): ConfigRepository
    {
        /** @var \Illuminate\Config\Repository */
        return $this->app?->make(ConfigRepository::class);
    }
}
