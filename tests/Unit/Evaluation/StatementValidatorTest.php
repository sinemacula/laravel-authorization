<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\StatementValidator;

/**
 * Unit tests for the statement validator: the parts of a statement document it
 * reads and the malformed statements it refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 * @SuppressWarnings("php:S1448")
 */
#[CoversClass(StatementValidator::class)]
final class StatementValidatorTest extends TestCase
{
    /**
     * KEYS lists exactly the eight keys a statement may carry.
     *
     * @return void
     */
    public function testKeysConstant(): void
    {
        self::assertSame(['sid', 'effect', 'actions', 'not_actions', 'resources', 'not_resources', 'principals', 'conditions'], StatementValidator::KEYS);
    }

    /**
     * assertKnownKeys() accepts every known key, and any subset of them.
     *
     * @return void
     */
    public function testAssertKnownKeysAcceptsKnownKeys(): void
    {
        StatementValidator::assertKnownKeys(\array_fill_keys(StatementValidator::KEYS, 'x'));
        StatementValidator::assertKnownKeys(['effect' => 'allow']);
        StatementValidator::assertKnownKeys([]);

        $this->addToAssertionCount(3);
    }

    /**
     * Provide documents carrying keys a statement does not define.
     *
     * @return iterable<string, array{0: array<array-key, mixed>, 1: string}>
     */
    public static function unknownKeyProvider(): iterable
    {
        yield 'one' => [['effect' => 'allow', 'condition' => []], 'Policy statement has unknown keys: condition.'];
        yield 'several' => [['principal' => '*', 'effect' => 'allow', 'notActions' => []], 'Policy statement has unknown keys: principal, notActions.'];
        yield 'numeric' => [['effect' => 'allow', 0 => 'x'], 'Policy statement has unknown keys: 0.'];
    }

    /**
     * assertKnownKeys() lists every unknown key, in order.
     *
     * @param  array<array-key, mixed>  $data
     * @param  string  $message
     * @return void
     */
    #[DataProvider('unknownKeyProvider')]
    public function testAssertKnownKeysRefusesUnknownKeys(array $data, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        StatementValidator::assertKnownKeys($data);
    }

    /**
     * Provide action and resource pattern lists with the fault in them, or null
     * when they are acceptable.
     *
     * @return iterable<string, array{0: array<int, string>|null, 1: array<int, string>|null, 2: array<int, string>|null, 3: array<int, string>|null, 4: string|null}>
     */
    public static function targetProvider(): iterable
    {
        yield 'actions' => [['a'], null, null, null, null];
        yield 'not_actions' => [null, ['a'], null, null, null];
        yield 'actions and resources' => [['a'], null, ['r'], null, null];
        yield 'not_actions and not_resources' => [null, ['a'], null, ['r'], null];
        yield 'empty actions' => [[], null, null, null, 'Policy statement actions must be a non-empty list of non-empty strings.'];
        yield 'empty not_actions' => [null, [], null, null, 'Policy statement not_actions must be a non-empty list of non-empty strings.'];
        yield 'empty resources' => [['a'], null, [], null, 'Policy statement resources must be a non-empty list of non-empty strings.'];
        yield 'empty not_resources' => [['a'], null, null, [], 'Policy statement not_resources must be a non-empty list of non-empty strings.'];
        yield 'empty action' => [[''], null, null, null, 'Policy statement actions must be a non-empty list of non-empty strings.'];
        yield 'map of not_actions' => [null, [1 => 'a'], null, null, 'Policy statement not_actions must be a non-empty list of non-empty strings.'];
        yield 'neither actions' => [null, null, null, null, 'Policy statement requires actions or not_actions.'];
        yield 'neither actions with resources' => [null, null, ['r'], null, 'Policy statement requires actions or not_actions.'];
        yield 'both actions' => [['a'], ['b'], null, null, 'Policy statement takes actions or not_actions, not both.'];
        yield 'both resources' => [['a'], null, ['r'], ['s'], 'Policy statement takes resources or not_resources, not both.'];
    }

    /**
     * assertTargets() requires exactly one of actions and not_actions, at most
     * one of resources and not_resources, and each one given to be a non-empty
     * list of non-empty strings.
     *
     * @param  array<int, string>|null  $actions
     * @param  array<int, string>|null  $notActions
     * @param  array<int, string>|null  $resources
     * @param  array<int, string>|null  $notResources
     * @param  string|null  $message
     * @return void
     */
    #[DataProvider('targetProvider')]
    public function testAssertTargets(?array $actions, ?array $notActions, ?array $resources, ?array $notResources, ?string $message): void
    {
        if ($message !== null) {
            $this->expectException(\InvalidArgumentException::class);
            $this->expectExceptionMessage($message);
        }

        StatementValidator::assertTargets($actions, $notActions, $resources, $notResources);

        $this->addToAssertionCount(1);
    }

    /**
     * assertValidResource() accepts well-formed patterns and refuses one with a
     * malformed reference, naming it.
     *
     * @return void
     */
    public function testAssertValidResource(): void
    {
        foreach (['*', 'posts:*', 'posts:${subject.id}', 'posts:\${literal}', 'App\Models\Post:*'] as $pattern) {
            StatementValidator::assertValidResource($pattern);
        }

        $this->addToAssertionCount(1);
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy statement resource pattern \'posts:${foo\' has a malformed ${…} reference.');

        StatementValidator::assertValidResource('posts:${foo');
    }

    /**
     * assertValidResource() refuses a pattern holding a NUL byte, without
     * echoing the byte in the message.
     *
     * @return void
     */
    public function testAssertValidResourceRefusesANulByte(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Policy statement resource pattern holds a NUL byte.');

        StatementValidator::assertValidResource("posts:\0*");
    }

    /**
     * effectOf() reads the effect, and refuses a missing, non-string or unknown
     * one.
     *
     * @return void
     */
    public function testEffectOf(): void
    {
        self::assertSame(PolicyEffect::ALLOW, StatementValidator::effectOf(['effect' => 'allow']));
        self::assertSame(PolicyEffect::DENY, StatementValidator::effectOf(['effect' => 'deny']));

        foreach ([[], ['effect' => null], ['effect' => 1]] as $data) {
            self::assertRefused('Policy statement requires a string effect.', static fn () => StatementValidator::effectOf($data));
        }

        self::assertRefused('Invalid policy effect: \'audit\'', static fn () => StatementValidator::effectOf(['effect' => 'audit']));
    }

    /**
     * Provide statement ids with whether they are accepted.
     *
     * @return iterable<string, array{0: mixed, 1: bool}>
     */
    public static function sidProvider(): iterable
    {
        yield 'one letter' => ['a', true];
        yield 'every allowed character' => ['Allow_Read-posts:1.2', true];
        yield 'digits' => ['42', true];
        yield 'sixty-four characters' => [\str_repeat('a', 64), true];
        yield 'empty' => ['', false];
        yield 'sixty-five characters' => [\str_repeat('a', 65), false];
        yield 'space' => ['allow read', false];
        yield 'slash' => ['allow/read', false];
        yield 'asterisk' => ['allow*', false];
        yield 'trailing newline' => ["allow\n", false];
        yield 'non-ascii letter' => ['allöw', false];
        yield 'int' => [42, false];
        yield 'null' => [null, false];
        yield 'list' => [['a'], false];
    }

    /**
     * sidOf() reads a statement id of 1 to 64 letters, digits, `_`, `-`, `:`
     * and `.`, and refuses anything else, null included.
     *
     * @param  mixed  $sid
     * @param  bool  $isAccepted
     * @return void
     */
    #[DataProvider('sidProvider')]
    public function testSidOf(mixed $sid, bool $isAccepted): void
    {
        if (!$isAccepted) {
            $this->expectException(\InvalidArgumentException::class);
            $this->expectExceptionMessage('Policy statement sid must be 1 to 64 letters, digits, \'_\', \'-\', \':\' or \'.\'.');
        }

        self::assertSame($sid, StatementValidator::sidOf(['sid' => $sid]));
    }

    /**
     * sidOf() returns null for a statement without a sid.
     *
     * @return void
     */
    public function testSidOfIsNullWhenAbsent(): void
    {
        self::assertNull(StatementValidator::sidOf(['effect' => 'allow']));
    }

    /**
     * Provide pattern lists that are not a non-empty list of non-empty strings.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function malformedPatternListProvider(): iterable
    {
        yield 'string' => ['posts:read'];
        yield 'null' => [null];
        yield 'empty list' => [[]];
        yield 'empty string' => [['posts:read', '']];
        yield 'int' => [[42]];
        yield 'nested list' => [[['posts:read']]];
        yield 'map' => [['a' => 'posts:read']];
        yield 'list not from zero' => [[1 => 'posts:read']];
    }

    /**
     * patternsOf() refuses a malformed list for every pattern field.
     *
     * @param  mixed  $patterns
     * @return void
     */
    #[DataProvider('malformedPatternListProvider')]
    public function testPatternsOfRefusesMalformedLists(mixed $patterns): void
    {
        foreach (['actions', 'not_actions', 'resources', 'not_resources'] as $field) {
            self::assertRefused(
                "Policy statement {$field} must be a non-empty list of non-empty strings.",
                static fn () => StatementValidator::patternsOf([$field => $patterns], $field),
            );
        }
    }

    /**
     * patternsOf() reads a list as given, and returns null for an absent field.
     *
     * @return void
     */
    public function testPatternsOfReadsListsAndAbsentFields(): void
    {
        $data = ['actions' => ['posts:*', 'users:read'], 'not_resources' => ['post:1']];

        self::assertSame(['posts:*', 'users:read'], StatementValidator::patternsOf($data, 'actions'));
        self::assertSame(['post:1'], StatementValidator::patternsOf($data, 'not_resources'));
        self::assertNull(StatementValidator::patternsOf($data, 'not_actions'));
        self::assertNull(StatementValidator::patternsOf($data, 'resources'));
    }

    /**
     * patternsOf() checks resource patterns for malformed references, in
     * `resources` and `not_resources`, but leaves action patterns alone.
     *
     * @return void
     */
    public function testPatternsOfChecksResourceReferences(): void
    {
        self::assertSame(['posts:${foo'], StatementValidator::patternsOf(['actions' => ['posts:${foo']], 'actions'));
        self::assertSame(['posts:${foo'], StatementValidator::patternsOf(['not_actions' => ['posts:${foo']], 'not_actions'));

        foreach (['resources', 'not_resources'] as $field) {
            self::assertRefused(
                'Policy statement resource pattern \'posts:${foo\' has a malformed ${…} reference.',
                static fn () => StatementValidator::patternsOf([$field => ['posts:*', 'posts:${foo']], $field),
            );
        }
    }

    /**
     * conditionsOf() reads the conditions map, defaults it to empty, and
     * refuses one that is not an array, null included.
     *
     * @return void
     */
    public function testConditionsOf(): void
    {
        self::assertSame(['eq' => ['input.k' => 1]], StatementValidator::conditionsOf(['conditions' => ['eq' => ['input.k' => 1]]]));
        self::assertSame([], StatementValidator::conditionsOf([]));

        foreach (['nope', null, 1] as $conditions) {
            self::assertRefused(
                'Policy statement conditions must map operators to key tests.',
                static fn () => StatementValidator::conditionsOf(['conditions' => $conditions]),
            );
        }
    }

    /**
     * Provide condition maps with the faults that make them unreadable as a
     * whole.
     *
     * @return iterable<string, array{0: array<array-key, mixed>, 1: list<string>}>
     */
    public static function operatorErrorProvider(): iterable
    {
        yield 'well formed' => [['eq' => ['input.tenant' => 'org-1'], 'ip_in_if_exists' => ['input.ip' => '10.0.0.0/8']], []];
        yield 'empty' => [[], []];
        yield 'key-first shape' => [['tenant' => ['eq' => 'org-1']], ['conditions have an unknown operator \'tenant\'']];
        yield 'bare value' => [['tenant' => 'org-1'], ['conditions have an unknown operator \'tenant\'']];
        yield 'cidr' => [['cidr' => ['ip' => '10.0.0.0/8']], ['conditions have an unknown operator \'cidr\'']];
        yield 'string_like' => [['string_like' => ['name' => 'a*']], ['conditions have an unknown operator \'string_like\'']];
        yield 'not_null' => [['not_null' => ['name' => true]], ['conditions have an unknown operator \'not_null\'']];
        yield 'null_if_exists' => [['null_if_exists' => ['name' => true]], ['conditions have an unknown operator \'null_if_exists\'']];
        yield 'authentication_requirement' => [['authentication_requirement' => ['authentication' => ['multifactor' => []]]], []];
        yield 'authentication_requirement_if_exists' => [
            ['authentication_requirement_if_exists' => ['authentication' => ['multifactor' => []]]],
            ['condition operator \'authentication_requirement_if_exists\' is not an operator; an authentication requirement has no _if_exists form'],
        ];
        yield 'authentication_requirement without tests' => [
            ['authentication_requirement' => []],
            ['condition operator \'authentication_requirement\' must map context keys to operands'],
        ];
        yield 'list of conditions' => [[['eq' => ['input.k' => 1]]], ['conditions must map operator names to key tests']];
        yield 'operator without tests' => [['eq' => []], ['condition operator \'eq\' must map context keys to operands']];
        yield 'operator with a value' => [['eq' => 'org-1'], ['condition operator \'eq\' must map context keys to operands']];
        yield 'operator with a list' => [['in' => ['a', 'b']], ['condition operator \'in\' must map context keys to operands']];
        yield 'operator with a numeric key' => [['eq' => ['input.tenant' => 'a', 0 => 'b']], ['condition operator \'eq\' must map context keys to operands']];
        yield 'several faults in order' => [
            ['bogus' => ['k' => 1], 'eq' => ['input.k' => 1], 'gt' => 5],
            ['conditions have an unknown operator \'bogus\'', 'condition operator \'gt\' must map context keys to operands'],
        ];
    }

    /**
     * operatorErrors() lists every operator entry that is not a known operator
     * mapping context keys to operands, in order.
     *
     * @param  array<array-key, mixed>  $conditions
     * @param  list<string>  $expected
     * @return void
     */
    #[DataProvider('operatorErrorProvider')]
    public function testOperatorErrors(array $conditions, array $expected): void
    {
        self::assertSame($expected, StatementValidator::operatorErrors($conditions));
    }

    /**
     * conditionTests() lists every key test of the well-formed operator entries
     * in order, with its key split into the segments of its dot path, the
     * operator it tests with and whether a missing key passes it, and leaves
     * out the malformed entries.
     *
     * @return void
     */
    public function testConditionTestsListsEveryKeyTest(): void
    {
        $tests = StatementValidator::conditionTests([
            'eq'              => ['input.tenant' => 'org-1', 'input.post.role' => 'admin'],
            'bogus'           => ['input.tenant' => 'x'],
            'ip_in_if_exists' => ['request.ip' => '10.0.0.0/8'],
            'gt'              => 5,
            'null'            => ['input.deleted_at' => true],
            0                 => ['eq' => ['input.k' => 1]],
        ]);

        self::assertSame([
            ['key' => 'input.tenant', 'path' => ['input', 'tenant'], 'operator' => 'eq', 'isOptional' => false, 'operand' => 'org-1', 'error' => null],
            ['key' => 'input.post.role', 'path' => ['input', 'post', 'role'], 'operator' => 'eq', 'isOptional' => false, 'operand' => 'admin', 'error' => null],
            ['key' => 'request.ip', 'path' => ['request', 'ip'], 'operator' => 'ip_in', 'isOptional' => true, 'operand' => '10.0.0.0/8', 'error' => null],
            ['key' => 'input.deleted_at', 'path' => ['input', 'deleted_at'], 'operator' => 'null', 'isOptional' => false, 'operand' => true, 'error' => null],
        ], $tests);
    }

    /**
     * conditionTests() carries a well-formed requirement's operand built, as
     * one test of the key `authentication` that a missing key never passes, and
     * leaves a malformed one's operand as written.
     *
     * @return void
     */
    public function testConditionTestsBuildTheRequirement(): void
    {
        $tests = StatementValidator::conditionTests([
            'authentication_requirement' => ['authentication' => ['multifactor' => ['max_age' => 900], 'phishing_resistant' => []]],
        ]);

        self::assertCount(1, $tests);
        self::assertSame('authentication', $tests[0]['key']);
        self::assertSame(['authentication'], $tests[0]['path']);
        self::assertSame('authentication_requirement', $tests[0]['operator']);
        self::assertFalse($tests[0]['isOptional']);
        self::assertNull($tests[0]['error']);
        self::assertEquals(new AuthenticationRequirement(['multifactor' => 900, 'phishing_resistant' => null]), $tests[0]['operand']);

        $malformed = StatementValidator::conditionTests(['authentication_requirement' => ['authentication' => ['mfa' => []]]]);

        self::assertSame(['mfa' => []], $malformed[0]['operand']);
    }

    /**
     * Provide key tests with the fault each carries, or null when it is well
     * formed.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string|null}>
     */
    public static function keyTestErrorProvider(): iterable
    {
        yield 'valid operand' => [['eq' => ['input.k' => 'x']], null];
        yield 'valid interpolated operand' => [['eq' => ['input.k' => '${input.k}']], null];
        yield 'valid suffixed operand' => [['eq_if_exists' => ['input.k' => 'x']], null];
        yield 'list operand for eq' => [['eq' => ['input.k' => ['x']]], 'condition \'input.k\' has an invalid operand for operator \'eq\''];
        yield 'list operand for suffixed eq' => [['eq_if_exists' => ['input.k' => ['x']]], 'condition \'input.k\' has an invalid operand for operator \'eq\''];
        yield 'string operand for in' => [['in' => ['input.k' => 'x']], 'condition \'input.k\' has an invalid operand for operator \'in\''];
        yield 'empty set for any_value_in' => [['any_value_in' => ['input.k' => []]], 'condition \'input.k\' has an invalid operand for operator \'any_value_in\''];
        yield 'string operand for null' => [['null' => ['input.k' => 'true']], 'condition \'input.k\' has an invalid operand for operator \'null\''];
        yield 'empty set for ip_in' => [['ip_in' => ['input.k' => []]], 'condition \'input.k\' has an invalid operand for operator \'ip_in\''];
        yield 'malformed reference' => [['eq' => ['input.k' => '${foo']], 'condition \'input.k\' has a malformed ${…} reference'];
        yield 'malformed reference in a pattern' => [['like' => ['input.k' => 'a-${input.tenant-id}*']], 'condition \'input.k\' has a malformed ${…} reference'];
        yield 'malformed reference in a number' => [['gt' => ['input.k' => '${input.tenant-id}']], 'condition \'input.k\' has an invalid operand for operator \'gt\''];
        yield 'requirement' => [['authentication_requirement' => ['authentication' => ['multifactor' => ['max_age' => 900]]]], null];
        yield 'requirement on another key' => [
            ['authentication_requirement' => ['request.ip' => ['multifactor' => []]]],
            'condition operator \'authentication_requirement\' tests the key \'authentication\' alone, not \'request.ip\'',
        ];
        yield 'requirement on a key under authentication' => [
            ['authentication_requirement' => ['authentication.amr' => ['multifactor' => []]]],
            'condition operator \'authentication_requirement\' tests the key \'authentication\' alone, not \'authentication.amr\'',
        ];
        yield 'requirement with an unknown part' => [
            ['authentication_requirement' => ['authentication' => ['mfa' => []]]],
            'authentication requirement names an unknown part \'mfa\'',
        ];
        yield 'requirement with no parts' => [
            ['authentication_requirement' => ['authentication' => []]],
            'authentication requirement must map one or more parts (additional_verification, multifactor, phishing_resistant, assurance_level) to their options',
        ];
        yield 'requirement with a bad max age' => [
            ['authentication_requirement' => ['authentication' => ['multifactor' => ['max_age' => 0]]]],
            'authentication requirement part \'multifactor\' max_age must be a whole number of seconds, at least 1',
        ];
        yield 'requirement with a level and no min' => [
            ['authentication_requirement' => ['authentication' => ['assurance_level' => []]]],
            'authentication requirement part \'assurance_level\' requires min, a string that is not empty or blank',
        ];
    }

    /**
     * conditionTests() records why a key test cannot be evaluated: a literal
     * operand of the wrong type, then a malformed reference.
     *
     * @param  array<string, mixed>  $conditions
     * @param  string|null  $expected
     * @return void
     */
    #[DataProvider('keyTestErrorProvider')]
    public function testConditionTestsRecordEachFault(array $conditions, ?string $expected): void
    {
        $tests = StatementValidator::conditionTests($conditions);

        self::assertCount(1, $tests);
        self::assertSame($expected, $tests[0]['error']);
    }

    /**
     * Provide principals an allow may name.
     *
     * @return iterable<string, array{list<string>}>
     */
    public static function validPrincipals(): iterable
    {
        yield 'a subject' => [['user:1']];
        yield 'a role' => [['role:9b2c6f0e-1d2a-4c3b-8e4f-5a6b7c8d9e0f']];
        yield 'a class morph type' => [['App\Models\User:42']];
        yield 'an id with a colon' => [['user:a:b']];
        yield 'the longest parts' => [[\str_repeat('t', 191) . ':' . \str_repeat('i', 191)]];
        yield 'several' => [['user:1', 'role:2']];
    }

    /**
     * An allow's principals are taken when they are a non-empty list of
     * selectors, each a subject reference or a role by its key, and none is
     * nothing to check.
     *
     * @param  list<string>  $principals
     * @return void
     */
    #[DataProvider('validPrincipals')]
    public function testAssertPrincipalsAcceptsSelectors(array $principals): void
    {
        StatementValidator::assertPrincipals(PolicyEffect::ALLOW, $principals);
        StatementValidator::assertPrincipals(PolicyEffect::DENY, null);

        self::assertSame(1, \preg_match(StatementValidator::SELECTOR_PATTERN, $principals[0]));
    }

    /**
     * Provide principals that are refused, with the reason.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect, array<int, mixed>, string}>
     */
    public static function invalidPrincipals(): iterable
    {
        $list     = 'Policy statement principals must be a non-empty list of selectors.';
        $selector = static fn (string $selector): string => "Policy statement principal '{$selector}' must be a subject reference <type>:<id> or a role role:<role id>.";

        yield 'on a deny' => [PolicyEffect::DENY, ['user:1'], 'Policy statement principals name whom an allow applies to; a deny takes none, and applies to everyone.'];
        yield 'empty' => [PolicyEffect::ALLOW, [], $list];
        yield 'not a list' => [PolicyEffect::ALLOW, [1 => 'user:1'], $list];
        yield 'an empty selector' => [PolicyEffect::ALLOW, [''], $list];
        yield 'not a string' => [PolicyEffect::ALLOW, [7], $list];
        yield 'no colon' => [PolicyEffect::ALLOW, ['user'], $selector('user')];
        yield 'no type' => [PolicyEffect::ALLOW, [':1'], $selector(':1')];
        yield 'no id' => [PolicyEffect::ALLOW, ['user:'], $selector('user:')];
        yield 'a wildcard id' => [PolicyEffect::ALLOW, ['user:*'], $selector('user:*')];
        yield 'a wildcard type' => [PolicyEffect::ALLOW, ['*:1'], $selector('*:1')];
        yield 'a space' => [PolicyEffect::ALLOW, ['user:1 2'], $selector('user:1 2')];
        yield 'a reference' => [PolicyEffect::ALLOW, ['user:${subject.id}'], $selector('user:${subject.id}')];
        yield 'a NUL byte' => [PolicyEffect::ALLOW, ["user:1\0"], 'Policy statement principal \'user:1'];
        yield 'a type too long' => [PolicyEffect::ALLOW, [\str_repeat('t', 192) . ':1'], 'must be a subject reference'];
        yield 'an id too long' => [PolicyEffect::ALLOW, ['user:' . \str_repeat('i', 192)], 'must be a subject reference'];
        yield 'a valid then an invalid one' => [PolicyEffect::ALLOW, ['user:1', 'role'], $selector('role')];
    }

    /**
     * Principals that are not a non-empty list of selectors, a selector that is
     * not `<type>:<id>` or that holds a space, `*`, `${` or a NUL byte, or
     * principals on a deny, are refused.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect  $effect
     * @param  array<int, mixed>  $principals
     * @param  string  $message
     * @return void
     */
    #[DataProvider('invalidPrincipals')]
    public function testAssertPrincipalsRefusesMalformedPrincipals(PolicyEffect $effect, array $principals, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        StatementValidator::assertPrincipals($effect, $principals); // @phpstan-ignore argument.type
    }

    /**
     * principalsOf() reads no principals as null and a list of selectors as it
     * is, and refuses anything that is not a non-empty list of strings.
     *
     * @return void
     */
    public function testPrincipalsOfReadsTheList(): void
    {
        self::assertNull(StatementValidator::principalsOf(['effect' => 'allow']));
        self::assertSame(['user:1', 'role:2'], StatementValidator::principalsOf(['principals' => ['user:1', 'role:2']]));

        foreach ([null, 'user:1', [], ['user:1' => 'x'], [''], [1]] as $principals) {
            try {
                StatementValidator::principalsOf(['principals' => $principals]);
                self::fail('The principals were not refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('Policy statement principals must be a non-empty list of selectors.', $exception->getMessage());
            }
        }
    }

    /**
     * dependenciesOf() names every reference of the well-formed tests' string
     * operands and of the patterns, each once, in order, and none of a
     * malformed test, a literal operand or an escaped reference.
     *
     * @return void
     */
    public function testDependenciesOf(): void
    {
        $tests = StatementValidator::conditionTests([
            'eq'    => ['input.a' => '${subject.id}-${input.b}', 'input.c' => 'plain', 'input.d' => '\${input.escaped}'],
            'in'    => ['input.e' => ['${input.listed}']],
            'gt'    => ['input.f' => '${subject.id}'],
            'ip_in' => ['request.ip' => ['${input.ranged}']],
        ]);

        self::assertSame(['subject.id', 'input.b', 'resource.owner'], StatementValidator::dependenciesOf($tests, ['posts:*', 'posts:${resource.owner}/${subject.id}']));
        self::assertSame([], StatementValidator::dependenciesOf([], []));
        self::assertSame([], StatementValidator::dependenciesOf(StatementValidator::conditionTests(['eq' => ['input.a' => []]]), []));
        self::assertSame([], StatementValidator::dependenciesOf(StatementValidator::conditionTests(['between' => ['input.f' => '${input.malformed}']]), []));
        self::assertSame(['input.g'], StatementValidator::dependenciesOf([], ['posts:*', 'posts:${input.g}', 'posts:${input.g}']));
    }

    /**
     * Assert that the callback throws an invalid-argument exception with the
     * message.
     *
     * @param  string  $message
     * @param  \Closure(): mixed  $callback
     * @return void
     */
    private static function assertRefused(string $message, \Closure $callback): void
    {
        try {
            $callback();
        } catch (\InvalidArgumentException $exception) {
            self::assertSame($message, $exception->getMessage());

            return;
        }

        self::fail("Expected the refusal: {$message}");
    }
}
