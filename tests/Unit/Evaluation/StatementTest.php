<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use Illuminate\Support\Arr;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\ConditionOperands;
use SineMacula\Laravel\Authorization\Evaluation\ConditionResult;
use SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator;
use SineMacula\Laravel\Authorization\Evaluation\Enums\ConditionOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\IpRanges;
use SineMacula\Laravel\Authorization\Evaluation\MatchResult;
use SineMacula\Laravel\Authorization\Evaluation\RequirementCheck;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Evaluation\StatementValidator;
use SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement;
use SineMacula\Laravel\Authorization\Subject;
use Tests\Feature\Stubs\StubRequirementChecker;

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
#[CoversClass(ConditionOperands::class)]
#[CoversClass(IpRanges::class)]
#[CoversClass(ContextInterpolator::class)]
final class StatementTest extends TestCase
{
    /** @var array<string, array<string, mixed>> The conditions of a statement stating the requirement most tests judge. */
    private const array REQUIREMENT = ['authentication_requirement' => ['authentication' => ['multifactor' => ['max_age' => 900], 'phishing_resistant' => []]]];

    /** @var string Trace detail for a statement whose patterns do not cover the check. */
    private const string TARGET_MISMATCH = 'action/resource did not match';

    /** @var string Trace detail for a resource pattern whose reference cannot be resolved. */
    private const string UNRESOLVED_RESOURCE = 'a resource pattern references a value that cannot be resolved';

    /** @var string Why a malformed sid is refused. */
    private const string SID_MESSAGE = 'Policy statement sid must be 1 to 64 letters, digits, \'_\', \'-\', \':\' or \'.\'.';

    // ------------------------------------------------------------------
    // Hydration and serialisation
    // ------------------------------------------------------------------

    /** @var array<string, int> How many times each namespace has been built. */
    private array $builds = [];

    /**
     * Provide documents that round-trip through fromArray() and toArray()
     * exactly, every key they were given and no other.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function roundTripProvider(): iterable
    {
        yield 'actions only' => [['effect' => 'deny', 'actions' => ['posts:delete']]];
        yield 'every positive key' => [[
            'sid'        => 'AllowRead',
            'effect'     => 'allow',
            'actions'    => ['posts:read', 'posts:list'],
            'resources'  => ['post:*'],
            'conditions' => ['eq' => ['input.tenant' => 'org-1'], 'ip_in_if_exists' => ['request.ip' => ['10.0.0.0/8']]],
        ]];
        yield 'negated lists' => [[
            'sid'           => 'deny.others:1',
            'effect'        => 'deny',
            'not_actions'   => ['posts:read'],
            'not_resources' => ['post:1', 'post:2'],
        ]];
        yield 'resources wildcard' => [['effect' => 'allow', 'actions' => ['x'], 'resources' => ['*']]];
    }

    /**
     * A document round-trips exactly, keeping its keys, and the statement
     * exposes each part.
     *
     * @param  array<string, mixed>  $document
     * @return void
     */
    #[DataProvider('roundTripProvider')]
    public function testRoundTripsExactlyTheKeysGiven(array $document): void
    {
        $statement = Statement::fromArray($document);

        self::assertSame($document, $statement->toArray());
        self::assertSame($document['sid'] ?? null, $statement->sid);
        self::assertIsString($document['effect']);
        self::assertSame(PolicyEffect::from($document['effect']), $statement->effect);
        self::assertSame($document['actions'] ?? null, $statement->actions);
        self::assertSame($document['not_actions'] ?? null, $statement->notActions);
        self::assertSame($document['resources'] ?? null, $statement->resources);
        self::assertSame($document['not_resources'] ?? null, $statement->notResources);
        self::assertSame($document['conditions'] ?? [], $statement->conditions);
    }

    /**
     * Absent resources stay absent, never `['*']`, and an empty conditions map
     * is left out of the serialised statement.
     *
     * @return void
     */
    public function testAbsentResourcesStayAbsentAndEmptyConditionsAreOmitted(): void
    {
        $statement = Statement::fromArray(['effect' => 'deny', 'actions' => ['posts:delete'], 'conditions' => []]);

        self::assertNull($statement->resources);
        self::assertNull($statement->notResources);
        self::assertNull($statement->sid);
        self::assertSame([], $statement->conditions);
        self::assertSame(['effect' => 'deny', 'actions' => ['posts:delete']], $statement->toArray());
    }

    /**
     * The constructor defaults to no sid, no resources, no negated lists and no
     * conditions, which names every resource and a check without one.
     *
     * @return void
     */
    public function testConstructorDefaults(): void
    {
        $statement = new Statement(PolicyEffect::ALLOW, ['posts:create']);

        self::assertNull($statement->resources);
        self::assertNull($statement->notActions);
        self::assertNull($statement->notResources);
        self::assertNull($statement->sid);
        self::assertSame([], $statement->conditions);
        self::assertTrue($statement->matches('posts:create', 'any-resource'));
        self::assertTrue($statement->matches('posts:create'));
        self::assertSame(['effect' => 'allow', 'actions' => ['posts:create']], $statement->toArray());
    }

    /**
     * Provide constructor arguments that name both or neither of the action
     * lists, or both resource lists, or give one of them empty.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function constructorTargetProvider(): iterable
    {
        yield 'neither actions' => [[], 'Policy statement requires actions or not_actions.'];
        yield 'both actions' => [['actions' => ['a'], 'notActions' => ['b']], 'Policy statement takes actions or not_actions, not both.'];
        yield 'both resources' => [['actions' => ['a'], 'resources' => ['r'], 'notResources' => ['s']], 'Policy statement takes resources or not_resources, not both.'];
        yield 'empty actions' => [['actions' => []], 'Policy statement actions must be a non-empty list of non-empty strings.'];
        yield 'empty not_actions' => [['notActions' => []], 'Policy statement not_actions must be a non-empty list of non-empty strings.'];
        yield 'empty resources' => [['actions' => ['x'], 'resources' => []], 'Policy statement resources must be a non-empty list of non-empty strings.'];
        yield 'empty not_resources' => [['actions' => ['x'], 'notResources' => []], 'Policy statement not_resources must be a non-empty list of non-empty strings.'];
    }

    /**
     * A directly constructed statement must name exactly one action list and at
     * most one resource list, each a non-empty list of non-empty strings, so a
     * computed `not_actions` or `not_resources` that turns out empty never
     * names every action or resource.
     *
     * @param  array<string, mixed>  $arguments
     * @param  string  $message
     * @return void
     */
    #[DataProvider('constructorTargetProvider')]
    public function testConstructorRefusesConflictingTargets(array $arguments, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        new Statement(PolicyEffect::DENY, ...$arguments); // @phpstan-ignore argument.type
    }

    /**
     * Provide documents fromArray() refuses, with the reason.
     *
     * @return iterable<string, array{0: array<array-key, mixed>, 1: string}>
     */
    public static function refusedDocumentProvider(): iterable
    {
        yield 'missing effect' => [['actions' => ['x']], 'Policy statement requires a string effect.'];
        yield 'non-string effect' => [['effect' => 1, 'actions' => ['x']], 'Policy statement requires a string effect.'];
        yield 'unknown effect' => [['effect' => 'audit', 'actions' => ['x']], 'Invalid policy effect: \'audit\''];
        yield 'no actions' => [['effect' => 'allow'], 'Policy statement requires actions or not_actions.'];
        yield 'both actions' => [['effect' => 'allow', 'actions' => ['x'], 'not_actions' => ['y']], 'Policy statement takes actions or not_actions, not both.'];
        yield 'both resources' => [
            ['effect' => 'allow', 'actions' => ['x'], 'resources' => ['r'], 'not_resources' => ['s']],
            'Policy statement takes resources or not_resources, not both.',
        ];
        yield 'string actions' => [['effect' => 'allow', 'actions' => 'posts:read'], 'Policy statement actions must be a non-empty list of non-empty strings.'];
        yield 'empty actions' => [['effect' => 'allow', 'actions' => []], 'Policy statement actions must be a non-empty list of non-empty strings.'];
        yield 'non-string action' => [['effect' => 'allow', 'actions' => [123]], 'Policy statement actions must be a non-empty list of non-empty strings.'];
        yield 'empty action' => [['effect' => 'allow', 'actions' => ['']], 'Policy statement actions must be a non-empty list of non-empty strings.'];
        yield 'empty not_actions' => [['effect' => 'allow', 'not_actions' => []], 'Policy statement not_actions must be a non-empty list of non-empty strings.'];
        yield 'null resources' => [['effect' => 'allow', 'actions' => ['x'], 'resources' => null], 'Policy statement resources must be a non-empty list of non-empty strings.'];
        yield 'empty resources' => [['effect' => 'allow', 'actions' => ['x'], 'resources' => []], 'Policy statement resources must be a non-empty list of non-empty strings.'];
        yield 'non-string resource' => [
            ['effect' => 'allow', 'actions' => ['x'], 'resources' => [42]],
            'Policy statement resources must be a non-empty list of non-empty strings.',
        ];
        yield 'nul byte in a resource' => [
            ['effect' => 'allow', 'actions' => ['x'], 'resources' => ["post:1\0"]],
            'Policy statement resource pattern holds a NUL byte.',
        ];
        yield 'nul byte in a not_resource' => [
            ['effect' => 'allow', 'actions' => ['x'], 'not_resources' => ["post:\0*"]],
            'Policy statement resource pattern holds a NUL byte.',
        ];
        yield 'map of not_resources' => [
            ['effect' => 'allow', 'actions' => ['x'], 'not_resources' => ['a' => 'post:1']],
            'Policy statement not_resources must be a non-empty list of non-empty strings.',
        ];
        yield 'empty sid' => [['sid' => '', 'effect' => 'allow', 'actions' => ['x']], self::SID_MESSAGE];
        yield 'long sid' => [['sid' => \str_repeat('s', 65), 'effect' => 'allow', 'actions' => ['x']], self::SID_MESSAGE];
        yield 'sid with a space' => [['sid' => 'Allow read', 'effect' => 'allow', 'actions' => ['x']], self::SID_MESSAGE];
        yield 'null sid' => [['sid' => null, 'effect' => 'allow', 'actions' => ['x']], self::SID_MESSAGE];
        yield 'non-array conditions' => [['effect' => 'allow', 'actions' => ['x'], 'conditions' => 'nope'], 'Policy statement conditions must map operators to key tests.'];
        yield 'misspelt conditions' => [['effect' => 'allow', 'actions' => ['x'], 'condition' => []], 'Policy statement has unknown keys: condition.'];
        yield 'several unknown keys' => [['effect' => 'allow', 'actions' => ['x'], 'Sid' => 'a', 'principal' => '*'], 'Policy statement has unknown keys: Sid, principal.'];
    }

    /**
     * fromArray() refuses a malformed statement with the reason.
     *
     * @param  array<array-key, mixed>  $document
     * @param  string  $message
     * @return void
     */
    #[DataProvider('refusedDocumentProvider')]
    public function testRefusesMalformedDocuments(array $document, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        Statement::fromArray($document);
    }

    /**
     * Provide condition maps in the shapes and names the language replaced, or
     * otherwise malformed, with the reason each is refused.
     *
     * @return iterable<string, array{0: array<array-key, mixed>, 1: string}>
     */
    public static function refusedConditionProvider(): iterable
    {
        yield 'key-first' => [['tenant' => ['eq' => 'org-1']], 'conditions have an unknown operator \'tenant\''];
        yield 'bare value' => [['tenant' => 'org-1'], 'conditions have an unknown operator \'tenant\''];
        yield 'cidr' => [['cidr' => ['ip' => '10.0.0.0/8']], 'conditions have an unknown operator \'cidr\''];
        yield 'string_like' => [['string_like' => ['name' => 'admin*']], 'conditions have an unknown operator \'string_like\''];
        yield 'not_null' => [['not_null' => ['name' => true]], 'conditions have an unknown operator \'not_null\''];
        yield 'null_if_exists' => [['null_if_exists' => ['name' => true]], 'conditions have an unknown operator \'null_if_exists\''];
        yield 'list of conditions' => [[['eq' => ['input.k' => 1]]], 'conditions must map operator names to key tests'];
        yield 'operator without tests' => [['eq' => []], 'condition operator \'eq\' must map context keys to operands'];
        yield 'operator with a value' => [['eq' => 'org-1'], 'condition operator \'eq\' must map context keys to operands'];
        yield 'eq list' => [['eq' => ['input.tenant' => ['org-1', 'org-2']]], 'condition \'input.tenant\' has an invalid operand for operator \'eq\''];
        yield 'neq null' => [['neq' => ['input.tenant' => null]], 'condition \'input.tenant\' has an invalid operand for operator \'neq\''];
        yield 'in string' => [['in' => ['input.role' => 'admin']], 'condition \'input.role\' has an invalid operand for operator \'in\''];
        yield 'not_in empty' => [['not_in' => ['input.role' => []]], 'condition \'input.role\' has an invalid operand for operator \'not_in\''];
        yield 'in null member' => [['in' => ['input.role' => ['admin', null]]], 'condition \'input.role\' has an invalid operand for operator \'in\''];
        yield 'starts_with empty' => [['starts_with' => ['input.path' => '']], 'condition \'input.path\' has an invalid operand for operator \'starts_with\''];
        yield 'ends_with list' => [['ends_with' => ['input.path' => ['.json']]], 'condition \'input.path\' has an invalid operand for operator \'ends_with\''];
        yield 'like empty' => [['like' => ['input.name' => '']], 'condition \'input.name\' has an invalid operand for operator \'like\''];
        yield 'like nul byte' => [['like' => ['input.ua' => "curl\0*"]], 'condition \'input.ua\' has an invalid operand for operator \'like\''];
        yield 'starts_with nul byte' => [['starts_with' => ['input.path' => "/a\0"]], 'condition \'input.path\' has an invalid operand for operator \'starts_with\''];
        yield 'ends_with nul byte reference' => [
            ['ends_with' => ['input.path' => "\${input.suffix}\0"]],
            'condition \'input.path\' has an invalid operand for operator \'ends_with\'',
        ];
        yield 'ip_in nul byte' => [['ip_in' => ['input.ip' => "10.0.0.0\0/8"]], 'condition \'input.ip\' has an invalid operand for operator \'ip_in\''];
        yield 'ip_in zone id' => [['ip_in' => ['input.ip' => 'fe80::%en0/10']], 'condition \'input.ip\' has an invalid operand for operator \'ip_in\''];
        yield 'ip_not_in leading zero' => [['ip_not_in' => ['input.ip' => '010.0.0.0/8']], 'condition \'input.ip\' has an invalid operand for operator \'ip_not_in\''];
        yield 'gt word' => [['gt' => ['input.age' => 'abc']], 'condition \'input.age\' has an invalid operand for operator \'gt\''];
        yield 'lte infinite' => [['lte' => ['input.age' => \INF]], 'condition \'input.age\' has an invalid operand for operator \'lte\''];
        yield 'before unparseable' => [['before' => ['input.at' => 'not-a-date']], 'condition \'input.at\' has an invalid operand for operator \'before\''];
        yield 'between one bound' => [['between' => ['input.at' => ['2026-04-10']]], 'condition \'input.at\' has an invalid operand for operator \'between\''];
        yield 'bool yes' => [['bool' => ['input.flag' => 'yes']], 'condition \'input.flag\' has an invalid operand for operator \'bool\''];
        yield 'null string' => [['null' => ['input.deleted_at' => 'true']], 'condition \'input.deleted_at\' has an invalid operand for operator \'null\''];
        yield 'before nul byte' => [['before' => ['input.at' => "2026-04-15\0"]], 'condition \'input.at\' has an invalid operand for operator \'before\''];
        yield 'between nul byte' => [['between' => ['input.at' => ["2026-04-10\0", '2026-04-15']]], 'condition \'input.at\' has an invalid operand for operator \'between\''];
        yield 'ip_in bad range' => [['ip_in' => ['input.ip' => '10.0.0.0/33']], 'condition \'input.ip\' has an invalid operand for operator \'ip_in\''];
        yield 'ip_not_in empty set' => [['ip_not_in' => ['input.ip' => []]], 'condition \'input.ip\' has an invalid operand for operator \'ip_not_in\''];
        yield 'any_value_in nested' => [['any_value_in' => ['input.tags' => [['a']]]], 'condition \'input.tags\' has an invalid operand for operator \'any_value_in\''];
        yield 'all_values_in string' => [['all_values_in' => ['input.tags' => 'a']], 'condition \'input.tags\' has an invalid operand for operator \'all_values_in\''];
        yield 'suffixed operand' => [['eq_if_exists' => ['input.tenant' => ['org-1']]], 'condition \'input.tenant\' has an invalid operand for operator \'eq\''];
        yield 'malformed reference' => [['eq' => ['input.tenant' => '${foo']], 'condition \'input.tenant\' has a malformed ${…} reference'];
        yield 'malformed pattern reference' => [['like' => ['input.name' => 'admin-${input.tenant-id}*']], 'condition \'input.name\' has a malformed ${…} reference'];
        yield 'first fault reported' => [
            ['eq' => ['input.tenant' => ['x']], 'bogus' => ['k' => 1]],
            'conditions have an unknown operator \'bogus\'',
        ];
    }

    /**
     * fromArray() refuses a malformed condition map, every replaced shape and
     * operator name included, reporting an operator-level fault first.
     *
     * @param  array<array-key, mixed>  $conditions
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('refusedConditionProvider')]
    public function testRefusesMalformedConditions(array $conditions, string $reason): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Policy statement {$reason}.");

        Statement::fromArray(['effect' => 'allow', 'actions' => ['x'], 'conditions' => $conditions]);
    }

    /**
     * A malformed `${…}` reference in a resource or not_resources pattern is
     * refused, naming the pattern.
     *
     * @return void
     */
    public function testRefusesMalformedResourceReferences(): void
    {
        foreach (['resources', 'not_resources'] as $field) {
            try {
                Statement::fromArray(['effect' => 'deny', 'actions' => ['x'], $field => ['post:*', 'post:${foo']]);
                self::fail("A malformed reference in {$field} was accepted.");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('Policy statement resource pattern \'post:${foo\' has a malformed ${…} reference.', $exception->getMessage());
            }
        }
    }

    // ------------------------------------------------------------------
    // Actions
    // ------------------------------------------------------------------

    /**
     * Action patterns are globs compared with literal backslashes.
     *
     * @return void
     */
    public function testActionPatterns(): void
    {
        $statement = Statement::fromArray(['effect' => 'allow', 'actions' => ['posts:*', 'App\Models\*']]);

        self::assertTrue($statement->coversAction('posts:create'));
        self::assertTrue($statement->coversAction('App\Models\Post'));
        self::assertFalse($statement->coversAction('AppModelsPost'));
        self::assertFalse($statement->coversAction('users:create'));
        self::assertTrue($statement->matches('posts:delete'));
        self::assertFalse($statement->matches('users:create'));
    }

    /**
     * not_actions names every action matching none of its patterns.
     *
     * @return void
     */
    public function testNotActionsNamesEveryOtherAction(): void
    {
        $statement = Statement::fromArray(['effect' => 'deny', 'not_actions' => ['posts:read', 'users:*']]);

        self::assertFalse($statement->coversAction('posts:read'));
        self::assertFalse($statement->coversAction('users:delete'));
        self::assertTrue($statement->coversAction('posts:delete'));
        self::assertTrue($statement->coversAction('posts:read:all'));
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, self::TARGET_MISMATCH, $statement->assess('users:read'));
        self::assertResult(MatchOutcome::MATCHES, '', $statement->assess('posts:delete'));
    }

    // ------------------------------------------------------------------
    // Resources
    // ------------------------------------------------------------------

    /**
     * Resource patterns are globs, and a statement without resources names
     * every resource.
     *
     * @return void
     */
    public function testResourcePatterns(): void
    {
        $scoped = self::allowOn('arn:posts:*');
        $open   = Statement::fromArray(['effect' => 'allow', 'actions' => ['posts:read']]);

        self::assertTrue($scoped->matches('posts:read', 'arn:posts:1'));
        self::assertFalse($scoped->matches('posts:read', 'arn:users:1'));
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, self::TARGET_MISMATCH, $scoped->assess('posts:read', 'arn:users:1'));
        self::assertTrue($open->matches('posts:read', 'arn:users:1'));
        self::assertTrue($open->matches('posts:read', 'post:*'));
    }

    /**
     * A type alone (`post:*`) is covered only by a pattern that covers every
     * record of the type, while a record of the type is still matched by
     * narrower patterns.
     *
     * @return void
     */
    public function testATypeAloneIsCoveredOnlyByAPatternCoveringEveryRecord(): void
    {
        foreach (['post:*', '*', '*:*', 'post*'] as $pattern) {
            self::assertTrue(self::allowOn($pattern)->matches('posts:read', 'post:*'), $pattern);
        }

        foreach (['post:?', 'post:?*', 'post:[*]', 'post:[!0-9]'] as $pattern) {
            self::assertResult(MatchOutcome::DOES_NOT_MATCH, self::TARGET_MISMATCH, self::allowOn($pattern)->assess('posts:read', 'post:*'));
        }

        self::assertTrue(self::allowOn('post:?*')->matches('posts:read', 'post:42'));
        self::assertTrue(self::allowOn('report?')->matches('posts:read', 'report*'));
    }

    /**
     * A check without a resource is named by a statement without resources or
     * whose resources include `*`, and never by one scoped to resources or
     * using not_resources.
     *
     * @return void
     */
    public function testResourcelessChecks(): void
    {
        $open        = Statement::fromArray(['effect' => 'deny', 'actions' => ['posts:read']]);
        $wildcard    = Statement::fromArray(['effect' => 'deny', 'actions' => ['posts:read'], 'resources' => ['arn:posts:1', '*']]);
        $scoped      = Statement::fromArray(['effect' => 'deny', 'actions' => ['posts:read'], 'resources' => ['arn:posts:*']]);
        $negated     = Statement::fromArray(['effect' => 'deny', 'actions' => ['posts:read'], 'not_resources' => ['arn:posts:1']]);
        $negatedOpen = Statement::fromArray(['effect' => 'deny', 'actions' => ['posts:read'], 'not_resources' => ['*']]);

        self::assertResult(MatchOutcome::MATCHES, '', $open->assess('posts:read'));
        self::assertResult(MatchOutcome::MATCHES, '', $wildcard->assess('posts:read'));
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, self::TARGET_MISMATCH, $scoped->assess('posts:read'));
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, self::TARGET_MISMATCH, $negated->assess('posts:read'));
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, self::TARGET_MISMATCH, $negatedOpen->assess('posts:read'));
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, self::TARGET_MISMATCH, $open->assess('posts:write'));
        self::assertTrue($open->matches('posts:read'));
        self::assertFalse($negated->matches('posts:read'));
    }

    /**
     * not_resources names every resource none of its patterns covers: a record
     * it lists is excluded, any other record is named.
     *
     * @return void
     */
    public function testNotResourcesWithARecord(): void
    {
        $statement = Statement::fromArray(['effect' => 'deny', 'actions' => ['posts:read'], 'not_resources' => ['post:1', 'comment:*']]);

        self::assertResult(MatchOutcome::DOES_NOT_MATCH, self::TARGET_MISMATCH, $statement->assess('posts:read', 'post:1'));
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, self::TARGET_MISMATCH, $statement->assess('posts:read', 'comment:9'));
        self::assertResult(MatchOutcome::MATCHES, '', $statement->assess('posts:read', 'post:2'));
        self::assertResult(MatchOutcome::MATCHES, '', $statement->assess('posts:read', 'user:1'));
        self::assertTrue($statement->matches('posts:read', 'post:2'));
        self::assertFalse($statement->matches('posts:read', 'post:1'));
    }

    /**
     * For not_resources a type alone is excluded only when a pattern covers it
     * by the type-alone rule, so a pattern naming one record, or needing an id
     * character, leaves the type alone named.
     *
     * @return void
     */
    public function testNotResourcesWithATypeAlone(): void
    {
        foreach (['post:*', '*', 'post*'] as $pattern) {
            $statement = Statement::fromArray(['effect' => 'deny', 'actions' => ['posts:read'], 'not_resources' => [$pattern]]);

            self::assertResult(MatchOutcome::DOES_NOT_MATCH, self::TARGET_MISMATCH, $statement->assess('posts:read', 'post:*'));
        }

        foreach (['post:1', 'post:?', 'post:[!0-9]'] as $pattern) {
            $statement = Statement::fromArray(['effect' => 'deny', 'actions' => ['posts:read'], 'not_resources' => [$pattern]]);

            self::assertResult(MatchOutcome::MATCHES, '', $statement->assess('posts:read', 'post:*'));
        }
    }

    /**
     * A not_resources pattern whose reference cannot be resolved makes the
     * target undecidable, unless another pattern definitely excludes the
     * resource.
     *
     * @return void
     */
    public function testNotResourcesWithAnUnresolvedPattern(): void
    {
        $statement = Statement::fromArray(['effect' => 'deny', 'actions' => ['posts:read'], 'not_resources' => ['post:${subject.id}']]);
        $excluding = Statement::fromArray(['effect' => 'deny', 'actions' => ['posts:read'], 'not_resources' => ['post:${subject.id}', 'post:9']]);

        $interpolator = new ContextInterpolator;

        self::assertResult(MatchOutcome::UNDECIDABLE, self::UNRESOLVED_RESOURCE, $statement->assess('posts:read', 'post:2', [], $interpolator));
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, self::TARGET_MISMATCH, $excluding->assess('posts:read', 'post:9', [], $interpolator));
        self::assertResult(MatchOutcome::MATCHES, '', $statement->assess('posts:read', 'post:2', ['subject' => ['id' => '1']], $interpolator));
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, self::TARGET_MISMATCH, $statement->assess('posts:read', 'post:1', ['subject' => ['id' => '1']], $interpolator));
    }

    /**
     * Literal resource patterns keep their backslashes, with or without an
     * interpolator.
     *
     * @return void
     */
    public function testBackslashesInLiteralResourcePatternsStillMatch(): void
    {
        $statement    = self::allowOn('App\Models\Post:*');
        $interpolator = new ContextInterpolator;

        self::assertTrue($statement->matches('posts:read', 'App\Models\Post:42'));
        self::assertTrue($statement->matches('posts:read', 'App\Models\Post:42', $interpolator));
        self::assertFalse($statement->matches('posts:read', 'AppModelsPost:42'));
        self::assertFalse($statement->matches('posts:read', 'App\Models\Comment:42', $interpolator));
    }

    /**
     * Resource patterns interpolate the subject, the resource and the rest of
     * the context, escaping every substituted value.
     *
     * @return void
     */
    public function testInterpolatedResourcePatterns(): void
    {
        $interpolator = new ContextInterpolator;
        $bySubject    = self::allowOn('posts:${subject.id}:*');
        $byContext    = self::allowOn('tenant:${input.tenant_id}:*');
        $byType       = self::allowOn('${resource.type}:*');
        $byName       = self::allowOn('folder:${subject.username}/*');

        self::assertTrue($bySubject->matches('posts:read', 'posts:42:draft', $interpolator, ['subject' => ['id' => '42']]));
        self::assertFalse($bySubject->matches('posts:read', 'posts:99:draft', $interpolator, ['subject' => ['id' => '42']]));
        self::assertTrue($byContext->matches('posts:read', 'tenant:org-5:posts', $interpolator, ['input' => ['tenant_id' => 'org-5']]));
        self::assertFalse($byContext->matches('posts:read', 'tenant:org-9:posts', $interpolator, ['input' => ['tenant_id' => 'org-5']]));
        self::assertTrue($byType->matches('posts:read', 'posts:42', $interpolator, ['resource' => ['type' => 'posts', 'id' => '42']]));
        self::assertFalse($byType->matches('posts:read', 'posts:42', $interpolator));
        self::assertFalse($byName->matches('posts:read', 'folder:alice/report', $interpolator, ['subject' => ['username' => '*']]));
        self::assertTrue($byName->matches('posts:read', 'folder:*/report', $interpolator, ['subject' => ['username' => '*']]));
        self::assertFalse($bySubject->matches('posts:read', 'posts:42:draft'));
        self::assertTrue($bySubject->matches('posts:read', 'posts:${subject.id}:draft'));
    }

    /**
     * A resource pattern whose reference cannot be resolved is undecidable
     * unless another pattern matches; a malformed one on a constructed
     * statement is unresolved too.
     *
     * @return void
     */
    public function testUnresolvedResourcePatterns(): void
    {
        $interpolator = new ContextInterpolator;
        $unresolved   = Statement::fromArray(['effect' => 'deny', 'actions' => ['posts:read'], 'resources' => ['posts:${subject.id}:*', 'arn:users:*']]);
        $fallback     = Statement::fromArray(['effect' => 'deny', 'actions' => ['posts:read'], 'resources' => ['posts:${subject.id}:*', 'posts:*']]);
        $malformed    = new Statement(PolicyEffect::DENY, ['posts:read'], ['posts:${input.tenant-id}']);

        self::assertResult(MatchOutcome::UNDECIDABLE, self::UNRESOLVED_RESOURCE, $unresolved->assess('posts:read', 'posts:42:draft', [], $interpolator));
        self::assertFalse($unresolved->matches('posts:read', 'posts:42:draft', $interpolator));
        self::assertResult(MatchOutcome::MATCHES, '', $fallback->assess('posts:read', 'posts:42:draft', [], $interpolator));
        self::assertResult(MatchOutcome::UNDECIDABLE, self::UNRESOLVED_RESOURCE, $malformed->assess('posts:read', 'posts:1', ['input' => ['tenant-id' => '1']], $interpolator));
        self::assertResult(MatchOutcome::MATCHES, '', $malformed->assess('posts:read', 'posts:${input.tenant-id}'));
    }

    /**
     * A NUL byte never reaches a resource match: a value holding one that is
     * substituted into a resource pattern leaves the pattern unresolved, so the
     * test is undecidable unless another pattern matches, and a literal one on
     * a constructed statement is unresolved too.
     *
     * @return void
     */
    public function testAResourcePatternHoldingANulByteIsUnresolved(): void
    {
        $interpolator = new ContextInterpolator;
        $substituted  = Statement::fromArray(['effect' => 'deny', 'actions' => ['posts:read'], 'resources' => ['posts:${input.tenant}:*']]);
        $fallback     = Statement::fromArray(['effect' => 'deny', 'actions' => ['posts:read'], 'resources' => ['posts:${input.tenant}:*', 'posts:*']]);
        $negated      = Statement::fromArray(['effect' => 'allow', 'actions' => ['posts:read'], 'not_resources' => ['posts:${input.tenant}:*']]);
        $literal      = new Statement(PolicyEffect::DENY, ['posts:read'], ["posts:\0*"]);
        $context      = ['input' => ['tenant' => "org\0"]];

        self::assertResult(MatchOutcome::UNDECIDABLE, self::UNRESOLVED_RESOURCE, $substituted->assess('posts:read', 'posts:org:1', $context, $interpolator));
        self::assertResult(MatchOutcome::MATCHES, '', $fallback->assess('posts:read', 'posts:org:1', $context, $interpolator));
        self::assertResult(MatchOutcome::UNDECIDABLE, self::UNRESOLVED_RESOURCE, $negated->assess('posts:read', 'posts:org:1', $context, $interpolator));
        self::assertResult(MatchOutcome::UNDECIDABLE, self::UNRESOLVED_RESOURCE, $literal->assess('posts:read', 'posts:1'));
        self::assertResult(MatchOutcome::MATCHES, '', $substituted->assess('posts:read', 'posts:org:1', ['input' => ['tenant' => 'org']], $interpolator));
    }

    // ------------------------------------------------------------------
    // Conditions
    // ------------------------------------------------------------------

    /**
     * Provide one test of every operator with a context that makes it hold, not
     * hold, or undecidable.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: mixed, 3: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 4: string}>
     */
    public static function operatorProvider(): iterable
    {
        $cases = [
            'eq'            => ['org-1', 'org-1', 'org-2', ['org-1']],
            'neq'           => ['org-1', 'org-2', 'org-1', null],
            'in'            => [['a', 'b'], 'a', 'c', null],
            'not_in'        => [['a', 'b'], 'c', 'a', null],
            'starts_with'   => ['/admin', '/admin/x', '/docs', 5],
            'ends_with'     => ['.json', 'a.json', 'a.xml', 5],
            'like'          => ['Mozilla/*', 'Mozilla/5.0', 'curl/8', 5],
            'gt'            => [17, 18, 17, 'abc'],
            'gte'           => [18, 18, 17, 'abc'],
            'lt'            => [3, 2, 3, 'abc'],
            'lte'           => [3, 3, 4, 'abc'],
            'before'        => ['2099-01-01', '2026-01-01', '2100-01-01', 'garbage'],
            'after'         => ['2000-01-01', '2026-01-01', '1999-01-01', 'garbage'],
            'between'       => [['2000-01-01', '2099-01-01'], '2026-01-01', '2100-01-01', 'garbage'],
            'bool'          => [true, 'true', false, 'yes'],
            'null'          => [true, null, 'x', null],
            'ip_in'         => [['10.0.0.0/8', '2001:db8::/32'], '10.0.0.42', '11.0.0.1', 'not-an-ip'],
            'ip_not_in'     => ['10.0.0.0/8', '11.0.0.1', '10.0.0.42', 'not-an-ip'],
            'any_value_in'  => [['a', 'b'], ['x', 'a'], ['x'], 'a'],
            'all_values_in' => [['a', 'b'], ['a', 'b'], [], 'a'],
        ];

        $details = [
            'starts_with'   => 'needs a string value',
            'ends_with'     => 'needs a string value',
            'like'          => 'needs a string value',
            'gt'            => 'needs a number',
            'gte'           => 'needs a number',
            'lt'            => 'needs a number',
            'lte'           => 'needs a number',
            'before'        => 'needs a time',
            'after'         => 'needs a time',
            'between'       => 'needs a time',
            'bool'          => 'needs a boolean',
            'ip_in'         => 'needs an IP address',
            'ip_not_in'     => 'needs an IP address',
            'any_value_in'  => 'needs a list of values',
            'all_values_in' => 'needs a list of values',
        ];

        foreach ($cases as $operator => [$operand, $holding, $failing, $undecidable]) {
            yield "{$operator} holds" => [$operator, $operand, $holding, MatchOutcome::MATCHES, ''];
            yield "{$operator} does not hold" => [$operator, $operand, $failing, MatchOutcome::DOES_NOT_MATCH, ''];

            if (!isset($details[$operator])) {
                continue;
            }

            yield "{$operator} undecidable" => [$operator, $operand, $undecidable, MatchOutcome::UNDECIDABLE, "condition 'input.k': operator '{$operator}' {$details[$operator]}"];
        }
    }

    /**
     * Every operator holds, does not hold or cannot be decided through a
     * statement, which names the key in the detail.
     *
     * @param  string  $operator
     * @param  mixed  $operand
     * @param  mixed  $actual
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome  $outcome
     * @param  string  $detail
     * @return void
     */
    #[DataProvider('operatorProvider')]
    public function testEveryOperator(string $operator, mixed $operand, mixed $actual, MatchOutcome $outcome, string $detail): void
    {
        $statement = Statement::fromArray(['effect' => 'allow', 'actions' => ['x'], 'conditions' => [$operator => ['input.k' => $operand]]]);
        $result    = $statement->assess('x', null, ['input' => ['k' => $actual]]);

        self::assertResult($outcome, $detail, $result);
        self::assertSame(['input.k' => $outcome === MatchOutcome::MATCHES], $result->conditions);
        self::assertSame($outcome === MatchOutcome::MATCHES, $statement->conditionsSatisfiedBy(['input' => ['k' => $actual]]));
    }

    /**
     * Every test of every operator must hold, and assess() reports each key, in
     * order of first test, with whether all of its tests held.
     *
     * @return void
     */
    public function testEveryTestMustHoldAndEachKeyIsReported(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['posts:read'],
            'conditions' => [
                'eq'    => ['input.tenant' => 'org-1', 'input.level' => 3],
                'in'    => ['input.role' => ['admin', 'staff']],
                'gte'   => ['input.level' => 2],
                'ip_in' => ['input.ip' => '10.0.0.0/8'],
            ],
        ]);

        $context = ['input' => ['tenant' => 'org-1', 'level' => 3, 'role' => 'admin', 'ip' => '10.1.1.1']];
        $matched = $statement->assess('posts:read', null, $context);

        self::assertResult(MatchOutcome::MATCHES, '', $matched);
        self::assertSame(['input.tenant' => true, 'input.level' => true, 'input.role' => true, 'input.ip' => true], $matched->conditions);

        $failed = $statement->assess('posts:read', null, ['input' => ['level' => 2, 'role' => 'guest'] + $context['input']]);

        self::assertSame(MatchOutcome::DOES_NOT_MATCH, $failed->outcome);
        self::assertSame(['input.tenant' => true, 'input.level' => false, 'input.role' => false, 'input.ip' => true], $failed->conditions);

        $missing = $statement->assess('posts:read', null, ['input' => ['tenant' => 'org-1', 'level' => 3, 'role' => 'admin']]);

        self::assertResult(MatchOutcome::UNDECIDABLE, 'key \'input.ip\' is missing from the context', $missing);
        self::assertSame(['input.tenant' => true, 'input.level' => true, 'input.role' => true, 'input.ip' => false], $missing->conditions);
    }

    /**
     * A key tested by several operators holds only when every one of its tests
     * held, whichever fails.
     *
     * @return void
     */
    public function testAKeyTestedTwiceHoldsOnlyWhenBothHold(): void
    {
        $statement = Statement::fromArray(['effect' => 'allow', 'actions' => ['x'], 'conditions' => ['gt' => ['input.n' => 1], 'lt' => ['input.n' => 5]]]);

        self::assertSame(['input.n' => true], $statement->assess('x', null, ['input' => ['n' => 3]])->conditions);
        self::assertSame(['input.n' => false], $statement->assess('x', null, ['input' => ['n' => 0]])->conditions);
        self::assertSame(['input.n' => false], $statement->assess('x', null, ['input' => ['n' => 9]])->conditions);
    }

    /**
     * assess() reports an empty map for a statement without conditions that
     * names the check, and null when it does not name it.
     *
     * @return void
     */
    public function testAssessReportsConditionsOnlyForAStatementNamingTheCheck(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['posts:read'],
            'resources'  => ['posts/1'],
            'conditions' => ['eq' => ['input.tenant' => 'org-1']],
        ]);
        $unconditional = Statement::fromArray(['effect' => 'deny', 'actions' => ['posts:read']]);
        $context       = ['input' => ['tenant' => 'org-1']];

        self::assertSame([], $unconditional->assess('posts:read')->conditions);
        self::assertNull($statement->assess('users:read', 'posts/1', $context)->conditions);
        self::assertNull($statement->assess('posts:read', 'posts/2', $context)->conditions);
        self::assertNull($statement->assess('posts:read', null, $context)->conditions);
        self::assertSame(['input.tenant' => true], $statement->assess('posts:read', 'posts/1', $context)->conditions);
    }

    /**
     * A missing key makes a test undecidable, naming the key, while a key
     * present with a null value is decided by the operator.
     *
     * @return void
     */
    public function testAMissingKeyIsUndecidable(): void
    {
        $statement = Statement::fromArray(['effect' => 'deny', 'actions' => ['x'], 'conditions' => ['eq' => ['input.tenant' => 'org-1']]]);

        self::assertResult(MatchOutcome::UNDECIDABLE, 'key \'input.tenant\' is missing from the context', $statement->assess('x'));
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, '', $statement->assess('x', null, ['input' => ['tenant' => null]]));
        self::assertFalse($statement->conditionsSatisfiedBy([]));
    }

    /**
     * Provide the null operator's outcome for a key absent, null and present.
     *
     * @return iterable<string, array{0: bool, 1: array<string, mixed>, 2: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome}>
     */
    public static function nullProvider(): iterable
    {
        yield 'true, absent' => [true, [], MatchOutcome::MATCHES];
        yield 'true, null' => [true, ['input' => ['k' => null]], MatchOutcome::MATCHES];
        yield 'true, present' => [true, ['input' => ['k' => 'x']], MatchOutcome::DOES_NOT_MATCH];
        yield 'true, false' => [true, ['input' => ['k' => false]], MatchOutcome::DOES_NOT_MATCH];
        yield 'false, absent' => [false, [], MatchOutcome::DOES_NOT_MATCH];
        yield 'false, null' => [false, ['input' => ['k' => null]], MatchOutcome::DOES_NOT_MATCH];
        yield 'false, present' => [false, ['input' => ['k' => 'x']], MatchOutcome::MATCHES];
        yield 'false, empty string' => [false, ['input' => ['k' => '']], MatchOutcome::MATCHES];
    }

    /**
     * `null: true` holds for a key absent or null and `null: false` for one
     * present and not null, so a missing key is decided, never undecidable.
     *
     * @param  bool  $operand
     * @param  array<string, mixed>  $context
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome  $outcome
     * @return void
     */
    #[DataProvider('nullProvider')]
    public function testNullOperator(bool $operand, array $context, MatchOutcome $outcome): void
    {
        $statement = Statement::fromArray(['effect' => 'deny', 'actions' => ['x'], 'conditions' => ['null' => ['input.k' => $operand]]]);
        $result    = $statement->assess('x', null, $context);

        self::assertResult($outcome, '', $result);
        self::assertSame(['input.k' => $outcome === MatchOutcome::MATCHES], $result->conditions);
    }

    /**
     * Provide `_if_exists` tests with a context and the outcome.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>, 2: \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome, 3: string}>
     */
    public static function ifExistsProvider(): iterable
    {
        $ip = ['ip_in_if_exists' => ['input.ip' => '10.0.0.0/8']];
        $eq = ['eq_if_exists' => ['input.tenant' => 'org-1']];

        yield 'absent passes' => [$ip, [], MatchOutcome::MATCHES, ''];
        yield 'present and within' => [$ip, ['input' => ['ip' => '10.1.1.1']], MatchOutcome::MATCHES, ''];
        yield 'present and outside' => [$ip, ['input' => ['ip' => '11.1.1.1']], MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'present null' => [$ip, ['input' => ['ip' => null]], MatchOutcome::UNDECIDABLE, 'condition \'input.ip\': operator \'ip_in\' needs an IP address'];
        yield 'present wrong type' => [$ip, ['input' => ['ip' => 42]], MatchOutcome::UNDECIDABLE, 'condition \'input.ip\': operator \'ip_in\' needs an IP address'];
        yield 'eq absent' => [$eq, [], MatchOutcome::MATCHES, ''];
        yield 'eq present null' => [$eq, ['input' => ['tenant' => null]], MatchOutcome::DOES_NOT_MATCH, ''];
        yield 'eq present' => [$eq, ['input' => ['tenant' => 'org-1']], MatchOutcome::MATCHES, ''];
        yield 'with another test missing' => [$eq + ['eq' => ['input.role' => 'admin']], [], MatchOutcome::UNDECIDABLE, 'key \'input.role\' is missing from the context'];
    }

    /**
     * Under `_if_exists` only an absent key passes: a present null or a value
     * of the wrong type is decided exactly as without the suffix.
     *
     * @param  array<string, mixed>  $conditions
     * @param  array<string, mixed>  $context
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome  $outcome
     * @param  string  $detail
     * @return void
     */
    #[DataProvider('ifExistsProvider')]
    public function testIfExists(array $conditions, array $context, MatchOutcome $outcome, string $detail): void
    {
        $statement = Statement::fromArray(['effect' => 'deny', 'actions' => ['x'], 'conditions' => $conditions]);

        self::assertResult($outcome, $detail, $statement->assess('x', null, $context));
    }

    /**
     * Under `_if_exists` a malformed operand is still invalid and an unresolved
     * interpolation of a present key still undecidable; an absent key passes
     * before its operand is interpolated.
     *
     * @return void
     */
    public function testIfExistsDecidesFaultsAsWithoutTheSuffix(): void
    {
        $malformed  = new Statement(PolicyEffect::DENY, ['x'], conditions: ['ip_in_if_exists' => ['input.ip' => '10.0.0.0/33']]);
        $referenced = Statement::fromArray(['effect' => 'deny', 'actions' => ['x'], 'conditions' => ['eq_if_exists' => ['input.owner' => '${subject.id}']]]);

        $interpolator = new ContextInterpolator;

        self::assertResult(MatchOutcome::INVALID, 'condition \'input.ip\' has an invalid operand for operator \'ip_in\'', $malformed->assess('x'));
        self::assertResult(
            MatchOutcome::INVALID,
            'condition \'input.ip\' has an invalid operand for operator \'ip_in\'',
            $malformed->assess('x', null, ['input' => ['ip' => '10.0.0.1']]),
        );
        self::assertResult(
            MatchOutcome::UNDECIDABLE,
            'condition \'input.owner\' references a value that cannot be resolved',
            $referenced->assess('x', null, ['input' => ['owner' => '1']], $interpolator),
        );
        self::assertResult(MatchOutcome::MATCHES, '', $referenced->assess('x', null, [], $interpolator));
    }

    /**
     * ip_not_in never reads a value that is not an address as outside the
     * ranges.
     *
     * @return void
     */
    public function testIpNotInWithAnInvalidAddressIsUndecidable(): void
    {
        $statement = Statement::fromArray(['effect' => 'deny', 'actions' => ['x'], 'conditions' => ['ip_not_in' => ['request.ip' => ['10.0.0.0/8']]]]);

        self::assertResult(
            MatchOutcome::UNDECIDABLE,
            'condition \'request.ip\': operator \'ip_not_in\' needs an IP address',
            $statement->assess('x', null, ['request' => ['ip' => 'unknown']]),
        );
        self::assertResult(MatchOutcome::MATCHES, '', $statement->assess('x', null, ['request' => ['ip' => '192.0.2.1']]));
    }

    /**
     * A NUL byte in a context value, or in an operand substituted into one,
     * never throws: the test is undecidable, so a deny applies and an allow
     * does not.
     *
     * @return void
     */
    public function testANulByteIsUndecidable(): void
    {
        $interpolator = new ContextInterpolator;
        $cases        = [
            'ip_in'       => ['request.ip', '1.2.3.0/24', "1.2.3.4\0", 'operator \'ip_in\' needs an IP address'],
            'ip_not_in'   => ['request.ip', '1.2.3.0/24', "9.9.9.9\0", 'operator \'ip_not_in\' needs an IP address'],
            'like'        => ['input.ua', 'curl*', "curl\0", 'operator \'like\' cannot test a NUL byte'],
            'starts_with' => ['input.ua', 'curl', "curl\0", 'operator \'starts_with\' cannot test a NUL byte'],
            'ends_with'   => ['input.ua', 'curl', "\0curl", 'operator \'ends_with\' cannot test a NUL byte'],
        ];

        foreach ($cases as $operator => [$key, $operand, $value, $detail]) {
            $statement = Statement::fromArray(['effect' => 'deny', 'actions' => ['a'], 'conditions' => [$operator => [$key => $operand]]]);

            self::assertResult(MatchOutcome::UNDECIDABLE, "condition '{$key}': {$detail}", $statement->assess('a', null, Arr::undot([$key => $value])));
        }

        $substituted = Statement::fromArray(['effect' => 'deny', 'actions' => ['a'], 'conditions' => ['like' => ['input.ua' => '${input.agent}*']]]);

        self::assertResult(
            MatchOutcome::UNDECIDABLE,
            'condition \'input.ua\': operator \'like\' cannot test a NUL byte',
            $substituted->assess('a', null, ['input' => ['ua' => 'curl', 'agent' => "cu\0"]], $interpolator),
        );
    }

    /**
     * all_values_in does not hold for an empty list, and any_value_in is
     * undecidable for a value that is not a list.
     *
     * @return void
     */
    public function testValueSetsOnEmptyAndNonListValues(): void
    {
        $all = Statement::fromArray(['effect' => 'allow', 'actions' => ['x'], 'conditions' => ['all_values_in' => ['input.tags' => ['a', 'b']]]]);
        $any = Statement::fromArray(['effect' => 'allow', 'actions' => ['x'], 'conditions' => ['any_value_in' => ['input.tags' => ['a', 'b']]]]);

        self::assertResult(MatchOutcome::DOES_NOT_MATCH, '', $all->assess('x', null, ['input' => ['tags' => []]]));
        self::assertResult(
            MatchOutcome::UNDECIDABLE,
            'condition \'input.tags\': operator \'any_value_in\' needs a list of values',
            $any->assess('x', null, ['input' => ['tags' => 'a']]),
        );
        self::assertResult(MatchOutcome::MATCHES, '', $any->assess('x', null, ['input' => ['tags' => ['b']]]));
    }

    /**
     * Provide malformed conditions of a directly constructed statement with the
     * detail it is invalid with.
     *
     * @return iterable<string, array{0: array<array-key, mixed>, 1: string, 2: array<string, bool>}>
     */
    public static function malformedConditionProvider(): iterable
    {
        yield 'unknown operator' => [['bogus' => ['tenant' => 'org-1']], 'conditions have an unknown operator \'bogus\'', []];
        yield 'key-first' => [['tenant' => ['eq' => 'org-1']], 'conditions have an unknown operator \'tenant\'', []];
        yield 'list of conditions' => [[['eq' => ['input.tenant' => 'org-1']]], 'conditions must map operator names to key tests', []];
        yield 'empty operator map' => [['eq' => []], 'condition operator \'eq\' must map context keys to operands', []];
        yield 'invalid operand' => [['in' => ['input.tenant' => 'org-1']], 'condition \'input.tenant\' has an invalid operand for operator \'in\'', ['input.tenant' => false]];
        yield 'empty string operand' => [
            ['starts_with' => ['input.tenant' => '']],
            'condition \'input.tenant\' has an invalid operand for operator \'starts_with\'',
            ['input.tenant' => false],
        ];
        yield 'malformed reference' => [['eq' => ['input.tenant' => '${foo']], 'condition \'input.tenant\' has a malformed ${…} reference', ['input.tenant' => false]];
    }

    /**
     * A malformed condition of a directly constructed statement is invalid
     * whatever the context holds, its key missing included.
     *
     * @param  array<array-key, mixed>  $conditions
     * @param  string  $detail
     * @param  array<string, bool>  $held
     * @return void
     */
    #[DataProvider('malformedConditionProvider')]
    public function testMalformedConditionIsInvalidWhateverTheContext(array $conditions, string $detail, array $held): void
    {
        $statement    = new Statement(PolicyEffect::DENY, ['x'], conditions: $conditions);
        $interpolator = new ContextInterpolator;

        foreach ([[], ['input' => ['tenant' => 'org-1']]] as $context) {
            $result = $statement->assess('x', null, $context, $interpolator);

            self::assertResult(MatchOutcome::INVALID, $detail, $result);
            self::assertSame($held, $result->conditions);
            self::assertFalse($statement->conditionsSatisfiedBy($context));
        }
    }

    /**
     * An invalid test beats every other outcome wherever it sits, and a
     * definite failure beats an undecidable test, in either order.
     *
     * @return void
     */
    public function testOutcomePrecedence(): void
    {
        $invalidLast  = new Statement(PolicyEffect::DENY, ['x'], conditions: ['eq' => ['input.a' => 1, 'input.b' => 1], 'in' => ['input.c' => 'x']]);
        $invalidFirst = new Statement(PolicyEffect::DENY, ['x'], conditions: ['in' => ['input.c' => 'x'], 'eq' => ['input.b' => 1, 'input.a' => 1]]);
        $operatorLast = new Statement(PolicyEffect::DENY, ['x'], conditions: ['eq' => ['input.b' => 2], 'bogus' => ['input.c' => 1]]);
        $invalid      = 'condition \'input.c\' has an invalid operand for operator \'in\'';

        self::assertResult(MatchOutcome::INVALID, $invalid, $invalidLast->assess('x', null, ['input' => ['b' => 2, 'c' => 1]]));
        self::assertResult(MatchOutcome::INVALID, $invalid, $invalidFirst->assess('x', null, ['input' => ['b' => 2, 'c' => 1]]));
        self::assertResult(MatchOutcome::INVALID, 'conditions have an unknown operator \'bogus\'', $operatorLast->assess('x', null, ['input' => ['b' => 3]]));

        $undecidableFirst = Statement::fromArray(['effect' => 'deny', 'actions' => ['x'], 'conditions' => ['eq' => ['input.a' => 1, 'input.b' => 2]]]);
        $failingFirst     = Statement::fromArray(['effect' => 'deny', 'actions' => ['x'], 'conditions' => ['eq' => ['input.b' => 2, 'input.a' => 1]]]);
        $acrossOperators  = Statement::fromArray(['effect' => 'deny', 'actions' => ['x'], 'conditions' => ['starts_with' => ['input.n' => 'a'], 'eq' => ['input.n' => 6]]]);

        self::assertResult(MatchOutcome::DOES_NOT_MATCH, '', $undecidableFirst->assess('x', null, ['input' => ['b' => 3]]));
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, '', $failingFirst->assess('x', null, ['input' => ['b' => 3]]));
        self::assertResult(MatchOutcome::UNDECIDABLE, 'key \'input.a\' is missing from the context', $undecidableFirst->assess('x'));
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, '', $acrossOperators->assess('x', null, ['input' => ['n' => 5]]));
        self::assertResult(
            MatchOutcome::UNDECIDABLE,
            'condition \'input.n\': operator \'starts_with\' needs a string value',
            $acrossOperators->assess('x', null, ['input' => ['n' => 6]]),
        );
    }

    /**
     * The target and conditions combine: an undecidable resource is beaten by a
     * failing or invalid condition and kept over a matching one, and a target
     * that does not cover the check is reported without its conditions.
     *
     * @return void
     */
    public function testTargetCombinesWithConditions(): void
    {
        $statement    = new Statement(PolicyEffect::DENY, ['posts:read'], ['posts:${subject.id}'], ['eq' => ['input.tenant' => 'org-1']]);
        $invalid      = new Statement(PolicyEffect::DENY, ['posts:read'], ['posts:${subject.id}'], ['bogus' => ['tenant' => 'org-1']]);
        $scoped       = new Statement(PolicyEffect::DENY, ['posts:read'], ['posts:1'], ['bogus' => ['tenant' => 'org-1']]);
        $interpolator = new ContextInterpolator;

        $undecidable = $statement->assess('posts:read', 'posts:1', ['input' => ['tenant' => 'org-1']], $interpolator);

        self::assertResult(MatchOutcome::UNDECIDABLE, self::UNRESOLVED_RESOURCE, $undecidable);
        self::assertSame(['input.tenant' => true], $undecidable->conditions);
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, '', $statement->assess('posts:read', 'posts:1', ['input' => ['tenant' => 'org-2']], $interpolator));
        self::assertResult(MatchOutcome::INVALID, 'conditions have an unknown operator \'bogus\'', $invalid->assess('posts:read', 'posts:1', [], $interpolator));
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, self::TARGET_MISMATCH, $scoped->assess('users:read', 'posts:1'));
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, self::TARGET_MISMATCH, $scoped->assess('posts:read', 'posts:2'));
        self::assertResult(MatchOutcome::INVALID, 'conditions have an unknown operator \'bogus\'', $scoped->assess('posts:read', 'posts:1'));
    }

    // ------------------------------------------------------------------
    // Interpolated operands
    // ------------------------------------------------------------------

    /**
     * String operands carrying a reference are resolved when the statement is
     * assessed.
     *
     * @return void
     */
    public function testInterpolatedOperandsAreResolved(): void
    {
        $conditions = [
            'ip_in'  => ['input.ip' => '${input.range}'],
            'before' => ['input.at' => '${input.deadline}'],
            'after'  => ['input.at' => '${input.opens}'],
            'gt'     => ['input.size' => '${input.minimum}'],
            'lte'    => ['input.size' => '${input.maximum}'],
            'bool'   => ['input.flag' => '${input.expected_flag}'],
            'like'   => ['input.name' => '${input.prefix}*'],
            'eq'     => ['input.owner' => '${subject.id}', 'input.post' => '${resource.id}'],
        ];

        $statement = Statement::fromArray(['effect' => 'allow', 'actions' => ['x'], 'conditions' => $conditions]);
        $context   = [
            'input' => [
                'ip'            => '10.1.2.3',
                'at'            => '2026-04-15',
                'size'          => 5,
                'flag'          => false,
                'name'          => 'admin-user',
                'owner'         => '42',
                'post'          => '7',
                'range'         => '10.0.0.0/8',
                'deadline'      => '2026-04-20',
                'opens'         => '2026-04-10',
                'minimum'       => 1,
                'maximum'       => 5,
                'expected_flag' => false,
                'prefix'        => 'admin',
            ],
            'subject'  => ['id' => '42'],
            'resource' => ['id' => '7', 'type' => 'post'],
        ];

        $interpolator = new ContextInterpolator;

        self::assertSame($conditions, $statement->conditions);
        self::assertResult(MatchOutcome::MATCHES, '', $statement->assess('x', 'post:7', $context, $interpolator));
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, '', $statement->assess('x', 'post:7', ['input' => ['size' => 6] + $context['input']] + $context, $interpolator));
        $wildcard = ['input' => ['prefix' => '*'] + $context['input']] + $context;

        self::assertResult(MatchOutcome::DOES_NOT_MATCH, '', $statement->assess('x', 'post:7', $wildcard, $interpolator));
        self::assertTrue($statement->conditionsSatisfiedBy($context, $interpolator));
        self::assertFalse($statement->conditionsSatisfiedBy(['resource' => ['id' => '8']] + $context, $interpolator));
    }

    /**
     * Provide interpolated operands that resolve to a value of the wrong type
     * for their operator.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function interpolatedWrongTypeProvider(): iterable
    {
        yield 'bool' => ['bool', true, 'yes'];
        yield 'gt' => ['gt', 5, 'abc'];
        yield 'before' => ['before', '2026-04-15', 'not-a-date'];
        yield 'ip_in' => ['ip_in', '10.0.0.1', 'not-a-range'];
        yield 'ip_not_in' => ['ip_not_in', '10.0.0.1', '10.0.0.0/33'];
    }

    /**
     * An interpolated operand of the wrong type is undecidable rather than
     * invalid, whatever the effect.
     *
     * @param  string  $operator
     * @param  mixed  $actual
     * @param  string  $substituted
     * @return void
     */
    #[DataProvider('interpolatedWrongTypeProvider')]
    public function testInterpolatedOperandOfTheWrongTypeIsUndecidable(string $operator, mixed $actual, string $substituted): void
    {
        $context = ['input' => ['k' => $actual, 'operand' => $substituted]];
        $detail  = "condition 'input.k': the substituted operand is an invalid operand for operator '{$operator}'";

        foreach (['deny', 'allow'] as $effect) {
            $statement = Statement::fromArray(['effect' => $effect, 'actions' => ['x'], 'conditions' => [$operator => ['input.k' => '${input.operand}']]]);

            self::assertResult(MatchOutcome::UNDECIDABLE, $detail, $statement->assess('x', null, $context, new ContextInterpolator));
        }
    }

    /**
     * An operand whose reference cannot be resolved is undecidable, an empty
     * interpolated pattern too, and without an interpolator the operand is
     * compared as written.
     *
     * @return void
     */
    public function testUnresolvedAndLiteralOperands(): void
    {
        $owner   = Statement::fromArray(['effect' => 'deny', 'actions' => ['x'], 'conditions' => ['eq' => ['input.owner_id' => '${subject.id}']]]);
        $pattern = Statement::fromArray(['effect' => 'deny', 'actions' => ['x'], 'conditions' => ['like' => ['input.name' => '${input.pattern}']]]);
        $classes = Statement::fromArray(['effect' => 'allow', 'actions' => ['x'], 'conditions' => ['like' => ['input.class' => 'App\Models\*']]]);
        $path    = Statement::fromArray(['effect' => 'allow', 'actions' => ['x'], 'conditions' => ['eq' => ['input.path' => 'App\Models:${input.suffix}']]]);

        $interpolator = new ContextInterpolator;

        self::assertResult(
            MatchOutcome::UNDECIDABLE,
            'condition \'input.owner_id\' references a value that cannot be resolved',
            $owner->assess('x', null, ['input' => ['owner_id' => '']], $interpolator),
        );
        self::assertResult(MatchOutcome::MATCHES, '', $owner->assess('x', null, ['input' => ['owner_id' => '${subject.id}']]));
        self::assertResult(
            MatchOutcome::UNDECIDABLE,
            'condition \'input.name\': operator \'like\' has an empty operand',
            $pattern->assess('x', null, ['input' => ['name' => 'a', 'pattern' => '']], $interpolator),
        );
        self::assertResult(MatchOutcome::MATCHES, '', $classes->assess('x', null, ['input' => ['class' => 'App\Models\Post']]));
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, '', $classes->assess('x', null, ['input' => ['class' => 'AppModelsPost']]));
        self::assertResult(MatchOutcome::MATCHES, '', $path->assess('x', null, ['input' => ['path' => 'App\Models:Po*', 'suffix' => 'Po*']], $interpolator));
    }

    // ------------------------------------------------------------------
    // Context paths
    // ------------------------------------------------------------------

    /**
     * A condition key is a dot path read segment by segment through the
     * namespaces of the context.
     *
     * @return void
     */
    public function testAConditionKeyIsADotPath(): void
    {
        $statement = Statement::fromArray(['effect' => 'allow', 'actions' => ['x'], 'conditions' => [
            'eq'    => ['input.post.status' => 'draft'],
            'ip_in' => ['request.ip' => '10.0.0.0/8'],
        ]]);
        $context = ['input' => ['post' => ['status' => 'draft']], 'request' => ['ip' => '10.0.0.1']];

        self::assertResult(MatchOutcome::MATCHES, '', $statement->assess('x', null, $context));
        self::assertSame(['input.post.status' => true, 'request.ip' => true], $statement->assess('x', null, $context)->conditions);
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, '', $statement->assess('x', null, ['input' => ['post' => ['status' => 'published']]] + $context));
        self::assertTrue($statement->conditionsSatisfiedBy(new CheckContext($context)));
    }

    /**
     * Provide contexts in which a dot path is missing: a literal dotted key at
     * the top level or within a namespace, a segment read through a value that
     * is not an array, and an absent namespace.
     *
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function missingPathProvider(): iterable
    {
        yield 'literal dotted top-level key' => [['input.post.status' => 'draft']];
        yield 'literal dotted key within the namespace' => [['input' => ['post.status' => 'draft']]];
        yield 'through a scalar' => [['input' => ['post' => 'draft']]];
        yield 'through a null' => [['input' => ['post' => null]]];
        yield 'absent namespace' => [['request' => ['post' => ['status' => 'draft']]]];
    }

    /**
     * A literal flat key never stands in for a dot path, and a path through a
     * value that is not an array is missing: the test is undecidable, passes
     * under `_if_exists`, and `null` decides it.
     *
     * @param  array<string, mixed>  $context
     * @return void
     */
    #[DataProvider('missingPathProvider')]
    public function testAPathThatIsNotThereIsMissing(array $context): void
    {
        $eq       = Statement::fromArray(['effect' => 'deny', 'actions' => ['x'], 'conditions' => ['eq' => ['input.post.status' => 'draft']]]);
        $optional = Statement::fromArray(['effect' => 'deny', 'actions' => ['x'], 'conditions' => ['eq_if_exists' => ['input.post.status' => 'draft']]]);
        $null     = Statement::fromArray(['effect' => 'deny', 'actions' => ['x'], 'conditions' => ['null' => ['input.post.status' => true]]]);

        self::assertResult(MatchOutcome::UNDECIDABLE, 'key \'input.post.status\' is missing from the context', $eq->assess('x', null, $context));
        self::assertResult(MatchOutcome::MATCHES, '', $optional->assess('x', null, $context));
        self::assertResult(MatchOutcome::MATCHES, '', $null->assess('x', null, $context));
    }

    /**
     * A key present along a path with a null value is not missing: the operator
     * tests the null, `_if_exists` included, and `null: false` does not hold.
     *
     * @return void
     */
    public function testAPresentNullAlongAPathIsNotMissing(): void
    {
        $context  = ['input' => ['post' => ['status' => null]]];
        $eq       = Statement::fromArray(['effect' => 'deny', 'actions' => ['x'], 'conditions' => ['eq' => ['input.post.status' => 'draft']]]);
        $optional = Statement::fromArray(['effect' => 'deny', 'actions' => ['x'], 'conditions' => ['ip_in_if_exists' => ['input.post.status' => '10.0.0.0/8']]]);
        $isNull   = Statement::fromArray(['effect' => 'deny', 'actions' => ['x'], 'conditions' => ['null' => ['input.post.status' => true]]]);
        $notNull  = Statement::fromArray(['effect' => 'deny', 'actions' => ['x'], 'conditions' => ['null' => ['input.post.status' => false]]]);

        self::assertResult(MatchOutcome::DOES_NOT_MATCH, '', $eq->assess('x', null, $context));
        self::assertResult(MatchOutcome::UNDECIDABLE, 'condition \'input.post.status\': operator \'ip_in\' needs an IP address', $optional->assess('x', null, $context));
        self::assertResult(MatchOutcome::MATCHES, '', $isNull->assess('x', null, $context));
        self::assertResult(MatchOutcome::DOES_NOT_MATCH, '', $notNull->assess('x', null, $context));
        self::assertResult(MatchOutcome::MATCHES, '', $notNull->assess('x', null, ['input' => ['post' => ['status' => '']]]));
    }

    /**
     * A statement builds only the namespaces it reads, through its condition
     * keys and its references, and none at all when it does not name the action
     * or its test is malformed.
     *
     * @return void
     */
    public function testAStatementBuildsOnlyTheNamespacesItReads(): void
    {
        $context   = $this->countingContext(['request' => ['ip' => '10.0.0.1'], 'tenant' => ['id' => 'org-1'], 'environment' => ['time' => 'now']]);
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['x'],
            'resources'  => ['tenants/${tenant.id}/*'],
            'conditions' => ['eq' => ['request.ip' => '10.0.0.1']],
        ]);
        $malformed = new Statement(PolicyEffect::DENY, ['x'], conditions: ['ip_in' => ['environment.time' => 5]]);

        self::assertResult(MatchOutcome::DOES_NOT_MATCH, Statement::TARGET_MISMATCH, $statement->assess('y', 'tenants/org-1/posts', $context, new ContextInterpolator));
        self::assertSame([], $this->builds);

        self::assertResult(MatchOutcome::INVALID, 'condition \'environment.time\' has an invalid operand for operator \'ip_in\'', $malformed->assess('x', null, $context));
        self::assertSame([], $this->builds);

        self::assertResult(MatchOutcome::MATCHES, '', $statement->assess('x', 'tenants/org-1/posts', $context, new ContextInterpolator));
        self::assertSame(['tenant' => 1, 'request' => 1], $this->builds);
    }

    /**
     * Within one check a namespace is built once, however many tests and
     * statements read it; a new check builds it again.
     *
     * @return void
     */
    public function testANamespaceIsBuiltOncePerCheck(): void
    {
        $values = ['request' => ['ip' => '10.0.0.1', 'method' => 'GET']];
        $first  = Statement::fromArray(['effect' => 'allow', 'actions' => ['x'], 'conditions' => ['eq' => ['request.ip' => '10.0.0.1', 'request.method' => 'GET']]]);
        $second = Statement::fromArray(['effect' => 'deny', 'actions' => ['x'], 'conditions' => ['neq' => ['request.method' => '${request.ip}']]]);

        $check = $this->countingContext($values);

        $first->assess('x', null, $check);
        $second->assess('x', null, $check, new ContextInterpolator);
        self::assertSame(['request' => 1], $this->builds);

        $first->assess('x', null, $this->countingContext($values));
        self::assertSame(['request' => 2], $this->builds);
    }

    /**
     * Provide malformed authentication requirement conditions, with the message
     * each is refused with.
     *
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function malformedRequirementProvider(): iterable
    {
        yield 'another key' => [
            ['authentication_requirement' => ['authentication.amr' => ['multifactor' => []]]],
            'Policy statement condition operator \'authentication_requirement\' tests the key \'authentication\' alone, not \'authentication.amr\'.',
        ];
        yield 'an unknown part' => [
            ['authentication_requirement' => ['authentication' => ['hardware' => []]]],
            'Policy statement authentication requirement names an unknown part \'hardware\'.',
        ];
        yield 'a bad max age' => [
            ['authentication_requirement' => ['authentication' => ['multifactor' => ['max_age' => '900']]]],
            'Policy statement authentication requirement part \'multifactor\' max_age must be a whole number of seconds, at least 1.',
        ];
        yield 'the _if_exists form' => [
            ['authentication_requirement_if_exists' => ['authentication' => ['multifactor' => []]]],
            'Policy statement condition operator \'authentication_requirement_if_exists\' is not an operator; an authentication requirement has no _if_exists form.',
        ];
    }

    /**
     * A malformed authentication requirement is refused on hydration.
     *
     * @param  array<string, mixed>  $conditions
     * @param  string  $message
     * @return void
     */
    #[DataProvider('malformedRequirementProvider')]
    public function testFromArrayRefusesAMalformedRequirement(array $conditions, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        Statement::fromArray(['effect' => 'allow', 'actions' => ['posts:read'], 'conditions' => $conditions]);
    }

    /**
     * A statement keeps its requirement as written, so it round-trips.
     *
     * @return void
     */
    public function testARequirementRoundTrips(): void
    {
        $data = ['effect' => 'allow', 'actions' => ['posts:read'], 'conditions' => self::REQUIREMENT];

        self::assertSame($data, Statement::fromArray($data)->toArray());
    }

    /**
     * A met requirement holds, and the trace records it as the key
     * `authentication`, held, without building the `authentication` namespace.
     *
     * @return void
     */
    public function testAMetRequirementHolds(): void
    {
        $context = $this->requirementContext(RequirementResult::met(), ['authentication' => ['amr' => ['pwd']]]);
        $result  = self::requiring()->assess('posts:read', null, $context);

        self::assertSame(MatchOutcome::MATCHES, $result->outcome);
        self::assertSame(['authentication' => true], $result->conditions);
        self::assertNull($result->unmetRequirement);
        self::assertSame([], $this->builds);
    }

    /**
     * An unmet requirement does not hold, and the assessment carries it with
     * its unmet parts, the key `authentication` recorded as not held.
     *
     * @return void
     */
    public function testAnUnmetRequirementIsCarried(): void
    {
        $result = self::requiring()->assess('posts:read', null, $this->requirementContext(RequirementResult::unmet(['multifactor'])));

        self::assertSame(MatchOutcome::DOES_NOT_MATCH, $result->outcome);
        self::assertSame(['authentication' => false], $result->conditions);
        self::assertEquals(new UnmetRequirement(self::requirement(), ['multifactor']), $result->unmetRequirement);
    }

    /**
     * A requirement the checker fails on is undecidable, and carries nothing.
     *
     * @return void
     */
    public function testARequirementTheCheckerFailsOnIsUndecidable(): void
    {
        $result = self::requiring()->assess('posts:read', null, $this->requirementContext(new \RuntimeException('down')));

        self::assertSame(MatchOutcome::UNDECIDABLE, $result->outcome);
        self::assertSame(['authentication' => false], $result->conditions);
        self::assertNull($result->unmetRequirement);
    }

    /**
     * The unmet requirement is carried when every other test holds, and not
     * when another does not hold or cannot be decided, nor when the requirement
     * is met and another test fails.
     *
     * @return void
     */
    public function testTheRequirementIsCarriedOnlyWhenItAloneFails(): void
    {
        $unmet = RequirementResult::unmet(['multifactor']);
        $with  = static fn (array $conditions): Statement => Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['posts:read'],
            'conditions' => [...self::REQUIREMENT, ...$conditions],
        ]);

        $holds       = $with(['eq' => ['input.k' => 'a']])->assess('posts:read', null, $this->requirementContext($unmet, ['input' => ['k' => 'a']]));
        $fails       = $with(['eq' => ['input.k' => 'a']])->assess('posts:read', null, $this->requirementContext($unmet, ['input' => ['k' => 'b']]));
        $undecidable = $with(['eq' => ['input.missing' => 'a']])->assess('posts:read', null, $this->requirementContext($unmet, ['input' => []]));
        $met         = $with(['eq' => ['input.k' => 'a']])->assess('posts:read', null, $this->requirementContext(RequirementResult::met(), ['input' => ['k' => 'b']]));

        self::assertNotNull($holds->unmetRequirement);
        self::assertSame(['authentication' => false, 'input.k' => true], $holds->conditions);
        self::assertSame(MatchOutcome::DOES_NOT_MATCH, $fails->outcome);
        self::assertNull($fails->unmetRequirement);
        self::assertSame(MatchOutcome::DOES_NOT_MATCH, $undecidable->outcome);
        self::assertNull($undecidable->unmetRequirement);
        self::assertSame(MatchOutcome::DOES_NOT_MATCH, $met->outcome);
        self::assertNull($met->unmetRequirement);
    }

    /**
     * A malformed operator beside an unmet requirement makes the statement
     * invalid, carrying nothing.
     *
     * @return void
     */
    public function testAnInvalidStatementCarriesNoRequirement(): void
    {
        $statement = new Statement(PolicyEffect::ALLOW, ['posts:read'], null, [...self::REQUIREMENT, 'bogus' => ['input.k' => 1]]);
        $result    = $statement->assess('posts:read', null, $this->requirementContext(RequirementResult::unmet(['multifactor'])));

        self::assertSame(MatchOutcome::INVALID, $result->outcome);
        self::assertNull($result->unmetRequirement);
    }

    /**
     * An unmet requirement is carried when the resource definitely matches, and
     * not when a resource pattern cannot be resolved.
     *
     * @return void
     */
    public function testTheRequirementIsCarriedOnlyWhenTheResourceMatches(): void
    {
        $unmet     = RequirementResult::unmet(['multifactor']);
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['posts:read'],
            'resources'  => ['post:${input.post}'],
            'conditions' => self::REQUIREMENT,
        ]);

        $matched    = $statement->assess('posts:read', 'post:1', $this->requirementContext($unmet, ['input' => ['post' => '1']]), new ContextInterpolator);
        $unresolved = $statement->assess('posts:read', 'post:1', $this->requirementContext($unmet, ['input' => []]), new ContextInterpolator);

        self::assertNotNull($matched->unmetRequirement);
        self::assertSame(MatchOutcome::DOES_NOT_MATCH, $unresolved->outcome);
        self::assertNull($unresolved->unmetRequirement);
    }

    /**
     * A context given as an array meets no requirement.
     *
     * @return void
     */
    public function testAnArrayContextMeetsNoRequirement(): void
    {
        $result = self::requiring()->assess('posts:read', null, ['authentication' => ['multifactor' => true]]);

        self::assertSame(MatchOutcome::DOES_NOT_MATCH, $result->outcome);
        self::assertSame(['multifactor', 'phishing_resistant'], $result->unmetRequirement?->unmet);
        self::assertFalse(self::requiring()->conditionsSatisfiedBy([]));
    }

    /**
     * An allow statement's principals are read from its document, kept on the
     * statement and written back with it; a statement without them has none and
     * writes none.
     *
     * @return void
     */
    public function testPrincipalsRoundTrip(): void
    {
        $data      = ['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:1', 'role:2']];
        $statement = Statement::fromArray($data);

        self::assertSame(['user:1', 'role:2'], $statement->principals);
        self::assertSame(['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:1', 'role:2']], $statement->toArray());
        self::assertNull(Statement::fromArray(['effect' => 'allow', 'actions' => ['posts:read']])->principals);
        self::assertArrayNotHasKey('principals', Statement::fromArray(['effect' => 'allow', 'actions' => ['posts:read']])->toArray());
        $full = Statement::fromArray([...$data, 'resources' => ['*'], 'conditions' => ['eq' => ['input.a' => 'b']]]);

        self::assertSame(['effect', 'actions', 'resources', 'principals', 'conditions'], \array_keys($full->toArray()));
    }

    /**
     * Principals on a deny, or malformed principals, are refused, read from a
     * document or built in code.
     *
     * @return void
     */
    public function testRefusesPrincipalsOnADenyOrMalformed(): void
    {
        $builds = [
            static fn (): Statement => Statement::fromArray(['effect' => 'deny', 'actions' => ['posts:read'], 'principals' => ['user:1']]),
            static fn (): Statement => Statement::fromArray(['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => 'user:1']),
            static fn (): Statement => Statement::fromArray(['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user']]),
            static fn (): Statement => new Statement(PolicyEffect::DENY, ['posts:read'], principals: ['user:1']),
            static fn (): Statement => new Statement(PolicyEffect::ALLOW, ['posts:read'], principals: []),
        ];

        foreach ($builds as $build) {
            try {
                $build();
                self::fail('The principals were not refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertStringStartsWith('Policy statement principal', $exception->getMessage());
            }
        }

        self::assertSame(['user:1'], (new Statement(PolicyEffect::ALLOW, ['posts:read'], principals: ['user:1']))->principals);
    }

    /**
     * A statement names every `${…}` reference of its condition operands and
     * resource patterns, each once, worked out on construction.
     *
     * @return void
     */
    public function testDependenciesAreTheReferencesTheStatementNames(): void
    {
        $statement = new Statement(PolicyEffect::ALLOW, ['posts:read'], null, ['eq' => ['input.a' => '${subject.id}']], null, null, ['posts:${input.tenant}/*']);

        self::assertSame(['subject.id', 'input.tenant'], $statement->dependencies);
        self::assertSame([], (new Statement(PolicyEffect::ALLOW, ['posts:read']))->dependencies);
        self::assertSame(['resource.owner'], (new Statement(PolicyEffect::ALLOW, ['posts:read'], ['posts:${resource.owner}']))->dependencies);
    }

    /**
     * Through an explained context, the assessment notes each condition test
     * and the resource patterns' references that could not be resolved with the
     * context, and gives the outcome and the condition keys an everyday
     * assessment gives; a statement whose target does not match notes none, and
     * an everyday context is never noted with.
     *
     * @return void
     */
    public function testAnExplainedAssessmentCarriesItsEvidence(): void
    {
        $statement = new Statement(PolicyEffect::DENY, ['posts:read'], ['posts:${input.missing}', 'posts:*'], ['eq' => ['input.a' => 'x']]);
        $everyday  = new CheckContext(['input' => ['a' => 'x']]);
        $context   = new CheckContext(['input' => ['a' => 'x']]);
        $plain     = $statement->assess('posts:read', 'posts:1', $everyday, new ContextInterpolator);

        $context->explain();

        $explained = $statement->assess('posts:read', 'posts:1', $context, new ContextInterpolator);

        self::assertSame($plain->outcome, $explained->outcome);
        self::assertSame($plain->conditions, $explained->conditions);
        self::assertSame([null, []], $everyday->takeAssessment());
        self::assertEquals([[new ConditionResult('input.a', 'eq', ConditionOutcome::HELD)], ['input.missing']], $context->takeAssessment());
        self::assertSame([], $context->takeUnresolved());

        $statement->assess('comments:read', 'posts:1', $context);
        (new Statement(PolicyEffect::DENY, ['posts:read'], ['posts:*']))->assess('posts:read', 'comments:1', $context, new ContextInterpolator);

        self::assertSame([null, []], $context->takeAssessment());

        $statement->assess('posts:read', 'comments:1', $context, new ContextInterpolator);

        self::assertSame(['input.missing'], $context->takeAssessment()[1]);
    }

    /**
     * Through an explained context, a statement whose target does not match
     * notes no test and the references its resource patterns could not resolve,
     * so the next statement assessed notes none of them as its own; an everyday
     * context is noted with nothing.
     *
     * @return void
     */
    public function testATargetMismatchNotesItsOwnUnresolvedReferences(): void
    {
        $deny     = new Statement(PolicyEffect::DENY, ['posts:read'], null, [], null, null, ['posts:${input.missing}', 'posts:1']);
        $allow    = new Statement(PolicyEffect::ALLOW, ['posts:read'], ['posts:*'], ['eq' => ['input.a' => 'x']]);
        $context  = new CheckContext(['input' => ['a' => 'x']]);
        $everyday = new CheckContext(['input' => ['a' => 'x']]);

        $context->explain();

        self::assertSame(MatchOutcome::DOES_NOT_MATCH, $deny->assess('posts:read', 'posts:1', $context, new ContextInterpolator)->outcome);
        self::assertSame([null, ['input.missing']], $context->takeAssessment());

        $deny->assess('posts:read', 'posts:1', $context, new ContextInterpolator);
        $allow->assess('posts:read', 'posts:1', $context, new ContextInterpolator);

        self::assertSame([], $context->takeAssessment()[1]);

        $deny->assess('posts:read', 'posts:1', $everyday, new ContextInterpolator);

        self::assertSame([null, []], $everyday->takeAssessment());
    }

    /**
     * A substituted operand of the wrong type is undecidable, its detail saying
     * so.
     *
     * @return void
     */
    public function testASubstitutedOperandOfTheWrongTypeSaysSo(): void
    {
        $statement = new Statement(PolicyEffect::ALLOW, ['posts:read'], null, ['gt' => ['input.n' => '${input.limit}']]);
        $result    = $statement->assess('posts:read', null, ['input' => ['n' => 5, 'limit' => 'abc']], new ContextInterpolator);

        self::assertSame(MatchOutcome::UNDECIDABLE, $result->outcome);
        self::assertStringStartsWith('condition \'input.n\': ' . Statement::SUBSTITUTED_OPERAND . ' ', $result->detail);
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
     * Build a check context whose namespaces are each built from the values
     * given, counting each build.
     *
     * @param  array<string, array<string, mixed>>  $values
     * @return \SineMacula\Laravel\Authorization\Evaluation\CheckContext
     */
    private function countingContext(array $values): CheckContext
    {
        $builders = [];

        foreach ($values as $namespace => $namespaceValues) {
            $builders[$namespace] = function () use ($namespace, $namespaceValues): array {
                $this->builds[$namespace] = ($this->builds[$namespace] ?? 0) + 1;

                return [$namespace => $namespaceValues];
            };
        }

        return new CheckContext([], $builders);
    }

    /**
     * Return a statement allowing `posts:read` under the requirement.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Statement
     */
    private static function requiring(): Statement
    {
        return Statement::fromArray(['effect' => 'allow', 'actions' => ['posts:read'], 'conditions' => self::REQUIREMENT]);
    }

    /**
     * Return the requirement the statements state.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement
     */
    private static function requirement(): AuthenticationRequirement
    {
        return new AuthenticationRequirement(['multifactor' => 900, 'phishing_resistant' => null]);
    }

    /**
     * Build a context whose requirements the checker answers for a subject in a
     * session, its namespaces counted as they are built.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\RequirementResult|\Throwable  $answer
     * @param  array<string, array<string, mixed>>  $values
     * @return \SineMacula\Laravel\Authorization\Evaluation\CheckContext
     */
    private function requirementContext(RequirementResult|\Throwable $answer, array $values = []): CheckContext
    {
        $builders = [];

        foreach ($values as $namespace => $namespaceValues) {
            $builders[$namespace] = function () use ($namespace, $namespaceValues): array {
                $this->builds[$namespace] = ($this->builds[$namespace] ?? 0) + 1;

                return [$namespace => $namespaceValues];
            };
        }

        $user = new \stdClass;

        return new CheckContext([], $builders, new RequirementCheck(new StubRequirementChecker($answer), new Subject($user, $user, session: 'session-1')));
    }

    /**
     * Build a statement allowing `posts:read` on the given resource pattern.
     *
     * @param  string  $pattern
     * @return \SineMacula\Laravel\Authorization\Evaluation\Statement
     */
    private static function allowOn(string $pattern): Statement
    {
        return Statement::fromArray(['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => [$pattern]]);
    }
}
