<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator;
use SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Statement;

/**
 * Coverage for the way `Statement` interpolates its operands and resource
 * patterns when an interpolator is supplied:
 *
 * - A string operator operand is interpolated; a reference that cannot be
 *   resolved makes the condition undecidable rather than comparing against an
 *   empty string.
 * - A non-string operand (integers, booleans, lists) passes through unchanged.
 * - A `like` operand and a resource pattern are interpolated as glob patterns:
 *   substituted values only ever match themselves and literal backslashes stay
 *   literal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(Statement::class)]
final class StatementInterpolationBranchesTest extends TestCase
{
    /** @var string Trace detail for a condition whose reference cannot be resolved. */
    private const string UNRESOLVED_TENANT = 'condition \'tenant\' references a value that cannot be resolved';

    /**
     * A string `eq` operand is interpolated and compared by identity against
     * the context value.
     *
     * @return void
     */
    public function testStringOperandIsInterpolatedInPlace(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['posts:update'],
            'conditions' => ['eq' => ['tenant' => '${principal.id}']],
        ]);

        $principal = self::principal('org-7');

        self::assertTrue($statement->conditionsSatisfiedBy(['tenant' => 'org-7'], new ContextInterpolator, $principal));
        self::assertFalse($statement->conditionsSatisfiedBy(['tenant' => 'org-9'], new ContextInterpolator, $principal));

        $matched = $statement->assess('posts:update', null, ['tenant' => 'org-7'], new ContextInterpolator, $principal);
        self::assertSame(MatchOutcome::MATCHES, $matched->outcome);
        self::assertSame('', $matched->detail);

        $mismatched = $statement->assess('posts:update', null, ['tenant' => 'org-9'], new ContextInterpolator, $principal);
        self::assertSame(MatchOutcome::DOES_NOT_MATCH, $mismatched->outcome);
        self::assertSame('', $mismatched->detail);
    }

    /**
     * Without an interpolator a string operand is compared as written.
     *
     * @return void
     */
    public function testStringOperandIsLiteralWithoutInterpolator(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['posts:update'],
            'conditions' => ['eq' => ['tenant' => '${principal.id}']],
        ]);

        self::assertTrue($statement->conditionsSatisfiedBy(['tenant' => '${principal.id}']));
        self::assertFalse($statement->conditionsSatisfiedBy(['tenant' => 'org-7']));
    }

    /**
     * A string operand embedding a reference that cannot be resolved makes the
     * condition undecidable, even when the context value is the empty string an
     * unresolved token used to become.
     *
     * @return void
     */
    public function testUnresolvedEmbeddedReferenceIsUndecidable(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['posts:update'],
            'conditions' => ['eq' => ['tenant' => 'org-${principal.id}']],
        ]);

        $result = $statement->assess('posts:update', null, ['tenant' => 'org-'], new ContextInterpolator, new \stdClass);

        self::assertSame(MatchOutcome::UNDECIDABLE, $result->outcome);
        self::assertSame(self::UNRESOLVED_TENANT, $result->detail);
        self::assertFalse($statement->conditionsSatisfiedBy(['tenant' => 'org-'], new ContextInterpolator, null));
    }

    /**
     * A string operand of a deny is interpolated, and one whose reference
     * cannot be resolved makes the condition undecidable.
     *
     * @return void
     */
    public function testOperatorOperandIsInterpolatedOrUndecidable(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'deny',
            'actions'    => ['posts:update'],
            'conditions' => ['eq' => ['tenant' => '${principal.id}']],
        ]);

        $matched = $statement->assess('posts:update', null, ['tenant' => 'org-7'], new ContextInterpolator, self::principal('org-7'));
        self::assertSame(MatchOutcome::MATCHES, $matched->outcome);

        $mismatched = $statement->assess('posts:update', null, ['tenant' => 'org-9'], new ContextInterpolator, self::principal('org-7'));
        self::assertSame(MatchOutcome::DOES_NOT_MATCH, $mismatched->outcome);

        $undecidable = $statement->assess('posts:update', null, ['tenant' => ''], new ContextInterpolator, null);
        self::assertSame(MatchOutcome::UNDECIDABLE, $undecidable->outcome);
        self::assertSame(self::UNRESOLVED_TENANT, $undecidable->detail);
    }

    /**
     * A string operand that interpolates to the empty string reaches the
     * operator, which reports it as undecidable with the condition named.
     *
     * @return void
     */
    public function testOperandInterpolatedToEmptyStringIsUndecidable(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['posts:update'],
            'conditions' => ['starts_with' => ['path' => '${context.prefix}']],
        ]);

        $result = $statement->assess('posts:update', null, ['path' => '/docs', 'prefix' => ''], new ContextInterpolator);

        self::assertSame(MatchOutcome::UNDECIDABLE, $result->outcome);
        self::assertSame('condition \'path\': operator \'starts_with\' has an empty operand', $result->detail);
    }

    /**
     * A list operand is never interpolated: its strings, references included,
     * are compared as written.
     *
     * @return void
     */
    public function testListOperandIsNeverInterpolated(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['posts:update'],
            'conditions' => ['in' => ['owner' => ['${principal.id}', 'admin']]],
        ]);

        $principal = self::principal('42');

        self::assertFalse($statement->conditionsSatisfiedBy(['owner' => '42'], new ContextInterpolator, $principal));
        self::assertTrue($statement->conditionsSatisfiedBy(['owner' => '${principal.id}'], new ContextInterpolator, $principal));
    }

    /**
     * A boolean operand passes through verbatim and is compared by identity
     * against the context value, never against its string form.
     *
     * @return void
     */
    public function testScalarOperandPassesThroughInterpolation(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['posts:update'],
            'conditions' => ['eq' => ['flag' => true]],
        ]);

        self::assertTrue($statement->conditionsSatisfiedBy(['flag' => true], new ContextInterpolator, null));
        self::assertFalse($statement->conditionsSatisfiedBy(['flag' => 'true'], new ContextInterpolator, null));
        self::assertFalse($statement->conditionsSatisfiedBy(['flag' => false], new ContextInterpolator, null));
    }

    /**
     * A `like` operand is interpolated as a pattern: a substituted wildcard
     * only matches itself while the pattern's own wildcard keeps its meaning.
     *
     * @return void
     */
    public function testStringLikeOperandEscapesSubstitutedValues(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['posts:update'],
            'conditions' => ['like' => ['path' => '${principal.id}/*']],
        ]);

        $principal = self::principal('*');

        self::assertTrue($statement->conditionsSatisfiedBy(['path' => '*/report'], new ContextInterpolator, $principal));
        self::assertFalse($statement->conditionsSatisfiedBy(['path' => 'team/report'], new ContextInterpolator, $principal));

        $undecidable = $statement->assess('posts:update', null, ['path' => '*/report'], new ContextInterpolator, null);
        self::assertSame(MatchOutcome::UNDECIDABLE, $undecidable->outcome);
        self::assertSame('condition \'path\' references a value that cannot be resolved', $undecidable->detail);
    }

    /**
     * A `like` operand keeps its backslashes literal with and without an
     * interpolator.
     *
     * @return void
     */
    public function testStringLikeOperandKeepsLiteralBackslashes(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['posts:update'],
            'conditions' => ['like' => ['type' => 'App\Models\*']],
        ]);

        self::assertTrue($statement->conditionsSatisfiedBy(['type' => 'App\Models\Post']));
        self::assertFalse($statement->conditionsSatisfiedBy(['type' => 'AppModelsPost']));
        self::assertTrue($statement->conditionsSatisfiedBy(['type' => 'App\Models\Post'], new ContextInterpolator, null));
        self::assertFalse($statement->conditionsSatisfiedBy(['type' => 'AppModelsPost'], new ContextInterpolator, null));
    }

    /**
     * A resource pattern is interpolated as a pattern: a substituted wildcard
     * only matches a literal wildcard in the resource. (A literal `posts:*` is
     * the type alone, which a pattern naming one record never covers.).
     *
     * @return void
     */
    public function testResourcePatternEscapesSubstitutedValues(): void
    {
        $statement = Statement::fromArray([
            'effect'    => 'allow',
            'actions'   => ['posts:update'],
            'resources' => ['posts:${principal.id}'],
        ]);

        $principal = self::principal('4*');

        $matched = $statement->assess('posts:update', 'posts:4*', [], new ContextInterpolator, $principal);
        self::assertSame(MatchOutcome::MATCHES, $matched->outcome);

        $mismatched = $statement->assess('posts:update', 'posts:42', [], new ContextInterpolator, $principal);
        self::assertSame(MatchOutcome::DOES_NOT_MATCH, $mismatched->outcome);
        self::assertSame('action/resource did not match', $mismatched->detail);

        self::assertTrue($statement->matches('posts:update', 'posts:4*', new ContextInterpolator, $principal));
        self::assertFalse($statement->matches('posts:update', 'posts:42', new ContextInterpolator, $principal));
    }

    /**
     * A resource pattern whose reference cannot be resolved is undecidable,
     * unless another pattern of the statement matches.
     *
     * @return void
     */
    public function testUnresolvedResourcePatternIsUndecidable(): void
    {
        $scoped = Statement::fromArray([
            'effect'    => 'deny',
            'actions'   => ['posts:update'],
            'resources' => ['posts:${context.post_id}'],
        ]);

        $undecidable = $scoped->assess('posts:update', 'posts:42', [], new ContextInterpolator);
        self::assertSame(MatchOutcome::UNDECIDABLE, $undecidable->outcome);
        self::assertSame('a resource pattern references a value that cannot be resolved', $undecidable->detail);
        self::assertFalse($scoped->matches('posts:update', 'posts:42', new ContextInterpolator));

        $withFallback = Statement::fromArray([
            'effect'    => 'deny',
            'actions'   => ['posts:update'],
            'resources' => ['posts:${context.post_id}', 'posts:4*'],
        ]);

        self::assertSame(MatchOutcome::MATCHES, $withFallback->assess('posts:update', 'posts:42', [], new ContextInterpolator)->outcome);
        self::assertSame(MatchOutcome::UNDECIDABLE, $withFallback->assess('posts:update', 'posts:99', [], new ContextInterpolator)->outcome);
    }

    /**
     * `${resource.id}` in a condition is unresolved for a resource without a
     * colon, so the condition is undecidable.
     *
     * @return void
     */
    public function testResourceIdWithoutColonIsUndecidable(): void
    {
        $statement = Statement::fromArray([
            'effect'     => 'allow',
            'actions'    => ['posts:update'],
            'conditions' => ['eq' => ['tenant' => '${resource.id}']],
        ]);

        $resolved = $statement->assess('posts:update', 'posts:42', ['tenant' => '42'], new ContextInterpolator);
        self::assertSame(MatchOutcome::MATCHES, $resolved->outcome);

        $undecidable = $statement->assess('posts:update', 'global', ['tenant' => 'global'], new ContextInterpolator);
        self::assertSame(MatchOutcome::UNDECIDABLE, $undecidable->outcome);
        self::assertSame(self::UNRESOLVED_TENANT, $undecidable->detail);
    }

    /**
     * A resource pattern keeps its backslashes literal with and without an
     * interpolator, so fully-qualified class names match as written.
     *
     * @return void
     */
    public function testResourcePatternKeepsLiteralBackslashes(): void
    {
        $statement = Statement::fromArray([
            'effect'    => 'allow',
            'actions'   => ['posts:update'],
            'resources' => ['App\Models\Post:*'],
        ]);

        self::assertTrue($statement->matches('posts:update', 'App\Models\Post:1'));
        self::assertFalse($statement->matches('posts:update', 'AppModelsPost:1'));
        self::assertTrue($statement->matches('posts:update', 'App\Models\Post:1', new ContextInterpolator));
        self::assertFalse($statement->matches('posts:update', 'AppModelsPost:1', new ContextInterpolator));
    }

    /**
     * Build a plain principal exposing the given id as a public property.
     *
     * @param  string  $id
     * @return object
     */
    private static function principal(string $id): object
    {
        $principal     = new \stdClass;
        $principal->id = $id;

        return $principal;
    }
}
