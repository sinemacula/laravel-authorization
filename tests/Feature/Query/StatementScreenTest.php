<?php

declare(strict_types = 1);

namespace Tests\Feature\Query;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\PrincipalSelectors;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Query\QueryAuthorizer;
use SineMacula\Laravel\Authorization\Query\Refusal;
use SineMacula\Laravel\Authorization\Query\ResourceShape;
use SineMacula\Laravel\Authorization\Query\SchemaInspector;
use SineMacula\Laravel\Authorization\Query\StatementScreen;
use SineMacula\Laravel\Authorization\Subject;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Fixtures\QueryScoping\InvariantRequirementChecker;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\TestCase;

/**
 * Feature tests for the screen that compiles each statement one class of rows
 * is decided from, or refuses it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(StatementScreen::class)]
final class StatementScreenTest extends TestCase
{
    /**
     * A statement with no resources matches and applies to every row, its
     * conditions holding, and matches none when they do not.
     *
     * @return void
     */
    public function testAStatementWithoutResourcesNamesEveryRow(): void
    {
        [$screen, $subject] = $this->screen();

        self::assertSame([QueryAuthorizer::EVERY_ROW, QueryAuthorizer::EVERY_ROW, false], $this->terms($screen, $subject, new Statement(PolicyEffect::ALLOW, ['posts:view'])));
        $failing = new Statement(PolicyEffect::ALLOW, ['posts:view'], null, ['eq' => ['input.type' => 'other']]);

        self::assertSame([QueryAuthorizer::NO_ROW, QueryAuthorizer::NO_ROW, false], $this->terms($screen, $subject, $failing));
        self::assertSame([], $screen->refusals());
    }

    /**
     * A literal id compares the key, a longer prefix the start of its text, a
     * pattern of another type names no row, and `not_resources` names, both
     * matching and applying to, the rows none of its patterns covers.
     *
     * @return void
     */
    public function testPatternsCompareTheKey(): void
    {
        [$screen, $subject] = $this->screen();
        $key                = DB::connection()->getQueryGrammar()->wrap('scoped_posts.id');

        [$matches, $applies, $isPatterned] = $this->terms($screen, $subject, new Statement(PolicyEffect::ALLOW, ['posts:view'], [self::type() . ':5']));

        self::assertSame("{$key} = 5", $matches);
        self::assertSame($matches, $applies);
        self::assertTrue($isPatterned);
        $prefixed = new Statement(PolicyEffect::ALLOW, ['posts:view'], [self::type() . ':1*']);

        self::assertSame(self::shape()->dialect->startsWith($key, '1'), $this->terms($screen, $subject, $prefixed)[0]);
        self::assertSame(QueryAuthorizer::NO_ROW, $this->terms($screen, $subject, new Statement(PolicyEffect::DENY, ['posts:view'], ['other:5']))[1]);
        $negated = new Statement(PolicyEffect::DENY, ['posts:view'], null, notResources: [self::type() . ':5']);

        self::assertSame(["NOT COALESCE({$key} = 5, 1 = 1)", "NOT COALESCE({$key} = 5, 1 = 1)", true], $this->terms($screen, $subject, $negated));
        self::assertSame(QueryAuthorizer::NO_ROW, $this->terms($screen, $subject, new Statement(PolicyEffect::DENY, ['posts:view'], null, notResources: ['*']))[1]);
        self::assertSame([], $screen->refusals());
    }

    /**
     * A pattern whose reference cannot be resolved, or resolves to a NUL byte,
     * makes the target undecidable unless another pattern covers the row: a
     * deny applies, an allow does not match, and no pattern is matched against
     * the identifier when none resolves.
     *
     * @return void
     */
    public function testAnUnresolvedPatternIsUndecidable(): void
    {
        [$screen, $subject] = $this->screen();
        $unresolved         = new Statement(PolicyEffect::DENY, ['posts:view'], ['${input.missing}:*', '${input.nul}']);
        $negated            = new Statement(PolicyEffect::ALLOW, ['posts:view'], null, notResources: ['${input.missing}']);

        self::assertSame([QueryAuthorizer::NO_ROW, QueryAuthorizer::EVERY_ROW, false], $this->terms($screen, $subject, $unresolved));
        self::assertSame([QueryAuthorizer::NO_ROW, QueryAuthorizer::EVERY_ROW, false], $this->terms($screen, $subject, $negated));
        self::assertSame(QueryAuthorizer::EVERY_ROW, $this->terms($screen, $subject, new Statement(PolicyEffect::ALLOW, ['posts:view'], ['${input.type}:*']))[0]);

        $key   = DB::connection()->getQueryGrammar()->wrap('scoped_posts.id');
        $mixed = new Statement(PolicyEffect::ALLOW, ['posts:view'], ['${input.missing}', self::type() . ':5']);

        self::assertSame(["{$key} = 5", QueryAuthorizer::EVERY_ROW, true], $this->terms($screen, $subject, $mixed));
        self::assertSame([], $screen->refusals());
    }

    /**
     * Conditions that cannot be decided keep an allow from matching but let a
     * deny apply, wherever its target does.
     *
     * @return void
     */
    public function testUndecidableConditionsApplyADeny(): void
    {
        [$screen, $subject] = $this->screen();
        $statement          = new Statement(PolicyEffect::DENY, ['posts:view'], [self::type() . ':5'], ['eq' => ['input.absent' => 'x']]);

        [$matches, $applies] = $this->terms($screen, $subject, $statement);

        self::assertSame(QueryAuthorizer::NO_ROW, $matches);
        self::assertStringEndsWith('= 5', $applies);
    }

    /**
     * A pattern no key can be compared with is refused, naming no row though a
     * pattern resolved, and so is a statement that cannot be evaluated once its
     * target names a row; one whose target names none is not.
     *
     * @return void
     */
    public function testWhatCannotBeCompiledIsRefused(): void
    {
        [$screen, $subject] = $this->screen();
        $broken             = ['no_such_operator' => ['input.x' => 1]];

        $question = $this->terms($screen, $subject, new Statement(PolicyEffect::DENY, ['posts:view'], [self::type() . ':?']), 'question');
        $this->terms($screen, $subject, new Statement(PolicyEffect::ALLOW, ['posts:view'], null, $broken, notResources: ['*']), 'unreached');
        $this->terms($screen, $subject, new Statement(PolicyEffect::ALLOW, ['posts:view'], ['other:1'], $broken), 'elsewhere');
        $this->terms($screen, $subject, new Statement(PolicyEffect::ALLOW, ['posts:view'], null, $broken), 'broken');
        $this->terms($screen, $subject, new Statement(PolicyEffect::ALLOW, ['posts:view'], [self::type() . ':9223372036854775808']), 'beyond');

        $refused = \array_map(static fn (Refusal $refusal): array => [$refusal->statement, $refusal->reason], $screen->refusals());

        $expected = [['question#0', RefusalReason::RESOURCE_PATTERN], ['broken#0', RefusalReason::INVALID_STATEMENT], ['beyond#0', RefusalReason::RESOURCE_PATTERN]];

        self::assertSame($expected, $refused);
        self::assertSame([QueryAuthorizer::NO_ROW, QueryAuthorizer::NO_ROW, true], $question);
    }

    /**
     * Without a context factory a check reads only what the caller passes and
     * the subject's built-ins, so only a read of the resource is refused,
     * whether in a condition's key, a string operand or a pattern; a refused
     * statement names no row, and no pattern is matched for it.
     *
     * @return void
     */
    public function testWithoutAFactoryOnlyTheResourceIsRefused(): void
    {
        [$screen, $subject] = $this->screen();

        $this->terms($screen, $subject, new Statement(PolicyEffect::DENY, ['posts:view'], null, ['eq' => ['plan.tier' => 'pro', 'subject.id' => '${request.ip}']]));
        $owner = $this->terms($screen, $subject, new Statement(PolicyEffect::DENY, ['posts:view'], null, ['eq' => ['input.owner' => '${resource.owner}']]));
        $this->terms($screen, $subject, new Statement(PolicyEffect::DENY, ['posts:view'], [self::type() . ':${resource.id}']));

        self::assertSame(['resource.owner', 'resource.id'], \array_map(static fn (Refusal $refusal): ?string => $refusal->key, $screen->refusals()));
        $reasons = \array_map(static fn (Refusal $refusal): RefusalReason => $refusal->reason, $screen->refusals());

        self::assertSame([RefusalReason::RESOURCE_NAMESPACE, RefusalReason::RESOURCE_NAMESPACE], $reasons);
        self::assertSame([QueryAuthorizer::NO_ROW, QueryAuthorizer::NO_ROW, false], $owner);
    }

    /**
     * An authentication requirement does not end the screening of its
     * statement: a read of the resource after it is still refused, with or
     * without a context factory, and with a checker marked `ScopeInvariant`.
     *
     * @return void
     */
    public function testAReadAfterARequirementIsStillScreened(): void
    {
        [$screen, $subject] = $this->screen();

        $this->app?->instance(AuthenticationRequirementChecker::class, new InvariantRequirementChecker(true));
        $this->app?->forgetInstance(CheckContextFactory::class);

        /** @var \SineMacula\Laravel\Authorization\Context\CheckContextFactory $factory */
        $factory    = $this->app?->make(CheckContextFactory::class);
        $conditions = ['authentication_requirement' => ['authentication' => ['multifactor' => []]], 'eq' => ['resource.status' => 'draft']];

        foreach ([$screen, new StatementScreen('posts:view', self::shape(), $subject, $factory)] as $screening) {
            $this->terms($screening, $subject, new Statement(PolicyEffect::DENY, ['posts:view'], null, $conditions));

            $refused = \array_map(static fn (Refusal $refusal): array => [$refusal->key, $refusal->reason], $screening->refusals());

            self::assertSame([['resource.status', RefusalReason::RESOURCE_NAMESPACE]], $refused);
        }
    }

    /**
     * Without a context factory a check judges no requirement through a seam,
     * so a statement whose only condition is one compiles, unmet on every row,
     * its pattern still matched against the identifier.
     *
     * @return void
     */
    public function testWithoutAFactoryARequirementCompiles(): void
    {
        [$screen, $subject] = $this->screen();

        $requirement = ['authentication_requirement' => ['authentication' => ['multifactor' => []]]];
        $statement   = new Statement(PolicyEffect::ALLOW, ['posts:view'], [self::type() . ':*'], $requirement);

        self::assertSame([QueryAuthorizer::NO_ROW, QueryAuthorizer::NO_ROW, true], $this->terms($screen, $subject, $statement));
        self::assertSame([], $screen->refusals());
    }

    /**
     * Return a screen of `posts:view` on posts, for a stored subject.
     *
     * @return array{\SineMacula\Laravel\Authorization\Query\StatementScreen, \SineMacula\Laravel\Authorization\Subject}
     */
    private function screen(): array
    {
        $user    = StubIdentity::create(['id' => 'u1']);
        $subject = new Subject($user, $user);

        return [new StatementScreen('posts:view', self::shape(), $subject), $subject];
    }

    /**
     * Return the terms the screen compiles for the statement, as a policy of
     * the name given holds it, with the caller's input.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\StatementScreen  $screen
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @param  string  $policy
     * @return array{string, string, bool}
     */
    private function terms(StatementScreen $screen, Subject $subject, Statement $statement, string $policy = 'policy'): array
    {
        $context = new CheckContext(['input' => ['type' => self::type(), 'nul' => "a\0b"]], [], null, new PrincipalSelectors($subject));

        return $screen->terms(new StatementReference($policy, 0), $statement, $context);
    }

    /**
     * Return the shape of the posts screened.
     *
     * @return \SineMacula\Laravel\Authorization\Query\ResourceShape
     */
    private static function shape(): ResourceShape
    {
        return ResourceShape::of(new ScopedPost, 'posts:view', new SchemaInspector);
    }

    /**
     * Return the morph type of the posts screened.
     *
     * @return string
     */
    private static function type(): string
    {
        return (new ScopedPost)->getMorphClass();
    }
}
