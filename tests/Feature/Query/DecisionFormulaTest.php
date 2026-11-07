<?php

declare(strict_types = 1);

namespace Tests\Feature\Query;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\CheckSources;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\PrincipalSelectors;
use SineMacula\Laravel\Authorization\Evaluation\SessionCaps;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Query\DecisionFormula;
use SineMacula\Laravel\Authorization\Query\QueryAuthorizer;
use SineMacula\Laravel\Authorization\Query\ResourceShape;
use SineMacula\Laravel\Authorization\Query\SchemaInspector;
use SineMacula\Laravel\Authorization\Query\StatementScreen;
use SineMacula\Laravel\Authorization\Subject;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\TestCase;

/**
 * Feature tests for the condition a class's sources compile to, stage by stage
 * as the policy evaluator weighs them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(DecisionFormula::class)]
final class DecisionFormulaTest extends TestCase
{
    /** @var string The action every formula is compiled for. */
    private const string ACTION = 'posts:view';

    /**
     * An allow that matches allows, a deny that applies keeps the row out, and
     * a permission held allows without any allow; nothing allows no row.
     *
     * @return void
     */
    public function testTheDeniesAndTheAllowsAreWeighed(): void
    {
        [$screen, $subject] = $this->screen();
        $key                = self::key();
        $allow              = new Policy('allow', [new Statement(PolicyEffect::ALLOW, [self::ACTION])]);
        $deny               = new Policy('deny', [new Statement(PolicyEffect::DENY, [self::ACTION], [self::type() . ':5'])]);

        self::assertSame([QueryAuthorizer::EVERY_ROW, false], DecisionFormula::of(self::ACTION, $screen, $this->sources($subject, [$allow]), false));
        self::assertSame([QueryAuthorizer::NO_ROW, false], DecisionFormula::of(self::ACTION, $screen, $this->sources($subject, []), false));
        self::assertSame([QueryAuthorizer::EVERY_ROW, false], DecisionFormula::of(self::ACTION, $screen, $this->sources($subject, []), true));
        self::assertSame(["NOT COALESCE({$key} = 5, 1 = 1)", true], DecisionFormula::of(self::ACTION, $screen, $this->sources($subject, [$allow, $deny]), false));
        self::assertSame([QueryAuthorizer::NO_ROW, false], DecisionFormula::of('posts:edit', $screen, $this->sources($subject, [$allow, $deny]), false));
    }

    /**
     * Every guardrail and boundary must have a matching allow; with the
     * guardrails exempt, or none, they cap nothing; a session cap that does not
     * cover the action allows nothing.
     *
     * @return void
     */
    public function testTheCapsAreIntersected(): void
    {
        [$screen, $subject] = $this->screen();
        $allow              = new Policy('allow', [new Statement(PolicyEffect::ALLOW, [self::ACTION])]);
        $cap                = new Policy('cap', [new Statement(PolicyEffect::ALLOW, ['posts:*'], [self::type() . ':5'])]);
        $closed             = new Policy('closed', [new Statement(PolicyEffect::ALLOW, ['other:*'])]);
        $key                = self::key();

        self::assertSame(["{$key} = 5", true], DecisionFormula::of(self::ACTION, $screen, $this->sources($subject, [$allow], [$cap]), false));
        self::assertSame([QueryAuthorizer::NO_ROW, false], DecisionFormula::of(self::ACTION, $screen, $this->sources($subject, [$allow], [$closed]), false));
        self::assertSame([QueryAuthorizer::EVERY_ROW, false], DecisionFormula::of(self::ACTION, $screen, $this->sources($subject, [$allow], null), false));
        self::assertSame(["{$key} = 5", true], DecisionFormula::of(self::ACTION, $screen, $this->sources($subject, [$allow], [], [$cap]), false));
        $session = fn (string $pattern): CheckSources => $this->sources($subject, [$allow], [], [], [['cap', [$pattern]]]);

        self::assertSame([QueryAuthorizer::NO_ROW, false], DecisionFormula::of(self::ACTION, $screen, $session('other:*'), false));
        self::assertSame([QueryAuthorizer::EVERY_ROW, false], DecisionFormula::of(self::ACTION, $screen, $session('posts:*'), false));
    }

    /**
     * A policy attached to records weighs where it is attached: its deny on
     * everyone, its allow on the subjects it names, none of its allows when
     * only its denies count; none of its patterns counts as matched against
     * every row's identifier.
     *
     * @return void
     */
    public function testAnAttachedPolicyWeighsWhereItIsAttached(): void
    {
        [$screen, $subject] = $this->screen();

        /** @var \Tests\Feature\Stubs\StubIdentity $user */
        $user   = $subject->subject;
        $named  = new Statement(PolicyEffect::ALLOW, [self::ACTION], [self::type() . ':*'], principals: [$user->getMorphClass() . ':u1']);
        $other  = new Statement(PolicyEffect::ALLOW, [self::ACTION], principals: [$user->getMorphClass() . ':u2']);
        $denied = new Statement(PolicyEffect::DENY, [self::ACTION]);
        $policy = (new Policy('attached', [$named, $other, $denied]))->withResource(self::type() . ':*');

        self::assertSame(['NOT COALESCE(here, 1 = 1)', false], DecisionFormula::of(self::ACTION, $screen, $this->sources($subject, []), true, [[$policy, 'here', true]]));
        self::assertSame([QueryAuthorizer::NO_ROW, false], DecisionFormula::of(self::ACTION, $screen, $this->sources($subject, []), false, [[$policy, 'here', true]]));

        $allowing = (new Policy('allowing', [$named, $other]))->withResource(self::type() . ':*');

        self::assertSame(['here', false], DecisionFormula::of(self::ACTION, $screen, $this->sources($subject, []), false, [[$allowing, 'here', false]]));
    }

    /**
     * An allow attached to a record and naming another subject grants nothing
     * there, while one naming the subject grants on its own record.
     *
     * @return void
     */
    public function testAnAttachedAllowNamingAnotherSubjectGrantsNothing(): void
    {
        [$screen, $subject] = $this->screen();

        /** @var \Tests\Feature\Stubs\StubIdentity $user */
        $user   = $subject->subject;
        $theirs = (new Policy('theirs', [new Statement(PolicyEffect::ALLOW, [self::ACTION], principals: [$user->getMorphClass() . ':u2'])]))->withResource(self::type() . ':*');
        $ours   = (new Policy('ours', [new Statement(PolicyEffect::ALLOW, [self::ACTION], principals: [$user->getMorphClass() . ':u1'])]))->withResource(self::type() . ':*');

        self::assertSame(['five', false], DecisionFormula::of(self::ACTION, $screen, $this->sources($subject, []), false, [[$theirs, 'four', false], [$ours, 'five', false]]));
        self::assertSame([QueryAuthorizer::NO_ROW, false], DecisionFormula::of(self::ACTION, $screen, $this->sources($subject, []), false, [[$theirs, 'four', false]]));
    }

    /**
     * A deny attached to a record whose own pattern resolves is weighed only
     * where it is attached, so its pattern does not count as matched against
     * every row's identifier; the same deny attached to the type does.
     *
     * @return void
     */
    public function testAnAttachedDenysPatternIsNotMatchedOnEveryRow(): void
    {
        [$screen, $subject] = $this->screen();

        $deny     = new Statement(PolicyEffect::DENY, [self::ACTION], [self::type() . ':1*']);
        $attached = (new Policy('attached-deny', [$deny]))->withResource(self::type() . ':*');
        $typed    = new Policy('typed-deny', [$deny]);

        self::assertFalse(DecisionFormula::of(self::ACTION, $screen, $this->sources($subject, []), true, [[$attached, 'here', true]])[1]);
        self::assertTrue(DecisionFormula::of(self::ACTION, $screen, $this->sources($subject, [$typed]), true)[1]);
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

        return [new StatementScreen(self::ACTION, ResourceShape::of(new ScopedPost, self::ACTION, new SchemaInspector), $subject), $subject];
    }

    /**
     * Return the sources of a class, with the policies, guardrails, boundaries
     * and session caps given.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\Policy>|null  $guardrails
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\Policy>  $boundaries
     * @param  list<array{string, list<string>}>  $session
     * @return \SineMacula\Laravel\Authorization\Evaluation\CheckSources
     */
    private function sources(Subject $subject, array $policies, ?array $guardrails = [], array $boundaries = [], array $session = []): CheckSources
    {
        $context = new CheckContext(['input' => []], [], null, new PrincipalSelectors($subject));

        return new CheckSources($policies, $guardrails, $boundaries, $context, static fn (): ?string => null, new SessionCaps($session));
    }

    /**
     * Return the posts' key, qualified and wrapped.
     *
     * @return string
     */
    private static function key(): string
    {
        return DB::connection()->getQueryGrammar()->wrap('scoped_posts.id');
    }

    /**
     * Return the posts' morph type.
     *
     * @return string
     */
    private static function type(): string
    {
        return (new ScopedPost)->getMorphClass();
    }
}
