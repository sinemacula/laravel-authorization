<?php

declare(strict_types = 1);

namespace Tests\Feature\ForgettingDecisions;

use Illuminate\Contracts\Events\Dispatcher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Feature\Stubs\ChangingRequirementChecker;
use Tests\Feature\Stubs\ChangingSubjectResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for a batch of the authorization manager running when the
 * decisions of the request are forgotten (N112): a batch about the request's
 * subject is about the subject the resolver gives afresh from its next chunk,
 * while a manager naming its subject keeps it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationManager::class)]
final class AuthorizationManagerTest extends TestCase
{
    /** @var string The action a step-up allows. */
    private const string EXPORT = 'reports:export';

    /**
     * Return the batches: about the request's subject, and about a subject
     * named, with whether each of their checks is allowed.
     *
     * @return iterable<string, array{bool, list<bool>}>
     */
    public static function batches(): iterable
    {
        yield 'the request\'s subject' => [false, [true, true, false, false]];
        yield 'a subject named' => [true, [true, true, true, true]];
    }

    /**
     * The session signs out and the decisions are forgotten after the second of
     * four checks, decided two to a chunk: a batch about the request's subject
     * refuses the checks still to come, and one about a subject named through
     * `for()` keeps the session it was named with.
     *
     * @param  bool  $isNamed
     * @param  list<bool>  $expected
     * @return void
     */
    #[DataProvider('batches')]
    public function testABatchFollowsTheRequestsSubjectUnlessItNamesOne(bool $isNamed, array $expected): void
    {
        $user     = StubIdentity::create(['id' => 'user-1']);
        $subject  = new Subject($user, $user, null, null, 'web', 'session-1');
        $resolver = $this->signIn($subject);
        $reported = 0;
        $manager  = Authorization::withPolicies([self::requiringPolicy()]);

        $this->container()->make(Dispatcher::class)->listen(DecisionEvaluated::class, static function () use (&$reported, $resolver, $user): void {
            if (++$reported !== 2) {
                return;
            }

            $resolver->subject = new Subject($user, $user, null, null, 'web');

            Authorization::forgetDecisionsFor('session-1');
        });

        $batch     = $isNamed ? $manager->for($subject) : $manager;
        $decisions = $batch->checkMany(\array_fill(0, 4, new CheckInput(self::EXPORT)));

        self::assertSame($expected, \array_map(static fn (Decision $decision): bool => $decision->isAllowed(), $decisions));
    }

    /**
     * Resolve the subject as the request's, with a checker meeting every
     * requirement asked of a session, the checks decided two to a chunk, and
     * the manager and what it holds built afresh.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return \Tests\Feature\Stubs\ChangingSubjectResolver
     */
    private function signIn(Subject $subject): ChangingSubjectResolver
    {
        $resolver = new ChangingSubjectResolver($subject);
        $app      = $this->container();

        $app->instance(AuthenticationRequirementChecker::class, new ChangingRequirementChecker(RequirementResult::met()));
        $app->instance(SubjectResolver::class, $resolver);
        $app->make('config')->set('authorization.bulk.chunk_size', 2);

        foreach (['authorization', AuthorizationManager::class, CheckContextFactory::class, ResolvedTenant::class] as $abstract) {
            $app->forgetInstance($abstract);
        }

        Authorization::clearResolvedInstance('authorization');

        return $resolver;
    }

    /**
     * Return a policy allowing the export once multifactor is proved.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     */
    private static function requiringPolicy(): EvaluationPolicy
    {
        return EvaluationPolicy::fromArray(['name' => 'step-up', 'statements' => [[
            'sid'        => 'Export',
            'effect'     => 'allow',
            'actions'    => [self::EXPORT],
            'conditions' => ['authentication_requirement' => ['authentication' => ['multifactor' => ['max_age' => 900]]]],
        ]]]);
    }
}
