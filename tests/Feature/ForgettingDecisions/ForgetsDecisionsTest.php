<?php

declare(strict_types = 1);

namespace Tests\Feature\ForgettingDecisions;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Concerns\ForgetsDecisions;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionMemory;
use SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Resolvers\DefaultPolicyResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Concerns\RefusesThePackage;
use Tests\Feature\Stubs\ChangingRequirementChecker;
use Tests\Feature\Stubs\ChangingSubjectResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for what the authorization manager forgets (N112):
 * `forgetDecisionsFor()`, which has the rest of the request decide afresh once
 * a proof, the session or the tenant changed, and `forgetLastDecision()`, which
 * clears the last decision alone. Neither is a decision, so neither refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversTrait(ForgetsDecisions::class)]
final class ForgetsDecisionsTest extends TestCase
{
    use RefusesThePackage;

    /** @var string The action a step-up allows. */
    private const string EXPORT = 'reports:export';

    /** @var string The action a held permission allows. */
    private const string READ = 'posts:read';

    /** @var string The session the subject signed in with. */
    private const string SESSION = 'session-1';

    /**
     * A denial remembered before a step-up is forgotten once the proof is
     * recorded and the call made: the last decision is gone, and the next check
     * reads the proof afresh and allows, while the denial already returned
     * stands.
     *
     * @return void
     */
    public function testADenialRememberedBeforeAStepUpIsForgotten(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $checker = new ChangingRequirementChecker(RequirementResult::unmet(['multifactor']));
        $manager = $this->signIn($user, $checker)->withPolicies([self::requiringPolicy()]);
        $denial  = $manager->check(self::EXPORT);

        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $denial->reason);

        $checker->answer = RequirementResult::met();

        self::assertSame($denial, $manager->lastDecision());

        $manager->forgetDecisionsFor(self::SESSION);

        self::assertNull($manager->lastDecision());
        self::assertNull($manager->lastDecisionProvenance());

        $allowed = $manager->check(self::EXPORT);

        self::assertTrue($allowed->isAllowed());
        self::assertSame($allowed, $manager->lastDecision());
        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $denial->reason);
        self::assertSame(2, $checker->calls);
    }

    /**
     * An allow remembered before a proof is revoked is forgotten once the call
     * is made, and the next check refuses; the events already dispatched are
     * not retracted.
     *
     * @return void
     */
    public function testAnAllowRememberedBeforeAProofIsRevokedIsForgotten(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $checker = new ChangingRequirementChecker(RequirementResult::met());
        $manager = $this->signIn($user, $checker)->withPolicies([self::requiringPolicy()]);
        $events  = [];

        $this->container()->make(Dispatcher::class)->listen(DecisionEvaluated::class, static function (DecisionEvaluated $event) use (&$events): void {
            $events[] = $event->reason;
        });

        $allowed = $manager->check(self::EXPORT);

        self::assertTrue($allowed->isAllowed());

        $checker->answer = RequirementResult::unmet(['multifactor']);

        $manager->forgetDecisionsFor(self::SESSION, $user);

        self::assertNull($manager->lastDecision());

        $refused = $manager->check(self::EXPORT);

        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $refused->reason);
        self::assertTrue($allowed->isAllowed());
        self::assertSame([null, DecisionReason::INSUFFICIENT_AUTHENTICATION], $events);
    }

    /**
     * The resolution memo is emptied: a grant revoked directly in the database
     * between two checks of the request is seen after the call, not before.
     *
     * @return void
     */
    public function testAGrantRevokedInTheDatabaseIsSeenOnlyAfterTheCall(): void
    {
        $this->signInHolding(StubIdentity::create(['id' => 'user-1']));

        self::assertTrue(Authorization::can(self::READ));

        self::revokeDirectly('user-1');

        self::assertTrue(Authorization::can(self::READ));

        Authorization::forgetDecisionsFor(self::SESSION);

        self::assertFalse(Authorization::can(self::READ));
    }

    /**
     * The persistent store is left as it is: no entry is written or dropped,
     * and no version key bumped, so a check after the call reads the entry the
     * store already held.
     *
     * @return void
     */
    public function testThePersistentStoreIsLeftAsItIs(): void
    {
        $this->container()->make('config')->set('authorization.cache.store', 'array');

        /** @var \Illuminate\Cache\ArrayStore $store */
        $store = Cache::store('array')->getStore();

        $this->signInHolding(StubIdentity::create(['id' => 'user-1']));

        self::assertTrue(Authorization::can(self::READ));

        $held = $store->all();

        self::assertNotSame([], $held);

        Authorization::forgetDecisionsFor(self::SESSION);

        self::assertSame($held, $store->all());

        self::revokeDirectly('user-1');

        self::assertTrue(Authorization::can(self::READ));
    }

    /**
     * The subject, its session and its tenant are read again from the resolver
     * after the call, the grants of the new tenant counting, while a scope put
     * in place with `within()` stays as its caller set it until it ends.
     *
     * @return void
     */
    public function testTheSubjectAndTenantAreReadAgainButAScopeInPlaceIsKept(): void
    {
        $first    = StubTenant::query()->create(['id' => 'tenant-a', 'name' => 'A']);
        $second   = StubTenant::query()->create(['id' => 'tenant-b', 'name' => 'B']);
        $third    = StubTenant::query()->create(['id' => 'tenant-c', 'name' => 'C']);
        $user     = StubIdentity::create(['id' => 'user-1']);
        $resolver = $this->resolveAs(new Subject($user, $user, $first, null, 'web', self::SESSION));

        $user->givePermission(Permission::create(['name' => 'posts:edit']), null, $second);

        self::assertFalse(Authorization::can('posts:edit'));

        $resolver->subject = new Subject($user, $user, $second, null, 'web', 'session-2');

        self::assertSame(['tenant-a'], self::tenantIds());
        self::assertFalse(Authorization::can('posts:edit'));

        TenantScope::within($third, 'admin', static function (): void {
            Authorization::forgetDecisionsFor('session-2');

            self::assertSame(['tenant-c'], self::tenantIds());
            self::assertSame('admin', TenantScope::currentApplication());
        });

        self::assertSame(['tenant-b'], self::tenantIds());
        self::assertTrue(Authorization::can('posts:edit'));
        self::assertSame('session-2', Authorization::currentSubject()?->session);

        $resolver->subject = new Subject($user, $user, $first, null, 'web', self::SESSION);

        Authorization::forgetDecisionsFor();

        self::assertSame(['tenant-a'], self::tenantIds());
        self::assertFalse(Authorization::can('posts:edit'));
    }

    /**
     * A manager from `for()` keeps the subject it was scoped to after the call,
     * and decides afresh about it, the last decision every clone shares
     * cleared.
     *
     * @return void
     */
    public function testAScopedManagerKeepsItsSubjectAndDecidesAfresh(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $this->signIn($user);

        $other  = StubIdentity::create(['id' => 'other']);
        $scoped = Authorization::for($other);

        $other->givePermission(Permission::create(['name' => self::READ]));

        self::assertTrue($scoped->can(self::READ));

        self::revokeDirectly('other');

        self::assertTrue($scoped->can(self::READ));

        $scoped->forgetDecisionsFor(null, $other);

        self::assertNull(Authorization::lastDecision());
        self::assertSame($other, $scoped->currentSubject()?->subject);
        self::assertFalse($scoped->can(self::READ));
        self::assertSame($user, Authorization::currentSubject()?->subject);
    }

    /**
     * Return what the call names as changed: a session, an identity, both or
     * neither.
     *
     * @return iterable<string, array{string|null, bool}>
     */
    public static function provideWhatChanged(): iterable
    {
        yield 'neither' => [null, false];
        yield 'a session' => [self::SESSION, false];
        yield 'an identity' => [null, true];
        yield 'both' => [self::SESSION, true];
    }

    /**
     * Whatever names what changed, a session, an identity, both or neither,
     * everything is forgotten: the last decision, the memo and the tenant the
     * request resolved, and the generation moves on.
     *
     * @param  string|null  $session
     * @param  bool  $isNamingIdentity
     * @return void
     */
    #[DataProvider('provideWhatChanged')]
    public function testEverythingIsForgottenWhateverTheArgumentsName(?string $session, bool $isNamingIdentity): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $this->signInHolding($user);

        self::assertTrue(Authorization::can(self::READ));

        $tenant     = $this->container()->make(ResolvedTenant::class);
        $generation = DecisionMemory::current()->generation();

        self::revokeDirectly('user-1');

        Authorization::forgetDecisionsFor($session, $isNamingIdentity ? $user : null);

        self::assertNull(Authorization::lastDecision());
        self::assertSame($generation + 1, DecisionMemory::current()->generation());
        self::assertNotSame($tenant, $this->container()->make(ResolvedTenant::class));
        self::assertFalse(Authorization::can(self::READ));
    }

    /**
     * Forgetting is no decision, so a manager obtained before the package
     * refused forgets while it refuses, and refuses its decisions still.
     *
     * @return void
     */
    public function testForgettingIsNotRefusedWhileThePackageRefuses(): void
    {
        $this->signInHolding(StubIdentity::create(['id' => 'user-1']));

        self::assertTrue(Authorization::can(self::READ));

        $store = $this->container()->make(LastDecisionStore::class);

        $this->refuseThePackage();

        Authorization::forgetDecisionsFor(self::SESSION);

        self::assertNull($store->get());

        $store->put(Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT), DecisionProvenance::of(null));

        Authorization::forgetLastDecision();

        self::assertNull($store->get());
        self::assertEachRefused(['check' => static fn (): Decision => Authorization::check(self::READ)]);
    }

    /**
     * A manager built outside an application that registered the package
     * forgets as any other does.
     *
     * @return void
     */
    public function testAManagerBuiltDirectlyForgets(): void
    {
        $user  = StubIdentity::create(['id' => 'user-1']);
        $store = new LastDecisionStore;

        $user->givePermission(Permission::create(['name' => self::READ]));

        $manager = new AuthorizationManager(new PolicyEvaluator, $this->resolveAs(new Subject($user, $user)), new DefaultPolicyResolver, $store);

        self::assertTrue($manager->can(self::READ));
        self::assertNotNull($store->get());

        $manager->forgetDecisionsFor();

        self::assertNull($store->get());
        self::assertNull($store->provenance());
    }

    /**
     * `forgetLastDecision()` clears the last decision alone: the memo is kept,
     * so a grant revoked directly in the database is still not seen, and the
     * generation stays where it was.
     *
     * @return void
     */
    public function testForgettingTheLastDecisionClearsItAlone(): void
    {
        $this->signInHolding(StubIdentity::create(['id' => 'user-1']));

        self::assertTrue(Authorization::can(self::READ));

        $generation = DecisionMemory::current()->generation();

        self::revokeDirectly('user-1');

        Authorization::forgetLastDecision();

        self::assertNull(Authorization::lastDecision());
        self::assertSame($generation, DecisionMemory::current()->generation());
        self::assertTrue(Authorization::can(self::READ));
    }

    /**
     * Resolve the user as the request's subject in the session, holding the
     * read permission platform-wide.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @return void
     */
    private function signInHolding(StubIdentity $user): void
    {
        $user->givePermission(Permission::create(['name' => self::READ]));

        $this->signIn($user);
    }

    /**
     * Resolve the user as the request's subject in the session, with the
     * checker bound when one is given, and return a manager built afresh.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  \SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker|null  $checker
     * @return \SineMacula\Laravel\Authorization\AuthorizationManager
     */
    private function signIn(StubIdentity $user, ?AuthenticationRequirementChecker $checker = null): AuthorizationManager
    {
        if ($checker !== null) {
            $this->container()->instance(AuthenticationRequirementChecker::class, $checker);
        }

        $this->resolveAs(new Subject($user, $user, null, null, 'web', self::SESSION));

        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager */
        return $this->container()->make(AuthorizationManager::class);
    }

    /**
     * Bind a resolver answering the subject, which the test may change, with
     * the manager and what it holds built afresh.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return \Tests\Feature\Stubs\ChangingSubjectResolver
     */
    private function resolveAs(Subject $subject): ChangingSubjectResolver
    {
        $resolver = new ChangingSubjectResolver($subject);
        $app      = $this->container();

        $app->instance(SubjectResolver::class, $resolver);

        foreach (['authorization', AuthorizationManager::class, CheckContextFactory::class, ResolvedTenant::class] as $abstract) {
            $app->forgetInstance($abstract);
        }

        Authorization::clearResolvedInstance('authorization');

        return $resolver;
    }

    /**
     * Revoke every permission the grantee holds directly in the database, past
     * the package, so nothing it remembers is told.
     *
     * @param  string  $grantee
     * @return void
     */
    private static function revokeDirectly(string $grantee): void
    {
        DB::table('authorizable_permissions')->where('authorizable_id', $grantee)->delete();
    }

    /**
     * Return the id of the tenant checks are decided in now, or none for the
     * platform.
     *
     * @return list<string>
     */
    private static function tenantIds(): array
    {
        $tenant = TenantScope::currentTenant();

        return $tenant === null ? [] : [$tenant[1]];
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
