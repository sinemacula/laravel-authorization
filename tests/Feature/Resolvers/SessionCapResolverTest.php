<?php

declare(strict_types = 1);

namespace Tests\Feature\Resolvers;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Resolvers\SessionCapResolver;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\CredentialScopes;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Concerns\ScopesQueries;
use Tests\Feature\Stubs\AuthenticatableIdentity;
use Tests\Feature\Stubs\CredentialScopesSource;
use Tests\Feature\Stubs\RequestSubjectResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubMachine;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for the session caps a subject's own scopes make (N121): a
 * source reading the scopes the subject resolver filled caps every check about
 * the subject, null and an empty list kept apart, and no two subjects that
 * differ only in their scopes or their platform marker share a cap or a
 * decision.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(SessionCapResolver::class)]
final class SessionCapResolverTest extends TestCase
{
    use ScopesQueries;

    /** @var string The action every credential's scopes name. */
    private const string READ = 'posts:read';

    /** @var string The action no credential's scopes name. */
    private const string CREATE = 'posts:create';

    /** @var \Tests\Feature\Stubs\CredentialScopesSource The source answering each subject's own scopes. */
    private CredentialScopesSource $source;

    /** @var \Tests\Feature\Stubs\StubIdentity The user holding both actions. */
    private StubIdentity $user;

    /**
     * Bind a source answering each subject's own scopes, and grant the user
     * both actions.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->source = new CredentialScopesSource;
        $this->user   = StubIdentity::create(['id' => 'user-1']);

        $this->app?->instance(SessionPolicySource::class, $this->source);
        $this->user->givePermission(Permission::create(['name' => self::READ]));
        $this->user->givePermission(Permission::create(['name' => self::CREATE]));
    }

    /**
     * A subject's scopes cap its checks: a scope allows the action it names and
     * refuses any other, an empty list refuses everything, and a subject naming
     * no credential is not capped; the source is given the subject as it was
     * named.
     *
     * @return void
     */
    public function testTheSubjectsScopesCapItsChecks(): void
    {
        $scoped = new Subject($this->user, $this->user, scopes: CredentialScopes::of([self::READ]));
        $none   = new Subject($this->user, $this->user, scopes: CredentialScopes::of([]));
        $free   = new Subject($this->user, $this->user);

        self::assertTrue(Authorization::for($scoped)->can(self::READ));
        self::assertSame($scoped, \array_pop($this->source->calls));
        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for($scoped)->check(self::CREATE)->reason);
        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for($none)->check(self::READ)->reason);
        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for($none)->check(self::CREATE)->reason);
        self::assertTrue(Authorization::for($free)->can(self::READ));
        self::assertTrue(Authorization::for($free)->can(self::CREATE));
        self::assertSame($free, \array_pop($this->source->calls));
    }

    /**
     * The request's subject is capped by its credential's scopes, and so is its
     * own model named through `for()`, while another model named through
     * `for()` is no request's credential and says nothing of its scopes.
     *
     * @return void
     */
    public function testTheRequestsScopesCapItsChecksButNotAnotherModels(): void
    {
        $other = StubIdentity::create(['id' => 'user-2']);

        $other->givePermission(self::CREATE);

        $this->actAs(new Subject($this->user, $this->user, scopes: CredentialScopes::of([self::READ])));

        self::assertTrue(Authorization::can(self::READ));
        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::check(self::CREATE)->reason);
        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for($this->user)->check(self::CREATE)->reason);
        self::assertTrue(Authorization::for($other)->can(self::CREATE));
        self::assertNull(\array_pop($this->source->calls)?->scopes);
    }

    /**
     * A machine whose subject carries no scopes still fails closed, while one
     * carrying scopes is capped by them, and one carrying none is refused.
     *
     * @return void
     */
    public function testAMachineWithoutScopesStillFailsClosed(): void
    {
        $machine = StubMachine::create(['id' => 'machine-1']);

        $machine->givePermission(self::READ);

        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for(new Subject($machine, $machine))->check(self::READ)->reason);
        self::assertTrue(Authorization::for(new Subject($machine, $machine, scopes: CredentialScopes::of([self::READ])))->can(self::READ));
        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for(new Subject($machine, $machine, scopes: CredentialScopes::of([])))->check(self::READ)->reason);
    }

    /**
     * Subjects about the same model that differ only in their scopes, or only
     * in their platform marker, never share a cap or a decision, however their
     * checks interleave, alone or in a batch.
     *
     * @return void
     */
    public function testSubjectsDifferingOnlyInScopesOrTheMarkerShareNothing(): void
    {
        $tenant = StubTenant::query()->create(['id' => 'tenant-a', 'name' => 'A']);

        $this->user->givePermission(Permission::create(['name' => 'posts:update']), null, $tenant);
        $this->resolveRequest(StubIdentity::create(['id' => 'request-user']), $tenant);

        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager $manager */
        $manager  = Authorization::getFacadeRoot();
        $subjects = [
            [new Subject($this->user, $this->user, scopes: CredentialScopes::of([self::READ])), [true, false, false]],
            [new Subject($this->user, $this->user), [true, true, true]],
            [new Subject($this->user, $this->user, scopes: CredentialScopes::of([])), [false, false, false]],
            [new Subject($this->user, $this->user, platform: true), [true, true, false]],
            [new Subject($this->user, $this->user, scopes: CredentialScopes::of([self::READ, 'posts:update'])), [true, false, true]],
            [new Subject($this->user, $this->user, scopes: CredentialScopes::uncapped()), [true, true, true]],
        ];

        foreach ([1, 2] as $round) {
            foreach ($subjects as $index => [$subject, $expected]) {
                $scoped  = $manager->for($subject);
                $message = "subject {$index}, round {$round}";
                $checks  = [new CheckInput(self::READ), new CheckInput(self::CREATE), new CheckInput('posts:update')];

                self::assertSame($expected, [$scoped->can(self::READ), $scoped->can(self::CREATE), $scoped->can('posts:update')], $message);
                self::assertSame($expected, \array_map(static fn (Decision $decision): bool => $decision->isAllowed(), $scoped->checkMany($checks)), $message);
            }
        }
    }

    /**
     * A hand-built subject naming a session but saying nothing of its scopes is
     * capped by the credential of that session, which the source establishes,
     * and allowed nothing when the source cannot resolve the session; a subject
     * saying its credential carries no cap, or none granted, is answered from
     * what it says.
     *
     * @return void
     */
    public function testASubjectInASessionSayingNothingIsCappedByItsCredential(): void
    {
        $this->bindSource(['session:session-1' => [self::READ]]);

        $session = new Subject($this->user, $this->user, session: 'session-1');
        $unknown = new Subject($this->user, $this->user, session: 'session-unknown');

        self::assertTrue(Authorization::for($session)->can(self::READ));
        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for($session)->check(self::CREATE)->reason);
        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for($unknown)->check(self::READ)->reason);
        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for($unknown)->check(self::CREATE)->reason);
        $uncapped = new Subject($this->user, $this->user, session: 'session-1', scopes: CredentialScopes::uncapped());
        $lifted   = new Subject($this->user, $this->user, session: 'session-unknown', scopes: CredentialScopes::uncapped());
        $nothing  = new Subject($this->user, $this->user, session: 'session-1', scopes: CredentialScopes::of([]));

        self::assertTrue(Authorization::for($uncapped)->can(self::CREATE));
        self::assertTrue(Authorization::for($lifted)->can(self::READ));
        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for($nothing)->check(self::READ)->reason);
    }

    /**
     * A subject with no session whose guard's caller is its own model, the same
     * instance or the same record, names that caller's credential, so it is
     * capped by its scopes, and allowed nothing when the source does not know
     * them; one whose guard's caller is another model names no credential and
     * is not capped.
     *
     * @return void
     */
    public function testAGuardsOwnCallerIsCappedByItsCredential(): void
    {
        $caller = AuthenticatableIdentity::create(['id' => 'caller-1']);
        $other  = AuthenticatableIdentity::create(['id' => 'caller-2']);

        $caller->givePermission(self::READ);
        $caller->givePermission(self::CREATE);
        $other->givePermission(self::CREATE);
        $this->bindSource(['guard:web' => [self::READ]]);
        $this->actingAs($caller, 'web');

        $fresh = AuthenticatableIdentity::query()->findOrFail('caller-1');

        self::assertTrue(Authorization::for(new Subject($caller, $caller, guard: 'web'))->can(self::READ));
        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for(new Subject($caller, $caller, guard: 'web'))->check(self::CREATE)->reason);
        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for(new Subject($fresh, $fresh, guard: 'web'))->check(self::CREATE)->reason);
        self::assertTrue(Authorization::for(new Subject($other, $other, guard: 'web'))->can(self::CREATE));
        self::assertTrue(Authorization::for(new Subject($caller, $caller))->can(self::CREATE));

        $this->bindSource();

        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for(new Subject($caller, $caller, guard: 'web'))->check(self::READ)->reason);
        self::assertTrue(Authorization::for(new Subject($other, $other, guard: 'web'))->can(self::CREATE));
    }

    /**
     * A job's subject names no credential, no session and no guard, so a person
     * is not capped while a machine is still allowed nothing, whatever
     * credentials the source knows.
     *
     * @return void
     */
    public function testAJobsSubjectIsNotCappedButAMachineFailsClosed(): void
    {
        $machine = StubMachine::create(['id' => 'machine-2']);

        $machine->givePermission(self::READ);
        $this->bindSource(['session:session-1' => [self::READ]]);

        self::assertTrue(Authorization::for(new Subject($this->user, $this->user, platform: true))->can(self::CREATE));
        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for(new Subject($machine, $machine, platform: true))->check(self::READ)->reason);
        self::assertNull(\array_pop($this->source->calls)?->session);
    }

    /**
     * Resolve the subject given as the request's, and build the manager afresh
     * for it.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return void
     */
    private function actAs(Subject $subject): void
    {
        $this->app?->instance(SubjectResolver::class, new RequestSubjectResolver($subject));

        foreach (['authorization', AuthorizationManager::class, ResolvedTenant::class] as $abstract) {
            $this->app?->forgetInstance($abstract);
        }

        Authorization::clearResolvedInstance('authorization');
    }

    /**
     * Bind a source knowing the credentials given, and build the manager afresh
     * for it.
     *
     * @param  array<string, list<string>|null>  $credentials
     * @return void
     */
    private function bindSource(array $credentials = []): void
    {
        $this->source = new CredentialScopesSource($credentials);

        $this->app?->instance(SessionPolicySource::class, $this->source);

        foreach (['authorization', AuthorizationManager::class] as $abstract) {
            $this->app?->forgetInstance($abstract);
        }

        Authorization::clearResolvedInstance('authorization');
    }
}
