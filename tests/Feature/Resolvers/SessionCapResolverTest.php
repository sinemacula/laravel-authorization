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
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Concerns\ScopesQueries;
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
     * refuses any other, an empty list refuses everything, and null caps
     * nothing; the source is given the subject as it was named.
     *
     * @return void
     */
    public function testTheSubjectsScopesCapItsChecks(): void
    {
        $scoped = new Subject($this->user, $this->user, scopes: [self::READ]);
        $none   = new Subject($this->user, $this->user, scopes: []);
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
     * `for()` is no request's credential and carries none.
     *
     * @return void
     */
    public function testTheRequestsScopesCapItsChecksButNotAnotherModels(): void
    {
        $other = StubIdentity::create(['id' => 'user-2']);

        $other->givePermission(self::CREATE);

        $this->actAs(new Subject($this->user, $this->user, scopes: [self::READ]));

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
        self::assertTrue(Authorization::for(new Subject($machine, $machine, scopes: [self::READ]))->can(self::READ));
        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for(new Subject($machine, $machine, scopes: []))->check(self::READ)->reason);
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
            [new Subject($this->user, $this->user, scopes: [self::READ]), [true, false, false]],
            [new Subject($this->user, $this->user), [true, true, true]],
            [new Subject($this->user, $this->user, scopes: []), [false, false, false]],
            [new Subject($this->user, $this->user, platform: true), [true, true, false]],
            [new Subject($this->user, $this->user, scopes: [self::READ, 'posts:update']), [true, false, true]],
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
}
