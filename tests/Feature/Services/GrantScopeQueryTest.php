<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Enums\GrantPresence;
use SineMacula\Laravel\Authorization\Enums\GrantScopeStatus;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GrantScopeQuery;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\RefusesThePackage;
use Tests\Feature\Stubs\RecordingLogger;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubMachine;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\Fixtures\GrantScope\ListedIdentityDirectory;
use Tests\Fixtures\GrantScope\UnreadableTenantTree;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\Fixtures\QueryScoping\SubtreeQueryTree;
use Tests\TestCase;

/**
 * Feature tests for the grant scope query (AUTHZ-14.2) and the principal
 * presence helper (AUTHZ-13.8), over a closure-table tree of two organisations,
 * the first with two accounts and a team below the first account, and over the
 * flat tree.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(GrantScopeQuery::class)]
final class GrantScopeQueryTest extends TestCase
{
    use RefusesThePackage;

    /** @var string The tenants' morph type. */
    private const string TENANT = 'tenant';

    /** @var string What the log line of a tree that cannot be read starts with. */
    private const string UNREADABLE = 'Authorization: the tenant tree could not be read for a grant scope query: ';

    /**
     * Provide each kind of grant: a role, a permission granted directly and a
     * policy attached, one that only denies.
     *
     * @return iterable<string, array{string}>
     */
    public static function kindProvider(): iterable
    {
        yield 'a role' => ['role'];
        yield 'a permission' => ['permission'];
        yield 'a deny-only policy' => ['policy'];
    }

    /**
     * A grant of each kind rooted at the tenant, or below it, node-only or
     * reaching its subtree, is within.
     *
     * @param  string  $kind
     * @return void
     */
    #[DataProvider('kindProvider')]
    public function testAGrantAtTheTenantOrBelowIsWithin(string $kind): void
    {
        $this->tree();

        $identity = self::identity('identity');

        self::grant($identity, $kind, self::tenant('org1'));
        self::grant($identity, $kind, self::tenant('acct1'), false);
        self::grant($identity, $kind, self::tenant('team1'));

        self::assertSame(GrantScopeStatus::WITHIN, self::scopes()->forIdentity(Reference::of($identity), self::tenant('org1')));
        self::assertSame(GrantScopeStatus::OUTSIDE, self::scopes()->forIdentity(Reference::of($identity), self::tenant('acct1')));
    }

    /**
     * A grant of each kind rooted at an ancestor, reaching its subtree or not,
     * at a sibling, at another organisation or at the platform, is outside.
     *
     * @param  string  $kind
     * @return void
     */
    #[DataProvider('kindProvider')]
    public function testAGrantRootedOutsideTheTenantIsOutside(string $kind): void
    {
        $roots = [
            'an ancestor subtree'  => [self::tenant('org1'), true],
            'an ancestor node'     => [self::tenant('org1'), false],
            'a sibling'            => [self::tenant('acct2'), true],
            'another organisation' => [self::tenant('org2'), true],
            'the platform'         => [null, true],
        ];

        $this->tree();

        foreach ($roots as $root => [$tenant, $isSubtree]) {
            $identity = self::identity('identity-' . \count(StubIdentity::query()->get()));

            self::grant($identity, $kind, self::tenant('acct1'));
            self::grant($identity, $kind, $tenant, $isSubtree);

            self::assertSame(GrantScopeStatus::OUTSIDE, self::scopes()->forIdentity(Reference::of($identity), self::tenant('acct1')), $root);
        }
    }

    /**
     * On the flat tree a grant applies only in its own tenant, so only a grant
     * at the tenant itself is within.
     *
     * @return void
     */
    public function testTheFlatTreeHoldsOnlyTheTenantWithin(): void
    {
        $this->app?->instance(IdentityDirectory::class, new ListedIdentityDirectory);

        $identity = self::identity('identity');

        self::grant($identity, 'role', self::tenant('acct1'));

        self::assertSame(GrantScopeStatus::WITHIN, self::scopes()->forIdentity(Reference::of($identity), self::tenant('acct1')));
        self::assertSame(GrantScopeStatus::OUTSIDE, self::scopes()->forIdentity(Reference::of($identity), self::tenant('org1')));
    }

    /**
     * An identity with no grants, and no principals holding any, is within when
     * the directory's list is complete, and unknown when it is not.
     *
     * @return void
     */
    public function testNoGrantsIsWithinOnlyWithACompleteDirectory(): void
    {
        $this->tree();

        $identity = Reference::of(self::identity('identity'));

        self::assertSame(GrantScopeStatus::WITHIN, self::scopes()->forIdentity($identity, self::tenant('acct1')));

        $this->app?->instance(IdentityDirectory::class, new ListedIdentityDirectory(isComplete: false));

        self::assertSame(GrantScopeStatus::UNKNOWN, self::scopes()->forIdentity($identity, self::tenant('acct1')));
    }

    /**
     * An incomplete directory gives unknown though every grant read is within,
     * and outside when a grant of a principal it does know is outside.
     *
     * @return void
     */
    public function testAnIncompleteDirectoryIsUnknownUnlessAGrantIsOutside(): void
    {
        $this->tree();

        $identity = self::identity('identity');
        $known    = self::identity('principal');

        self::grant($identity, 'role', self::tenant('acct1'));

        $this->app?->instance(IdentityDirectory::class, self::directory($identity, [$known], false));

        self::assertSame(GrantScopeStatus::UNKNOWN, self::scopes()->forIdentity(Reference::of($identity), self::tenant('acct1')));

        self::grant($known, 'permission', self::tenant('acct2'));

        self::assertSame(GrantScopeStatus::OUTSIDE, self::scopes()->forIdentity(Reference::of($identity), self::tenant('acct1')));
    }

    /**
     * The grants of every principal the directory lists count with the
     * identity's own, and those of a principal it does not list do not.
     *
     * @return void
     */
    public function testTheGrantsOfEveryPrincipalListedCount(): void
    {
        $this->tree();

        $identity = self::identity('identity');
        $first    = self::identity('principal-1');
        $second   = new StubSecondIdentity(['id' => 'principal-2']);
        $other    = self::identity('principal-3');

        $second->save();

        $this->app?->instance(IdentityDirectory::class, self::directory($identity, [$first, $second]));

        self::grant($first, 'role', self::tenant('acct1'));
        self::grant($other, 'role', null);

        self::assertSame(GrantScopeStatus::WITHIN, self::scopes()->forIdentity(Reference::of($identity), self::tenant('acct1')));

        self::grant($second, 'policy', self::tenant('org2'));

        self::assertSame(GrantScopeStatus::OUTSIDE, self::scopes()->forIdentity(Reference::of($identity), self::tenant('acct1')));
    }

    /**
     * Containment spans every application: a grant made for one application
     * counts as one made for all.
     *
     * @return void
     */
    public function testEveryApplicationCounts(): void
    {
        $this->tree();

        $identity = self::identity('identity');

        self::grant($identity, 'permission', self::tenant('acct1'), application: 'admin');

        self::assertSame(GrantScopeStatus::WITHIN, self::scopes()->forIdentity(Reference::of($identity), self::tenant('acct1')));

        self::grant($identity, 'role', self::tenant('acct2'), application: 'mobile');

        self::assertSame(GrantScopeStatus::OUTSIDE, self::scopes()->forIdentity(Reference::of($identity), self::tenant('acct1')));
    }

    /**
     * A grantee of another type sharing the identity's key is another grantee:
     * its grants never count for the identity.
     *
     * @return void
     */
    public function testAGranteeSharingTheKeyUnderAnotherTypeDoesNotCount(): void
    {
        $this->tree();

        $identity = self::identity('shared-key');
        $other    = new StubSecondIdentity(['id' => 'shared-key']);

        $other->save();

        self::grant($identity, 'role', self::tenant('acct1'));
        self::grant($other, 'role', null);
        self::grant($other, 'policy', self::tenant('org2'));

        self::assertSame(GrantScopeStatus::WITHIN, self::scopes()->forIdentity(Reference::of($identity), self::tenant('acct1')));
        self::assertSame(GrantScopeStatus::OUTSIDE, self::scopes()->forIdentity(Reference::of($other), self::tenant('acct1')));
    }

    /**
     * An expired grant is no grant: outside while it holds, and within once it
     * has expired.
     *
     * @return void
     */
    public function testAnExpiredGrantDoesNotCount(): void
    {
        $this->tree();

        Carbon::setTestNow('2026-07-01 12:00:00');

        $identity = self::identity('identity');

        self::grant($identity, 'permission', null, expiresAt: Carbon::parse('2026-07-01 13:00:00'));

        self::assertSame(GrantScopeStatus::OUTSIDE, self::scopes()->forIdentity(Reference::of($identity), self::tenant('acct1')));

        Carbon::setTestNow('2026-07-01 13:00:01');

        self::assertSame(GrantScopeStatus::WITHIN, self::scopes()->forIdentity(Reference::of($identity), self::tenant('acct1')));

        Carbon::setTestNow();
    }

    /**
     * Boundaries and guardrails constrain grants and are not grants, and a
     * role's own policy attachments are the role's, not the identity's: none of
     * them is outside.
     *
     * @return void
     */
    public function testBoundariesGuardrailsAndRoleAttachmentsAreNotGrants(): void
    {
        $this->tree();

        $identity = self::identity('identity');
        $role     = Role::create(['name' => 'scoped']);
        $policy   = self::denying('capped');

        $identity->assignRole($role, null, self::tenant('acct1'));
        $role->attachPolicy(self::denying('role-policy'));

        $this->app?->make(BoundaryService::class)->set($identity, $policy);

        DB::table('guardrails')->insert(['policy_id' => $policy->getKey(), 'tenant_type' => null, 'tenant_id' => null]);

        self::assertSame(GrantScopeStatus::WITHIN, self::scopes()->forIdentity(Reference::of($identity), self::tenant('acct1')));
    }

    /**
     * A grant row naming half a tenant cannot be read, so it gives unknown,
     * unless another grant is proven outside.
     *
     * @return void
     */
    public function testARowNamingHalfATenantIsUnknown(): void
    {
        $this->tree();

        $identity = self::identity('identity');

        DB::table('authorizable_permissions')->insert([
            'permission_id'     => Permission::create(['name' => 'half:read'])->getKey(),
            'authorizable_type' => $identity->getMorphClass(),
            'authorizable_id'   => $identity->getKey(),
            'tenant_type'       => self::TENANT,
            'tenant_id'         => null,
            'include_subtree'   => true,
        ]);

        self::assertSame(GrantScopeStatus::UNKNOWN, self::scopes()->forIdentity(Reference::of($identity), self::tenant('acct1')));

        self::grant($identity, 'role', self::tenant('acct2'));

        self::assertSame(GrantScopeStatus::OUTSIDE, self::scopes()->forIdentity(Reference::of($identity), self::tenant('acct1')));
    }

    /**
     * A tree that cannot be read gives unknown, written to the log, unless a
     * platform-wide grant, outside whatever the tree, is found.
     *
     * @return void
     */
    public function testATreeThatCannotBeReadIsUnknown(): void
    {
        $logger = new RecordingLogger;

        $this->app?->instance('log', $logger);

        $this->app?->instance(TenantTree::class, new UnreadableTenantTree);
        $this->app?->instance(IdentityDirectory::class, new ListedIdentityDirectory);

        $identity = self::identity('identity');

        self::grant($identity, 'role', self::tenant('acct1'));

        self::assertSame(GrantScopeStatus::UNKNOWN, self::scopes()->forIdentity(Reference::of($identity), self::tenant('acct1')));
        self::assertSame([[
            'level'   => 'warning',
            'message' => self::UNREADABLE . UnreadableTenantTree::MESSAGE,
            'context' => ['exception' => \RuntimeException::class],
        ]], $logger->records);

        self::grant($identity, 'permission', null);

        self::assertSame(GrantScopeStatus::OUTSIDE, self::scopes()->forIdentity(Reference::of($identity), self::tenant('acct1')));
    }

    /**
     * A subtree query that builds but fails as the grant query runs, over a
     * closure table that is missing, is a tree that cannot be read: written to
     * the log and unknown, unless a platform-wide grant is found. The failure
     * rolls back only the grant query, so the transaction the test runs in
     * stays usable, and the presence helper, which never runs the subtree
     * query, answers from the tree's ancestors as ever.
     *
     * @return void
     */
    public function testASubtreeQueryThatFailsAsItRunsIsUnknown(): void
    {
        $logger = new RecordingLogger;

        $this->tree();

        $this->app?->instance('log', $logger);
        $this->app?->instance(TenantTree::class, new SubtreeQueryTree(static fn (Reference $tenant): Builder => DB::table('grant_scope_missing_closure')
            ->select(['descendant_type as tenant_type', 'descendant_id as tenant_id'])
            ->where('ancestor_type', $tenant->type)
            ->where('ancestor_id', $tenant->id)));

        $identity = self::identity('identity');

        self::grant($identity, 'role', self::tenant('org1'));

        self::assertSame(GrantScopeStatus::UNKNOWN, self::scopes()->forIdentity(Reference::of($identity), self::tenant('acct1')));
        self::assertSame(GrantPresence::PRESENT, self::scopes()->hasGrantIn($identity, self::tenant('acct1')));
        self::assertSame(GrantPresence::ABSENT, self::scopes()->hasGrantIn($identity, self::tenant('org2')));

        self::assertCount(1, $logger->records);
        self::assertSame('warning', $logger->records[0]['level']);
        self::assertStringStartsWith(self::UNREADABLE, $logger->records[0]['message']);
        self::assertStringContainsString('grant_scope_missing_closure', $logger->records[0]['message']);
        self::assertSame(['exception' => QueryException::class], $logger->records[0]['context']);

        self::grant($identity, 'permission', null);

        self::assertSame(GrantScopeStatus::OUTSIDE, self::scopes()->forIdentity(Reference::of($identity), self::tenant('acct1')));
    }

    /**
     * The default directory knows that the shipped subject resolver's user owns
     * no other principal, so its answer is complete; under any other resolver
     * it is not.
     *
     * @return void
     */
    public function testTheDefaultDirectoryIsCompleteOnlyUnderTheShippedResolver(): void
    {
        $identity = self::identity('identity');

        self::grant($identity, 'role', self::tenant('acct1'));

        self::assertInstanceOf(AuthGuardSubjectResolver::class, app(SubjectResolver::class));
        self::assertSame(GrantScopeStatus::WITHIN, self::scopes()->forIdentity(Reference::of($identity), self::tenant('acct1')));

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver);

        self::assertSame(GrantScopeStatus::UNKNOWN, self::scopes()->forIdentity(Reference::of($identity), self::tenant('acct1')));
    }

    /**
     * The tenant may be named by a model or a reference alike, and the answer
     * is the status alone, carrying no tenant, grant or count.
     *
     * @return void
     */
    public function testTheAnswerCarriesNothingButTheStatus(): void
    {
        $this->tree();

        $identity = self::identity('identity');
        $tenant   = StubTenant::query()->create(['id' => 'acct1', 'name' => 'acct1']);

        self::grant($identity, 'role', Reference::of($tenant));
        self::grant($identity, 'policy', self::tenant('secret-tenant'));

        $byModel     = self::scopes()->forIdentity(Reference::of($identity), $tenant);
        $byReference = self::scopes()->forIdentity(Reference::of($identity), Reference::of($tenant));
        $presence    = self::scopes()->hasGrantIn($identity, Reference::of($tenant));

        self::assertSame(GrantScopeStatus::OUTSIDE, $byModel);
        self::assertSame($byModel, $byReference);
        self::assertSame(GrantPresence::PRESENT, $presence);

        foreach ([$byModel, $presence] as $answer) {
            $exported = \var_export($answer, true) . \serialize($answer) . \json_encode($answer);

            self::assertStringNotContainsString('secret-tenant', $exported);
            self::assertStringNotContainsString('deny-', $exported);
        }
    }

    /**
     * A subtree grant at an ancestor applies in the tenant, so the principal
     * holds a grant there, while the identity's grants lie outside it.
     *
     * @return void
     */
    public function testAnAncestorSubtreeGrantIsPresentButOutside(): void
    {
        $this->tree();

        $identity = self::identity('identity');

        self::grant($identity, 'role', self::tenant('org1'));

        self::assertSame(GrantPresence::PRESENT, self::scopes()->hasGrantIn($identity, self::tenant('acct1')));
        self::assertSame(GrantPresence::PRESENT, self::scopes()->hasGrantIn($identity, self::tenant('team1')));
        self::assertSame(GrantScopeStatus::OUTSIDE, self::scopes()->forIdentity(Reference::of($identity), self::tenant('acct1')));
        self::assertSame(GrantScopeStatus::WITHIN, self::scopes()->forIdentity(Reference::of($identity), self::tenant('org1')));
    }

    /**
     * A node-only grant applies in its own tenant alone; a grant at a sibling
     * or in another organisation applies in neither.
     *
     * @param  string  $kind
     * @return void
     */
    #[DataProvider('kindProvider')]
    public function testANodeOnlyGrantIsPresentOnlyAtItsTenant(string $kind): void
    {
        $this->tree();

        $identity = self::identity('identity');

        self::grant($identity, $kind, self::tenant('org1'), false);
        self::grant($identity, $kind, self::tenant('acct2'));
        self::grant($identity, $kind, self::tenant('org2'));

        self::assertSame(GrantPresence::PRESENT, self::scopes()->hasGrantIn($identity, self::tenant('org1')));
        self::assertSame(GrantPresence::ABSENT, self::scopes()->hasGrantIn($identity, self::tenant('acct1')));
        self::assertSame(GrantPresence::PRESENT, self::scopes()->hasGrantIn($identity, self::tenant('acct2')));
    }

    /**
     * A platform-wide grant applies in every tenant, and an expired grant in
     * none.
     *
     * @return void
     */
    public function testAPlatformGrantIsPresentAndAnExpiredOneIsNot(): void
    {
        $this->tree();

        Carbon::setTestNow('2026-07-01 12:00:00');

        $identity = self::identity('identity');

        self::grant($identity, 'permission', null, expiresAt: Carbon::parse('2026-07-01 13:00:00'));

        self::assertSame(GrantPresence::PRESENT, self::scopes()->hasGrantIn($identity, self::tenant('team1')));

        Carbon::setTestNow('2026-07-01 13:00:01');

        self::assertSame(GrantPresence::ABSENT, self::scopes()->hasGrantIn($identity, self::tenant('team1')));

        Carbon::setTestNow();
    }

    /**
     * The principal's identity's grants count for it, and another principal of
     * the same identity never does.
     *
     * @return void
     */
    public function testTheIdentitysGrantsCountAndAnotherPrincipalsDoNot(): void
    {
        $this->tree();

        $identity = self::identity('identity');
        $first    = self::identity('principal-1');
        $second   = self::identity('principal-2');

        self::grant($second, 'role', self::tenant('acct1'));

        self::assertSame(GrantPresence::ABSENT, self::scopes()->hasGrantIn(new Subject($first, $identity), self::tenant('acct1')));
        self::assertSame(GrantPresence::PRESENT, self::scopes()->hasGrantIn(new Subject($second, $identity), self::tenant('acct1')));

        self::grant($identity, 'policy', self::tenant('org1'));

        self::assertSame(GrantPresence::PRESENT, self::scopes()->hasGrantIn(new Subject($first, $identity), self::tenant('acct1')));
    }

    /**
     * A person's grants never reach a machine principal, so they do not make a
     * grant present for it.
     *
     * @return void
     */
    public function testAPersonsGrantsDoNotCountForAMachine(): void
    {
        $this->tree();

        $person  = self::identity('person');
        $machine = new StubMachine(['id' => 'machine']);

        $machine->save();

        self::grant($person, 'role', self::tenant('acct1'));

        self::assertSame(GrantPresence::ABSENT, self::scopes()->hasGrantIn(new Subject($machine, $person), self::tenant('acct1')));
    }

    /**
     * Given an application, a grant made for it or for every application counts
     * and one made for another does not; without one, any counts.
     *
     * @return void
     */
    public function testTheApplicationFiltersTheGrants(): void
    {
        $this->tree();

        $identity = self::identity('identity');
        $other    = self::identity('other');

        self::grant($identity, 'permission', self::tenant('acct1'), application: 'admin');
        self::grant($other, 'role', self::tenant('acct1'));

        self::assertSame(GrantPresence::PRESENT, self::scopes()->hasGrantIn($identity, self::tenant('acct1'), 'admin'));
        self::assertSame(GrantPresence::ABSENT, self::scopes()->hasGrantIn($identity, self::tenant('acct1'), 'mobile'));
        self::assertSame(GrantPresence::PRESENT, self::scopes()->hasGrantIn($identity, self::tenant('acct1')));
        self::assertSame(GrantPresence::PRESENT, self::scopes()->hasGrantIn($other, self::tenant('acct1'), 'mobile'));
    }

    /**
     * A principal that is not a subject becomes one as the bound resolver's
     * `forUser()` makes it, with the identity the resolver gives.
     *
     * @return void
     */
    public function testAPrincipalBecomesTheResolversSubject(): void
    {
        $this->tree();

        $identity = self::identity('identity');

        self::grant($identity, 'role', self::tenant('acct1'));

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver);

        self::assertSame(GrantPresence::PRESENT, self::scopes()->hasGrantIn($identity, self::tenant('acct1')));
        self::assertSame(GrantPresence::ABSENT, self::scopes()->hasGrantIn(self::identity('nobody'), self::tenant('acct1')));
    }

    /**
     * A tree that cannot be read turns no grant found into unknown, though a
     * grant made in the tenant itself, or platform-wide, is still found.
     *
     * @return void
     */
    public function testATreeThatCannotBeReadNeverTurnsUncertaintyIntoPresence(): void
    {
        $this->app?->instance('log', new RecordingLogger);

        $this->app?->instance(TenantTree::class, new UnreadableTenantTree);

        $identity = self::identity('identity');
        $other    = self::identity('other');

        self::grant($identity, 'role', self::tenant('org1'));
        self::grant($other, 'role', self::tenant('acct1'));

        self::assertSame(GrantPresence::UNKNOWN, self::scopes()->hasGrantIn($identity, self::tenant('acct1')));
        self::assertSame(GrantPresence::PRESENT, self::scopes()->hasGrantIn($other, self::tenant('acct1')));

        self::grant($identity, 'permission', null);

        self::assertSame(GrantPresence::PRESENT, self::scopes()->hasGrantIn($identity, self::tenant('acct1')));
    }

    /**
     * An identity that is not a model or reference cannot be read, so no grant
     * found is unknown; the principal's own grant is still present.
     *
     * @return void
     */
    public function testAnIdentityThatCannotBeReadIsUnknownUnlessAGrantIsFound(): void
    {
        $this->tree();

        $principal = self::identity('principal');
        $subject   = new Subject($principal, new \stdClass);

        self::assertSame(GrantPresence::UNKNOWN, self::scopes()->hasGrantIn($subject, self::tenant('acct1')));

        self::grant($principal, 'role', self::tenant('acct1'));

        self::assertSame(GrantPresence::PRESENT, self::scopes()->hasGrantIn($subject, self::tenant('acct1')));
    }

    /**
     * Once the package refuses, both questions refuse by their own guard,
     * before the tenant is read, a seam resolved or a grant queried.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testBothQuestionsRefuseOnceThePackageRefuses(): void
    {
        $user     = self::identity('user-1');
        $resolved = [];

        $this->refuseThePackage();
        $this->container()->beforeResolving(static function (string $abstract) use (&$resolved): void {
            $resolved[] = $abstract;
        });

        $this->assertEachRefused([
            'forIdentity' => static fn () => self::scopes()->forIdentity(new Reference('stub_identity', 'user-1'), self::tenant('t1')),
            'hasGrantIn'  => static fn () => self::scopes()->hasGrantIn($user, self::tenant('t1')),
        ]);

        self::assertSame([], \array_values(\array_intersect($resolved, [SubjectResolver::class, IdentityDirectory::class, TenantTree::class])));
    }

    /**
     * Put the fixture tenants in the closure-table tree and bind it, with a
     * complete directory listing no principals.
     *
     * @return void
     */
    private function tree(): void
    {
        $this->app?->instance(TenantTree::class, new ClosureTenantTree);
        $this->app?->instance(IdentityDirectory::class, new ListedIdentityDirectory);

        ClosureTenantTree::add(self::tenant('org1'));
        ClosureTenantTree::add(self::tenant('acct1'), self::tenant('org1'));
        ClosureTenantTree::add(self::tenant('acct2'), self::tenant('org1'));
        ClosureTenantTree::add(self::tenant('team1'), self::tenant('acct1'));
        ClosureTenantTree::add(self::tenant('org2'));
    }

    /**
     * Grant the grantee one grant of the kind, in the tenant or platform-wide.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity|\Tests\Feature\Stubs\StubSecondIdentity  $grantee
     * @param  string  $kind
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $isSubtree
     * @param  string|null  $application
     * @param  \Illuminate\Support\Carbon|null  $expiresAt
     * @return void
     */
    private static function grant(
        StubIdentity|StubSecondIdentity $grantee,
        string $kind,
        ?Reference $tenant,
        bool $isSubtree = true,
        ?string $application = null,
        ?Carbon $expiresAt = null,
    ): void {
        $name = $kind . '-' . Str::random(16);

        match ($kind) {
            'role'       => $grantee->assignRole(Role::create(['name' => $name]), $expiresAt, $tenant, $isSubtree, $application),
            'permission' => $grantee->givePermission(Permission::create(['name' => $name . ':read']), $expiresAt, $tenant, $isSubtree, $application),
            default      => $grantee->attachPolicy(self::denying($name), $expiresAt, $tenant, $isSubtree, $application),
        };
    }

    /**
     * Create a policy that only denies.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function denying(string $name): Policy
    {
        return Policy::create(['name' => 'deny-' . $name, 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['posts:delete']]]]]);
    }

    /**
     * Return a directory listing the principals of the identity.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $identity
     * @param  list<\Illuminate\Database\Eloquent\Model>  $principals
     * @param  bool  $isComplete
     * @return \Tests\Fixtures\GrantScope\ListedIdentityDirectory
     */
    private static function directory(Model $identity, array $principals, bool $isComplete = true): ListedIdentityDirectory
    {
        return new ListedIdentityDirectory([ListedIdentityDirectory::key(Reference::of($identity)) => \array_map(Reference::of(...), $principals)], $isComplete);
    }

    /**
     * Create a stub identity with the key.
     *
     * @param  string  $id
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private static function identity(string $id): StubIdentity
    {
        return StubIdentity::create(['id' => $id]);
    }

    /**
     * Return the reference to the fixture tenant with the key.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    private static function tenant(string $id): Reference
    {
        return new Reference(self::TENANT, $id);
    }

    /**
     * Return the grant scope query the container builds.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantScopeQuery
     */
    private static function scopes(): GrantScopeQuery
    {
        /** @var \SineMacula\Laravel\Authorization\Services\GrantScopeQuery */
        return app(GrantScopeQuery::class);
    }
}
