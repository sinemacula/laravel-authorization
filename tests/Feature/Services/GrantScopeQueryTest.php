<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionRolledBack;
use Illuminate\Database\QueryException;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Enums\GrantPresence;
use SineMacula\Laravel\Authorization\Enums\GrantScopeStatus;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GrantScopeQuery;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\RefusesThePackage;
use Tests\Concerns\UsesAnAuthorizationConnection;
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
use Tests\Fixtures\TenantTrees\ClashingTenants;
use Tests\TestCase;

/**
 * Feature tests for the grant scope query (AUTHZ-14.2), the principal presence
 * helper (AUTHZ-13.8) and the lists of the grantees reaching a tenant or within
 * it (N131), over a closure-table tree of two organisations, the first with two
 * accounts and a team below the first account, and over the flat tree.
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
    use RefusesThePackage, UsesAnAuthorizationConnection;

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
     * A grant row naming half a tenant, a type without a key or a key without a
     * type, cannot be read, so it gives unknown, unless another grant is proven
     * outside; and, applying nowhere, it is no grant in any tenant.
     *
     * @return void
     */
    public function testARowNamingHalfATenantIsUnknown(): void
    {
        $this->tree();

        $identity = self::identity('identity');

        foreach ([[self::TENANT, null], [null, 'acct1']] as $index => [$type, $id]) {
            DB::table('authorizable_permissions')->insert([
                'permission_id'     => Permission::create(['name' => 'half:read-' . $index])->getKey(),
                'authorizable_type' => $identity->getMorphClass(),
                'authorizable_id'   => $identity->getKey(),
                'tenant_type'       => $type,
                'tenant_id'         => $id,
                'include_subtree'   => true,
            ]);

            self::assertSame(GrantScopeStatus::UNKNOWN, self::scopes()->forIdentity(Reference::of($identity), self::tenant('acct1')));
            self::assertSame(GrantPresence::ABSENT, self::scopes()->hasGrantIn($identity, self::tenant('acct1')));
            self::assertSame(GrantPresence::ABSENT, self::scopes()->hasGrantIn($identity, self::tenant('org2')));
        }

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
     * Once the package refuses, every question refuses by its own guard, before
     * the tenant is read, a seam resolved or a grant queried.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryQuestionRefusesOnceThePackageRefuses(): void
    {
        $user     = self::identity('user-1');
        $resolved = [];

        $this->refuseThePackage();
        $this->container()->beforeResolving(static function (string $abstract) use (&$resolved): void {
            $resolved[] = $abstract;
        });

        $this->assertEachRefused([
            'forIdentity'      => static fn () => self::scopes()->forIdentity(new Reference('stub_identity', 'user-1'), self::tenant('t1')),
            'hasGrantIn'       => static fn () => self::scopes()->hasGrantIn($user, self::tenant('t1')),
            'granteesReaching' => static fn () => self::scopes()->granteesReaching(self::tenant('t1')),
            'granteesWithin'   => static fn () => self::scopes()->granteesWithin(self::tenant('t1')),
        ]);

        self::assertSame([], \array_values(\array_intersect($resolved, [SubjectResolver::class, IdentityDirectory::class, TenantTree::class])));
    }

    /**
     * Every grantee holding a grant of each kind that reaches the tenant is
     * listed: one made in the tenant, for it alone or reaching below it, one
     * made in an ancestor that reaches below it, and a platform-wide one; never
     * one made in an ancestor for itself alone, below the tenant, in a sibling
     * or in another organisation.
     *
     * @param  string  $kind
     * @return void
     */
    #[DataProvider('kindProvider')]
    public function testTheGranteesReachingTheTenantAreListed(string $kind): void
    {
        $this->tree();
        $this->holders($kind);

        self::assertEquals(self::references('c-ancestor-subtree', 'd-tenant-node', 'e-platform', 'h-tenant-subtree'), self::scopes()->granteesReaching(self::tenant('acct1')));
        self::assertEquals(self::references('a-below', 'c-ancestor-subtree', 'e-platform', 'h-tenant-subtree'), self::scopes()->granteesReaching(self::tenant('team1')));
        self::assertEquals(self::references('e-platform', 'g-other'), self::scopes()->granteesReaching(self::tenant('org2')));
    }

    /**
     * Every grantee holding a grant of each kind made in the tenant or below it
     * is listed, whether or not the grant reaches below its own tenant; never
     * one made in an ancestor, a sibling, another organisation or the platform.
     *
     * @param  string  $kind
     * @return void
     */
    #[DataProvider('kindProvider')]
    public function testTheGranteesWithinTheTenantAreListed(string $kind): void
    {
        $this->tree();
        $this->holders($kind);

        self::assertEquals(self::references('a-below', 'd-tenant-node', 'h-tenant-subtree'), self::scopes()->granteesWithin(self::tenant('acct1')));
        self::assertEquals(self::references('a-below'), self::scopes()->granteesWithin(self::tenant('team1')));
        self::assertEquals(
            self::references('a-below', 'b-ancestor-node', 'c-ancestor-subtree', 'd-tenant-node', 'f-sibling', 'h-tenant-subtree'),
            self::scopes()->granteesWithin(self::tenant('org1')),
        );
    }

    /**
     * On the flat tree a tenant has no ancestor and nothing below it, so only
     * the grants made in the tenant, and the platform-wide ones reaching it,
     * are listed.
     *
     * @return void
     */
    public function testTheFlatTreeListsTheTenantsOwnGrantees(): void
    {
        $this->app?->instance(TenantTree::class, new FlatTenantTree);

        self::grant(self::identity('node'), 'role', self::tenant('acct1'), false);
        self::grant(self::identity('subtree'), 'permission', self::tenant('acct1'));
        self::grant(self::identity('elsewhere'), 'policy', self::tenant('org1'));
        self::grant(self::identity('platform'), 'role', null);

        self::assertEquals(self::references('node', 'platform', 'subtree'), self::scopes()->granteesReaching(self::tenant('acct1')));
        self::assertEquals(self::references('node', 'subtree'), self::scopes()->granteesWithin(self::tenant('acct1')));
    }

    /**
     * An expired grant, a row naming half a tenant, which the package never
     * writes, and an inline policy attached to a grantee it does not belong to
     * are no grants, so their grantees are never listed.
     *
     * @return void
     */
    public function testNoGranteeIsListedForWhatIsNoGrant(): void
    {
        $this->tree();

        Carbon::setTestNow('2026-07-01 12:00:00');

        self::grant(self::identity('expiring'), 'permission', self::tenant('acct1'), expiresAt: Carbon::parse('2026-07-01 13:00:00'));

        self::half('type-only', self::TENANT, null);
        self::half('key-only', null, 'acct1');
        self::half('key-only-below', null, 'team1');

        $inline = Policy::create(['name' => 'theirs', 'owner_type' => 'stub', 'owner_id' => 'someone', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['*']]]]]);
        $stray  = self::identity('stray');

        foreach ([null, 'acct1'] as $tenant) {
            // A row the write paths refuse, written past them.
            DB::table('authorizable_policies')->insert([
                'policy_id'         => $inline->getKey(),
                'authorizable_type' => $stray->getMorphClass(),
                'authorizable_id'   => $stray->getKey(),
                'tenant_type'       => $tenant === null ? null : self::TENANT,
                'tenant_id'         => $tenant,
            ]);
        }

        self::assertEquals(self::references('expiring'), self::scopes()->granteesReaching(self::tenant('acct1')));
        self::assertEquals(self::references('expiring'), self::scopes()->granteesWithin(self::tenant('org1')));

        Carbon::setTestNow('2026-07-01 13:00:01');

        self::assertSame([], self::scopes()->granteesReaching(self::tenant('acct1')));
        self::assertSame([], self::scopes()->granteesWithin(self::tenant('org1')));

        Carbon::setTestNow();

        self::grant($stray, 'policy', self::tenant('acct1'));

        self::assertEquals(self::references('stray'), self::scopes()->granteesReaching(self::tenant('acct1')));
        self::assertEquals(self::references('stray'), self::scopes()->granteesWithin(self::tenant('acct1')));
    }

    /**
     * A role a policy is attached to is never listed as a grantee, wherever the
     * policy is attached: in the tenant, in an ancestor reaching below it, or
     * platform-wide. Whoever holds the role is listed through their own grant
     * of it.
     *
     * @return void
     */
    public function testARoleAPolicyIsAttachedToIsNeverListed(): void
    {
        $this->tree();

        $role = Role::create(['name' => 'scoped']);

        $role->attachPolicy(self::denying('in-tenant'), null, self::tenant('acct1'));
        $role->attachPolicy(self::denying('in-ancestor'), null, self::tenant('org1'));
        $role->attachPolicy(self::denying('on-platform'));

        self::identity('person')->assignRole($role, null, self::tenant('acct1'));

        self::assertEquals(self::references('person'), self::scopes()->granteesReaching(self::tenant('acct1')));
        self::assertEquals(self::references('person'), self::scopes()->granteesWithin(self::tenant('org1')));
        self::assertSame([], self::scopes()->granteesReaching(self::tenant('org2')));
        self::assertSame([], self::scopes()->granteesWithin(self::tenant('acct2')));
    }

    /**
     * In a tree of two tenant types whose ids clash, a tenant is told from
     * another sharing its id by its type, both above and below it.
     *
     * @return void
     */
    public function testTenantsSharingAnIdUnderAnotherTypeAreToldApart(): void
    {
        $this->app?->instance(TenantTree::class, new ClosureTenantTree);

        ClashingTenants::seed();

        foreach (ClashingTenants::nodes() as [$node]) {
            self::grant(self::identity('at-' . $node->type . '-' . $node->id), 'role', $node, $node->type !== 'team' || $node->id !== '7');
        }

        self::assertEquals(self::references('at-org-1', 'at-team-2', 'at-team-7'), self::scopes()->granteesReaching(new Reference('team', '7')));
        self::assertEquals(self::references('at-org-1', 'at-team-1'), self::scopes()->granteesReaching(new Reference('team', '1')));
        self::assertEquals(self::references('at-org-7', 'at-team-8'), self::scopes()->granteesReaching(new Reference('team', '8')));
        self::assertEquals(
            self::references('at-account-3', 'at-org-1', 'at-team-1', 'at-team-2', 'at-team-7'),
            self::scopes()->granteesWithin(new Reference('org', '1')),
        );
        self::assertEquals(self::references('at-team-1'), self::scopes()->granteesWithin(new Reference('team', '1')));
        self::assertEquals(self::references('at-org-7', 'at-team-8'), self::scopes()->granteesWithin(new Reference('org', '7')));
    }

    /**
     * Principals and identities are listed as their rows store them, each once
     * however many grants it holds, two sharing a key under different types
     * apart, by type and then key, byte by byte: never by number, nor folding
     * case. The stubs' types are their class names, the machine's before the
     * second identity's.
     *
     * @return void
     */
    public function testEachGranteeIsListedOnceByTypeThenKey(): void
    {
        $this->tree();

        $second  = new StubSecondIdentity(['id' => 'shared']);
        $machine = new StubMachine(['id' => 'machine']);

        $second->save();
        $machine->save();

        $identities = \array_map(self::identity(...), ['b', 'shared', 'a', 'C', '9', '10']);

        foreach ($identities as $identity) {
            self::grant($identity, 'policy', self::tenant('acct1'));
        }

        self::grant($identities[1], 'role', self::tenant('acct1'), false);
        self::grant($identities[1], 'permission', null);
        self::grant($second, 'permission', self::tenant('team1'));
        self::grant($second, 'role', self::tenant('org1'));
        self::grant($machine, 'role', self::tenant('acct1'), false);

        $expected = [...self::references('10', '9', 'C', 'a', 'b', 'shared'), Reference::of($machine), Reference::of($second)];

        self::assertEquals($expected, self::scopes()->granteesReaching(self::tenant('acct1')));
        self::assertEquals($expected, self::scopes()->granteesWithin(self::tenant('org1')));
    }

    /**
     * Given an application, only the grants that hold in it count, those made
     * for every application included; without one, every grant counts.
     *
     * @return void
     */
    public function testTheApplicationFiltersTheGrantees(): void
    {
        $this->tree();

        self::grant(self::identity('admin'), 'role', self::tenant('org1'), application: 'admin');
        self::grant(self::identity('every'), 'permission', self::tenant('acct1'));
        self::grant(self::identity('mobile'), 'policy', self::tenant('acct1'), application: 'mobile');

        self::assertEquals(self::references('admin', 'every'), self::scopes()->granteesReaching(self::tenant('acct1'), 'admin'));
        self::assertEquals(self::references('every', 'mobile'), self::scopes()->granteesReaching(self::tenant('acct1'), 'mobile'));
        self::assertEquals(self::references('admin', 'every', 'mobile'), self::scopes()->granteesReaching(self::tenant('acct1')));
        self::assertEquals(self::references('admin', 'every'), self::scopes()->granteesWithin(self::tenant('org1'), 'admin'));
        self::assertEquals(self::references('every', 'mobile'), self::scopes()->granteesWithin(self::tenant('acct1'), 'mobile'));
        self::assertEquals(self::references('every'), self::scopes()->granteesWithin(self::tenant('acct1'), 'admin'));
        self::assertEquals(self::references('admin', 'every', 'mobile'), self::scopes()->granteesWithin(self::tenant('org1')));
    }

    /**
     * The tenant may be named by a model or a reference alike, either listing
     * the grantees of the grants its reference names.
     *
     * @return void
     */
    public function testATenantModelListsAsItsReference(): void
    {
        $this->tree();

        $tenant = StubTenant::query()->create(['id' => 'acct1', 'name' => 'acct1']);

        ClosureTenantTree::add(Reference::of($tenant));

        self::grant(self::identity('holder'), 'role', Reference::of($tenant));

        self::assertEquals(self::references('holder'), self::scopes()->granteesReaching($tenant));
        self::assertEquals(self::references('holder'), self::scopes()->granteesWithin($tenant));
        self::assertEquals(self::references('holder'), self::scopes()->granteesWithin(Reference::of($tenant)));
    }

    /**
     * Each list reads the grants in one query, whatever the number of grants
     * and grantees: the subtree is nested in it, and only the ancestors the
     * grantees reaching the tenant are read through cost the tree's one read.
     *
     * @return void
     */
    public function testEachListReadsTheGrantsInOneQuery(): void
    {
        $this->tree();

        $reaching = $this->queriesOf(static fn (): array => self::scopes()->granteesReaching(self::tenant('team1')));
        $within   = $this->queriesOf(static fn (): array => self::scopes()->granteesWithin(self::tenant('org1')));

        self::assertSame([[], []], [$reaching['answer'], $within['answer']]);
        self::assertCount(2, $reaching['queries']);
        self::assertCount(1, $within['queries']);

        foreach (['b-one', 'c-two', 'd-three'] as $id) {
            $this->holders('role', $id . '-');
        }

        self::assertCount(2, $this->queriesOf(static fn (): array => self::scopes()->granteesReaching(self::tenant('team1')))['queries']);
        self::assertCount(1, $this->queriesOf(static fn (): array => self::scopes()->granteesWithin(self::tenant('org1')))['queries']);
    }

    /**
     * A subtree moved under a new parent comes to be reached by the grants
     * reaching that parent: listed by asking about the new parent, before the
     * move or after it, or about the moved tenant once it has moved, which no
     * longer lists those of its former ancestors. The grants made within the
     * moved subtree keep their place.
     *
     * @return void
     */
    public function testAMovedSubtreeIsReachedByItsNewParentsGrantees(): void
    {
        $this->tree();
        $this->holders('role');

        self::grant(self::identity('i-new-parent-subtree'), 'permission', self::tenant('org2'));
        self::grant(self::identity('j-new-parent-node'), 'policy', self::tenant('org2'), false);

        $parent   = self::references('e-platform', 'g-other', 'i-new-parent-subtree', 'j-new-parent-node');
        $reaching = self::references('d-tenant-node', 'e-platform', 'g-other', 'h-tenant-subtree', 'i-new-parent-subtree');
        $below    = self::references('a-below', 'e-platform', 'g-other', 'h-tenant-subtree', 'i-new-parent-subtree');
        $moved    = self::references('a-below', 'd-tenant-node', 'g-other', 'h-tenant-subtree', 'i-new-parent-subtree', 'j-new-parent-node');
        $within   = self::scopes()->granteesWithin(self::tenant('acct1'));

        self::assertEquals($parent, self::scopes()->granteesReaching(self::tenant('org2')));

        self::move(self::tenant('acct1'), self::tenant('org2'));

        self::assertEquals($parent, self::scopes()->granteesReaching(self::tenant('org2')));
        self::assertEquals($reaching, self::scopes()->granteesReaching(self::tenant('acct1')));
        self::assertEquals($below, self::scopes()->granteesReaching(self::tenant('team1')));
        self::assertEquals($within, self::scopes()->granteesWithin(self::tenant('acct1')));
        self::assertEquals($moved, self::scopes()->granteesWithin(self::tenant('org2')));
    }

    /**
     * Inside a batch of checks, the tenant's ancestors are read afresh each
     * time, so a move the tree was not told of is seen by the next list.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAncestorsAreReadAfreshInsideABatch(): void
    {
        $this->tree();

        self::grant(self::identity('old'), 'role', self::tenant('org1'));
        self::grant(self::identity('new'), 'role', self::tenant('org2'));

        $cache = ResolutionCache::instance();

        self::assertNotNull($cache);

        $lists = $cache->batch(static function (): array {
            $lists = [self::scopes()->granteesReaching(self::tenant('acct1'))];

            self::move(self::tenant('acct1'), self::tenant('org2'));

            $lists[] = self::scopes()->granteesReaching(self::tenant('acct1'));

            return $lists;
        });

        self::assertEquals([self::references('old'), self::references('new')], $lists);
    }

    /**
     * A tree that throws is thrown, never listed as no grantee; a subtree on
     * another connection than the package's is refused, while the ancestors are
     * read as ever.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATreeThatCannotBeReadIsThrown(): void
    {
        $this->app?->instance(TenantTree::class, new UnreadableTenantTree);

        $lists = [
            'granteesReaching' => static fn (): array => self::scopes()->granteesReaching(self::tenant('acct1')),
            'granteesWithin'   => static fn (): array => self::scopes()->granteesWithin(self::tenant('acct1')),
        ];

        foreach ($lists as $method => $list) {
            try {
                $list();

                self::fail("{$method} listed through a tree that cannot be read.");
            } catch (\RuntimeException $exception) {
                self::assertSame(UnreadableTenantTree::MESSAGE, $exception->getMessage(), $method);
            }
        }

        config()->set('database.connections.tenants', config('database.connections.' . DB::getDefaultConnection()));

        $this->tree();
        $this->app?->instance(TenantTree::class, new SubtreeQueryTree(static fn (Reference $tenant): Builder => DB::connection('tenants')->query()
            ->selectRaw('? as tenant_type, ? as tenant_id', [$tenant->type, $tenant->id])));

        self::grant(self::identity('holder'), 'role', self::tenant('org1'));

        self::assertEquals(self::references('holder'), self::scopes()->granteesReaching(self::tenant('acct1')));

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('The tenant tree\'s subtree is not a query on the package\'s connection.');

        self::scopes()->granteesWithin(self::tenant('acct1'));
    }

    /**
     * A subtree query that builds but fails as the grant query runs is thrown,
     * after only the grant query's own savepoint is rolled back, so the
     * transaction the caller runs in stays usable.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASubtreeQueryThatFailsAsItRunsIsThrownAfterItsSavepoint(): void
    {
        $this->tree();
        $this->app?->instance(TenantTree::class, new SubtreeQueryTree(static fn (Reference $tenant): Builder => DB::table('grant_scope_missing_closure')
            ->select(['descendant_type as tenant_type', 'descendant_id as tenant_id'])
            ->where('ancestor_type', $tenant->type)
            ->where('ancestor_id', $tenant->id)));

        self::grant(self::identity('holder'), 'role', self::tenant('acct1'));

        $rolledBack = 0;

        Event::listen(TransactionRolledBack::class, static function () use (&$rolledBack): void {
            $rolledBack++;
        });

        DB::transaction(static function () use (&$rolledBack): void {
            try {
                self::scopes()->granteesWithin(self::tenant('acct1'));

                self::fail('A subtree query that fails as it runs was listed.');
            } catch (QueryException $exception) {
                self::assertStringContainsString('grant_scope_missing_closure', $exception->getMessage());
            }

            self::assertSame(1, $rolledBack);
            self::assertEquals(self::references('holder'), self::scopes()->granteesReaching(self::tenant('acct1')));
        });
    }

    /**
     * The grantees are read on the write connection, so a replica that lags
     * never hides one, and on the package's connection, whatever the default.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function testTheGranteesAreReadOnThePackagesWriteConnection(): void
    {
        $this->useAnAuthorizationConnection();

        self::grant(self::identity('holder'), 'permission', self::tenant('acct1'));

        $connection = self::authorizationConnection();

        $connection->setReadPdo(static fn (): never => throw new \LogicException('The read connection was used.'));

        self::assertSame(0, $connection->transactionLevel());
        self::assertEquals(self::references('holder'), self::scopes()->granteesReaching(self::tenant('acct1')));
        self::assertEquals(self::references('holder'), self::scopes()->granteesWithin(self::tenant('acct1')));
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
     * Grant each fixture grantee one grant of the kind, in an order other than
     * that of their keys: below the tenant `acct1`, in its ancestor for itself
     * alone and reaching below it, in the tenant for itself alone and reaching
     * below it, at the platform, in a sibling and in another organisation.
     *
     * @param  string  $kind
     * @param  string  $prefix
     * @return void
     */
    private function holders(string $kind, string $prefix = ''): void
    {
        $holders = [
            'h-tenant-subtree'   => [self::tenant('acct1'), true],
            'g-other'            => [self::tenant('org2'), true],
            'f-sibling'          => [self::tenant('acct2'), true],
            'e-platform'         => [null, true],
            'd-tenant-node'      => [self::tenant('acct1'), false],
            'c-ancestor-subtree' => [self::tenant('org1'), true],
            'b-ancestor-node'    => [self::tenant('org1'), false],
            'a-below'            => [self::tenant('team1'), true],
        ];

        foreach ($holders as $id => [$tenant, $isSubtree]) {
            self::grant(self::identity($prefix . $id), $kind, $tenant, $isSubtree);
        }
    }

    /**
     * Write a permission grant to a new stub identity naming half a tenant,
     * past the write paths, which refuse it.
     *
     * @param  string  $id
     * @param  string|null  $type
     * @param  string|null  $key
     * @return void
     */
    private static function half(string $id, ?string $type, ?string $key): void
    {
        $identity = self::identity($id);

        DB::table('authorizable_permissions')->insert([
            'permission_id'     => Permission::create(['name' => $id . ':read'])->getKey(),
            'authorizable_type' => $identity->getMorphClass(),
            'authorizable_id'   => $identity->getKey(),
            'tenant_type'       => $type,
            'tenant_id'         => $key,
            'include_subtree'   => true,
        ]);
    }

    /**
     * Move the fixture tenant, and every tenant below it, under the new parent
     * in the closure-table tree, without telling the package.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $parent
     * @return void
     */
    private static function move(Reference $tenant, Reference $parent): void
    {
        $above = [$parent, ...(new ClosureTenantTree)->ancestors($parent)];
        $below = DB::table(ClosureTenantTree::TABLE)
            ->where('ancestor_type', $tenant->type)
            ->where('ancestor_id', $tenant->id)
            ->get(['descendant_type', 'descendant_id', 'depth']);

        foreach ($below as $row) {
            /** @var array{descendant_type: string, descendant_id: string, depth: int|string} $node */
            $node  = (array) $row;
            $depth = (int) $node['depth'];

            DB::table(ClosureTenantTree::TABLE)
                ->where('descendant_type', $node['descendant_type'])
                ->where('descendant_id', $node['descendant_id'])
                ->where('depth', '>', $depth)
                ->delete();

            foreach ($above as $offset => $ancestor) {
                DB::table(ClosureTenantTree::TABLE)->insert([
                    'ancestor_type'   => $ancestor->type,
                    'ancestor_id'     => $ancestor->id,
                    'descendant_type' => $node['descendant_type'],
                    'descendant_id'   => $node['descendant_id'],
                    'depth'           => $depth + $offset + 1,
                ]);
            }
        }
    }

    /**
     * Return the references to the stub identities with the keys.
     *
     * @param  string  ...$ids
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    private static function references(string ...$ids): array
    {
        return \array_values(\array_map(static fn (string $id): Reference => new Reference((new StubIdentity)->getMorphClass(), $id), $ids));
    }

    /**
     * Run the callback, and return its answer with the queries it ran.
     *
     * @template TAnswer
     *
     * @param  \Closure(): TAnswer  $callback
     * @return array{answer: TAnswer, queries: list<string>}
     */
    private function queriesOf(\Closure $callback): array
    {
        $queries = [];

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        $answer = $callback();

        $this->app?->make('events')->forget(QueryExecuted::class);

        return ['answer' => $answer, 'queries' => $queries];
    }

    /**
     * Grant the grantee one grant of the kind, in the tenant or platform-wide.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity|\Tests\Feature\Stubs\StubMachine|\Tests\Feature\Stubs\StubSecondIdentity  $grantee
     * @param  string  $kind
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $isSubtree
     * @param  string|null  $application
     * @param  \Illuminate\Support\Carbon|null  $expiresAt
     * @return void
     */
    private static function grant(
        StubIdentity|StubMachine|StubSecondIdentity $grantee,
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
