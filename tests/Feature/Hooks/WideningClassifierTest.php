<?php

declare(strict_types = 1);

namespace Tests\Feature\Hooks;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Enums\WideningReason;
use SineMacula\Laravel\Authorization\Exceptions\UnresolvableRecipientException;
use SineMacula\Laravel\Authorization\Hooks\GrantWidening;
use SineMacula\Laravel\Authorization\Hooks\ProposedGrant;
use SineMacula\Laravel\Authorization\Hooks\WideningClassifier;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\RecordsRowLocks;
use Tests\Concerns\WidensGrants;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Fixtures\GrantHooks\PrincipalSubjectResolver;
use Tests\Fixtures\GrantScope\ListedIdentityDirectory;
use Tests\Fixtures\GrantScope\UnreadableTenantTree;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\TestCase;

/**
 * Feature tests for the widening classification (AUTHZ-11.3): which grants a
 * call proposes widen an identity's scope, over an identity owning two
 * principals and a closure-table tree of two organisations.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(WideningClassifier::class)]
final class WideningClassifierTest extends TestCase
{
    use RecordsRowLocks, WidensGrants;

    /**
     * Set up the identity, its principals and the tree.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->closureTree();
        $this->principals();
    }

    /**
     * A grant to the identity itself widens, held tenant or not, and names the
     * identity as both the identity and the grantee.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantToTheIdentityWidens(): void
    {
        $person = self::person();

        self::grants()->grantRole(self::principal('p2'), self::role('held'), tenant: self::tenant('acct1'));

        $widening = self::classify($person, self::tenant('acct1'));

        self::assertSame([WideningReason::IDENTITY], $widening?->reasons);
        self::assertTrue($widening->isToIdentity());
        self::assertSame([StubIdentity::class, 'person'], [$widening->identity->type, $widening->identity->id]);
        self::assertSame([WideningReason::IDENTITY, WideningReason::NEW_TENANT], self::classify($person, self::tenant('acct2'))?->reasons);
    }

    /**
     * A platform-wide grant widens, whatever is held.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlatformGrantWidens(): void
    {
        self::grants()->grantRole(self::principal('p2'), self::role('held'));

        $widening = self::classify(self::principal('p1'), null);

        self::assertSame([WideningReason::PLATFORM], $widening?->reasons);
        self::assertFalse($widening->isToIdentity());
        self::assertSame([StubIdentity::class, 'person'], [$widening->identity->type, $widening->identity->id]);
        self::assertSame([StubSecondIdentity::class, 'p1'], [$widening->grantee->type, $widening->grantee->id]);
    }

    /**
     * A grant in a tenant where no grant of the identity or its principals
     * applied widens: a new tenant, a sibling of one held, and an ancestor of
     * one held.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantWhereNothingAppliedWidens(): void
    {
        $principal = self::principal('p1');

        self::assertSame([WideningReason::NEW_TENANT], self::classify($principal, self::tenant('acct1'))?->reasons);

        self::grants()->grantRole(self::principal('p2'), self::role('held'), tenant: self::tenant('acct1'));

        self::assertSame([WideningReason::NEW_TENANT], self::classify($principal, self::tenant('acct2'))?->reasons, 'a sibling');
        self::assertSame([WideningReason::NEW_TENANT], self::classify($principal, self::tenant('org1'))?->reasons, 'an ancestor');
        self::assertSame([WideningReason::NEW_TENANT], self::classify($principal, self::tenant('org2'))?->reasons, 'another organisation');
    }

    /**
     * A grant in a tenant a grant of another principal of the identity already
     * applies in widens nothing: one made there, or one made at an ancestor
     * that reaches below it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantWhereAGrantAlreadyAppliesWidensNothing(): void
    {
        $principal = self::principal('p1');

        self::grants()->grantRole(self::principal('p2'), self::role('held'), tenant: self::tenant('acct1'));

        self::assertNull(self::classify($principal, self::tenant('acct1')));
        self::assertNull(self::classify($principal, self::tenant('acct1'), false));
        self::assertNull(self::classify($principal, self::tenant('team1')), 'below a subtree grant');
    }

    /**
     * A grant of the identity itself, or a platform-wide one, applies in every
     * tenant it reaches, so a principal's grant there widens nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantOfTheIdentityOrThePlatformCounts(): void
    {
        self::grants()->grantRole(self::person(), self::role('identity'), tenant: self::tenant('org1'));

        self::assertNull(self::classify(self::principal('p1'), self::tenant('acct2')));

        self::grants()->grantRole(self::principal('p2'), self::role('platform'));

        self::assertNull(self::classify(self::principal('p1'), self::tenant('org2')));
    }

    /**
     * A grant reaching below its tenant widens where the grant held there
     * reaches only its own tenant; a grant limited to the tenant does not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantReachingBelowWhereNoneDidWidens(): void
    {
        $principal = self::principal('p1');

        self::grants()->grantRole(self::principal('p2'), self::role('held'), tenant: self::tenant('acct1'), includeSubtree: false);

        self::assertSame([WideningReason::NEW_SUBTREE], self::classify($principal, self::tenant('acct1'))?->reasons);
        self::assertNull(self::classify($principal, self::tenant('acct1'), false));
    }

    /**
     * The grant's own row counts as held: granting it unchanged, or shortening
     * it, is never classified, and an extension of it is classified but widens
     * nothing in a tenant, while the same changes to a platform-wide row follow
     * it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testUnchangedGrantsAndShorteningsAreNeverClassified(): void
    {
        $principal = self::principal('p1');
        $role      = self::role('held');
        $later     = Carbon::now('UTC')->addDays(2)->startOfSecond();
        $sooner    = Carbon::now('UTC')->addDay()->startOfSecond();

        self::grants()->grantRole($principal, $role, $later);
        self::grants()->grantRole($principal, $role, $later, tenant: self::tenant('acct1'));

        self::assertNull(self::classify($principal, null, true, $later, $role), 'unchanged');
        self::assertNull(self::classify($principal, null, true, $sooner, $role), 'shortened');
        self::assertNull(self::classify($principal, null, false, $later, $role), 'narrowed');
        self::assertSame([WideningReason::PLATFORM], self::classify($principal, null, true, $later->copy()->addDay(), $role)?->reasons, 'extended');
        self::assertSame([WideningReason::PLATFORM], self::classify($principal, null, true, null, $role)?->reasons, 'made permanent');
        self::assertNull(self::classify($principal, self::tenant('acct1'), true, null, $role), 'extended in a held tenant');
    }

    /**
     * A permanent grant held unchanged, or given an expiry, is never
     * classified, so not even an identity's grant widens then.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPermanentGrantShortenedIsNeverClassified(): void
    {
        $person = self::person();
        $role   = self::role('held');

        self::grants()->grantRole($person, $role);

        self::assertNull(self::classify($person, null, true, null, $role));
        self::assertNull(self::classify($person, null, true, Carbon::now('UTC')->addDay(), $role));
    }

    /**
     * An expired grant re-armed is classified as a new one: alone in its
     * tenant, it widens.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARearmedGrantIsClassified(): void
    {
        $principal = self::principal('p1');
        $role      = self::role('held');

        self::grants()->grantRole($principal, $role, Carbon::now('UTC')->addHour(), tenant: self::tenant('acct1'));

        $this->travel(2)->hours();

        self::assertSame([WideningReason::NEW_TENANT], self::classify($principal, self::tenant('acct1'), true, null, $role)?->reasons);
    }

    /**
     * A grant reaching below where its own row did not is classified, and
     * widens; one held for one application, granted for every application, is
     * classified but widens nothing, since the identity already held a grant in
     * the tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExpandedReachIsClassified(): void
    {
        $principal = self::principal('p1');
        $role      = self::role('held');

        self::grants()->grantRole($principal, $role, tenant: self::tenant('acct1'), includeSubtree: false, application: 'admin');

        self::assertNull(self::classify($principal, self::tenant('acct1'), false, null, $role));

        self::grants()->grantRole($principal, $role, tenant: self::tenant('acct1'), includeSubtree: false);

        self::assertSame([WideningReason::NEW_SUBTREE], self::classify($principal, self::tenant('acct1'), true, null, $role)?->reasons);
    }

    /**
     * An expired grant of another principal, a boundary or nothing at all
     * proves nothing held.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExpiredGrantProvesNothingHeld(): void
    {
        self::grants()->grantRole(self::principal('p2'), self::role('held'), Carbon::now('UTC')->addHour(), tenant: self::tenant('acct1'));

        $this->travel(2)->hours();

        self::assertSame([WideningReason::NEW_TENANT], self::classify(self::principal('p1'), self::tenant('acct1'))?->reasons);
    }

    /**
     * With an incomplete list of principals a grant widens in doubt, even in a
     * tenant a listed principal holds a grant in, and after the reasons it has.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIncompleteDirectoryWidensInDoubt(): void
    {
        $person = self::person();

        self::grants()->grantRole(self::principal('p2'), self::role('held'), tenant: self::tenant('acct1'));

        $this->app?->instance(IdentityDirectory::class, new ListedIdentityDirectory([
            ListedIdentityDirectory::key(Reference::of($person)) => [Reference::of(self::principal('p2'))],
        ], false));

        self::assertSame([WideningReason::INCOMPLETE_DIRECTORY], self::classify(self::principal('p1'), self::tenant('acct1'))?->reasons);
        self::assertSame([WideningReason::NEW_TENANT, WideningReason::INCOMPLETE_DIRECTORY], self::classify(self::principal('p1'), self::tenant('acct2'))?->reasons);
    }

    /**
     * A tree that cannot be read widens in doubt, while a platform-wide grant
     * still widens as one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATreeThatCannotBeReadWidensInDoubt(): void
    {
        self::grants()->grantRole(self::principal('p2'), self::role('held'), tenant: self::tenant('acct1'));

        $this->app?->instance(TenantTree::class, new UnreadableTenantTree);

        self::assertSame([WideningReason::UNREADABLE_TREE], self::classify(self::principal('p1'), self::tenant('acct1'))?->reasons);
        self::assertSame([WideningReason::PLATFORM], self::classify(self::principal('p1'), null)?->reasons);
    }

    /**
     * A principal the resolver names no identity for, a grantee whose model
     * cannot be found, and a resolver that throws, are each refused when a
     * grant is classified; an unchanged grant needs no identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityThatCannotBeResolvedIsRefused(): void
    {
        $orphan = StubSecondIdentity::query()->create(['id' => 'orphan']);
        $role   = self::role('held');

        self::grants()->grantRole($orphan, $role);

        self::assertNull(self::classify($orphan, null, true, null, $role));
        self::assertRefused(static fn (): mixed => self::classify($orphan, self::tenant('acct1')));
        $missing = new Reference(StubSecondIdentity::class, 'missing');
        $untyped = new Reference('no-such-type', '1');

        self::assertRefused(static fn (): mixed => WideningClassifier::classify(Operation::begin(), $missing, [self::proposal(self::role('other'), null)]));
        self::assertRefused(static fn (): mixed => WideningClassifier::classify(Operation::begin(), $untyped, [self::proposal(self::role('third'), null)]));

        $this->app?->instance(SubjectResolver::class, new class implements SubjectResolver {
            /**
             * Resolve nothing.
             *
             * @return \SineMacula\Laravel\Authorization\Subject|null
             */
            #[\Override]
            public function resolve(): ?Subject
            {
                return null;
            }

            /**
             * Fail for every user.
             *
             * @param  object  $user
             * @return \SineMacula\Laravel\Authorization\Subject
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function forUser(object $user): Subject
            {
                throw new \RuntimeException('The resolver failed.');
            }
        });

        $refusal = self::refusalOf(static fn (): mixed => self::classify(self::principal('p1'), null));

        self::assertSame('The resolver failed.', $refusal->getPrevious()?->getMessage());
        self::assertSame(StubSecondIdentity::class, $refusal->grantee->type);
    }

    /**
     * A resolver that names another subject, or an identity that is not a saved
     * model, cannot say whose scope widens, so the grant is refused.
     *
     * @return void
     */
    public function testAnIdentityThatIsNotTheGranteesIsRefused(): void
    {
        $principal = self::principal('p1');
        $other     = StubSecondIdentity::query()->create(['id' => 'other']);

        $this->app?->instance(SubjectResolver::class, new PrincipalSubjectResolver(['p1' => new StubSecondIdentity(['id' => 'unsaved'])]));

        self::assertRefused(static fn (): mixed => self::classify($principal, null));

        $this->app?->instance(SubjectResolver::class, new class ($other, self::person()) implements SubjectResolver {
            /**
             * Create a resolver naming the subject and identity given.
             *
             * @param  object  $subject
             * @param  object  $identity
             */
            public function __construct(

                /** The subject every user is made. */
                private readonly object $subject,

                /** The identity every user is given. */
                private readonly object $identity,
            ) {}

            /**
             * Resolve nothing.
             *
             * @return \SineMacula\Laravel\Authorization\Subject|null
             */
            #[\Override]
            public function resolve(): ?Subject
            {
                return null;
            }

            /**
             * Name the fixed subject and identity, whoever the user is.
             *
             * @param  object  $user
             * @return \SineMacula\Laravel\Authorization\Subject
             */
            #[\Override]
            public function forUser(object $user): Subject
            {
                return new Subject($this->subject, $this->identity);
            }
        });

        self::assertRefused(static fn (): mixed => self::classify($principal, null));
    }

    /**
     * The widening carries the operation, its actor references, every widening
     * grant as proposed with its reasons, a grant that widens nothing left out,
     * and when it was observed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheWideningCarriesTheProposal(): void
    {
        $principal = self::principal('p1');
        $operation = Operation::begin(new Reference('admins', 'a1'));
        $held      = self::role('held');
        $expiresAt = Carbon::now('UTC')->addDay()->startOfSecond();

        self::grants()->grantRole($principal, $held, tenant: self::tenant('acct1'));

        $widening = WideningClassifier::classify($operation, $principal, [
            self::proposal($held, self::tenant('acct1')),
            self::proposal(self::role('new'), self::tenant('acct2'), false, $expiresAt),
        ]);

        self::assertInstanceOf(GrantWidening::class, $widening);
        self::assertSame($operation->id, $widening->operationId);
        self::assertTrue($widening->isTrusted);
        self::assertSame('a1', $widening->actor?->id);
        self::assertNull($widening->actorIdentity);
        self::assertCount(1, $widening->changes);
        self::assertSame('acct2', $widening->changes[0]->tenant?->id);
        self::assertFalse($widening->changes[0]->includeSubtree);
        self::assertSame($expiresAt->getTimestamp(), $widening->changes[0]->expiresAt?->getTimestamp());
        self::assertEqualsWithDelta(Carbon::now('UTC')->getTimestamp(), $widening->observedAt->getTimestamp(), 2);
        self::assertSame('UTC', $widening->observedAt->getTimezone()->getName());
    }

    /**
     * A proposal of an action no grant table answers, such as a membership the
     * application proposes, is classified as a new grant; no proposal at all
     * widens nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProposalNoTableAnswersIsClassifiedAsNew(): void
    {
        $proposal = new ProposedGrant('membership.create', new Reference('memberships', '1'), self::tenant('acct1'), null, true, null);

        self::assertSame([WideningReason::NEW_TENANT], WideningClassifier::classify(Operation::begin(), self::principal('p1'), [$proposal])?->reasons);
        self::assertNull(WideningClassifier::classify(Operation::begin(), self::principal('p1'), []));
    }

    /**
     * A permission granted directly is classified as a role is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPermissionIsClassifiedAsARoleIs(): void
    {
        $principal  = self::principal('p1');
        $permission = Permission::query()->create(['name' => 'posts:edit']);

        self::grants()->grantPermission($principal, $permission, tenant: self::tenant('acct1'));

        $unchanged = ProposedGrant::of(GrantTarget::PERMISSION, $permission, new GrantScope(self::tenant('acct1'), null, true), null);

        self::assertNull(WideningClassifier::classify(Operation::begin(), $principal, [$unchanged]));
        self::assertSame([WideningReason::NEW_TENANT], WideningClassifier::classify(Operation::begin(), $principal, [
            ProposedGrant::of(GrantTarget::PERMISSION, $permission, new GrantScope(self::tenant('acct2'), null, true), null),
        ])?->reasons);
    }

    /**
     * A grant that widens nothing does not stop the classification: a later
     * grant of the call that widens is still found, alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantThatWidensNothingLeavesTheNextClassified(): void
    {
        $principal = self::principal('p1');

        self::grants()->grantRole($principal, self::role('held'), tenant: self::tenant('acct1'));

        $widening = WideningClassifier::classify(Operation::begin(), $principal, [
            self::proposal(self::role('beside'), self::tenant('acct1')),
            self::proposal(self::role('elsewhere'), self::tenant('acct2')),
        ]);

        self::assertNotNull($widening);
        self::assertCount(1, $widening->changes);
        self::assertSame('acct2', $widening->changes[0]->tenant?->id);
        self::assertSame([WideningReason::NEW_TENANT], $widening->reasons);
    }

    /**
     * A grantee named by reference is resolved from its model, its identity and
     * itself as for the model.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGranteeByReferenceIsResolvedFromItsModel(): void
    {
        $widening = WideningClassifier::classify(Operation::begin(), Reference::of(self::principal('p1')), [self::proposal(self::role('by-reference'), self::tenant('acct2'))]);

        self::assertSame([WideningReason::NEW_TENANT], $widening?->reasons);
        self::assertSame([StubSecondIdentity::class, 'p1'], [$widening->grantee->type, $widening->grantee->id]);
        self::assertSame([StubIdentity::class, 'person'], [$widening->identity->type, $widening->identity->id]);
    }

    /**
     * Inside a batch of checks, the tenant's chain is read afresh each time, so
     * a move of the tenant the tree did not report is seen by the next
     * classification: into an organisation another principal holds a grant in,
     * and out of it again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheChainIsReadAfreshInsideABatch(): void
    {
        $principal = self::principal('p1');
        $cache     = ResolutionCache::instance();

        self::grants()->grantRole(self::principal('p2'), self::role('held'), tenant: self::tenant('org2'));

        self::assertNotNull($cache);

        $reasons = $cache->batch(static function () use ($principal): array {
            $reasons = [self::classify($principal, self::tenant('acct2'))?->reasons];

            self::move('acct2', 'org2');

            $reasons[] = self::classify($principal, self::tenant('acct2'))?->reasons;

            self::move('acct2', 'org1');

            $reasons[] = self::classify($principal, self::tenant('acct2'))?->reasons;

            return $reasons;
        });

        self::assertSame([[WideningReason::NEW_TENANT], null, [WideningReason::NEW_TENANT]], $reasons);
    }

    /**
     * A resolver that makes the grantee a subject that is not a model cannot
     * say whose scope widens, even with the grantee's own identity, so the
     * grant is refused.
     *
     * @return void
     */
    public function testASubjectThatIsNotAModelIsRefused(): void
    {
        $this->app?->instance(SubjectResolver::class, new class (self::person()) implements SubjectResolver {
            /**
             * Create a resolver naming the identity given.
             *
             * @param  object  $identity
             */
            public function __construct(

                /** The identity every user is given. */
                private readonly object $identity,
            ) {}

            /**
             * Resolve nothing.
             *
             * @return \SineMacula\Laravel\Authorization\Subject|null
             */
            #[\Override]
            public function resolve(): ?Subject
            {
                return null;
            }

            /**
             * Make every user a subject that is not a model.
             *
             * @param  object  $user
             * @return \SineMacula\Laravel\Authorization\Subject
             */
            #[\Override]
            public function forUser(object $user): Subject
            {
                return new Subject(new \stdClass, $this->identity);
            }
        });

        self::assertRefused(static fn (): mixed => self::classify(self::principal('p1'), null));
    }

    /**
     * Asked to lock, the classification answers as it does without, reading the
     * grantee's own row and the grants that apply under the lock; without, it
     * locks nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALockedClassificationAnswersAsAnUnlockedOne(): void
    {
        $principal = self::principal('p1');
        $role      = self::role('proposed');

        self::grants()->grantRole(self::principal('p2'), self::role('held'), tenant: self::tenant('acct1'), includeSubtree: false);

        $locks     = $this->recordRowLocks();
        $proposals = [
            'held'      => self::proposal($role, self::tenant('acct1'), false),
            'below'     => self::proposal($role, self::tenant('acct1')),
            'elsewhere' => self::proposal($role, self::tenant('acct2')),
        ];

        foreach ($proposals as $case => $proposal) {
            $unlocked = WideningClassifier::classify(Operation::begin(), $principal, [$proposal])?->reasons;

            self::assertCount(0, $locks, $case);
            self::assertSame($unlocked, WideningClassifier::classify(Operation::begin(), $principal, [$proposal], isLocked: true)?->reasons, $case);
            self::assertNotCount(0, $locks, $case);

            $locks->exchangeArray([]);
        }

        self::assertSame([WideningReason::NEW_SUBTREE], WideningClassifier::classify(Operation::begin(), $principal, [$proposals['below']], isLocked: true)?->reasons);
        $roles = 'authorizable_roles';

        self::assertSame([$roles, $roles, $roles, 'authorizable_permissions', 'authorizable_policies'], \array_column($locks->getArrayCopy(), 0));
    }

    /**
     * Assert that the call is refused for an identity that cannot be resolved.
     *
     * @param  \Closure(): mixed  $call
     * @return void
     */
    private static function assertRefused(\Closure $call): void
    {
        self::assertInstanceOf(UnresolvableRecipientException::class, self::refusalOf($call));
    }

    /**
     * Run the call and return the refusal it throws.
     *
     * @param  \Closure(): mixed  $call
     * @return \SineMacula\Laravel\Authorization\Exceptions\UnresolvableRecipientException
     */
    private static function refusalOf(\Closure $call): UnresolvableRecipientException
    {
        try {
            $call();
        } catch (UnresolvableRecipientException $refusal) {
            return $refusal;
        }

        self::fail('The identity was resolved.');
    }

    /**
     * Classify a grant of a role to the grantee, a new role unless one is
     * given, in the tenant or platform-wide.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \SineMacula\Laravel\Authorization\Models\Role|null  $role
     * @return \SineMacula\Laravel\Authorization\Hooks\GrantWidening|null
     *
     * @throws \Throwable
     */
    private static function classify(Model $grantee, ?Reference $tenant, bool $includeSubtree = true, ?\DateTimeInterface $expiresAt = null, ?Role $role = null): ?GrantWidening
    {
        return WideningClassifier::classify(Operation::begin(), $grantee, [self::proposal($role ?? self::role('proposed-' . \uniqid()), $tenant, $includeSubtree, $expiresAt)]);
    }

    /**
     * Return the proposed grant of the role, in the tenant or platform-wide.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @param  \DateTimeInterface|null  $expiresAt
     * @return \SineMacula\Laravel\Authorization\Hooks\ProposedGrant
     */
    private static function proposal(Role $role, ?Reference $tenant, bool $includeSubtree = true, ?\DateTimeInterface $expiresAt = null): ProposedGrant
    {
        return ProposedGrant::of(GrantTarget::ROLE, $role, new GrantScope($tenant, null, $includeSubtree || $tenant === null), $expiresAt);
    }

    /**
     * Create a platform role with the name.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private static function role(string $name): Role
    {
        return Role::query()->create(['name' => $name]);
    }

    /**
     * Move the account under the organisation in the closure-table tree,
     * without reporting the move.
     *
     * @param  string  $account
     * @param  string  $organisation
     * @return void
     */
    private static function move(string $account, string $organisation): void
    {
        DB::table(ClosureTenantTree::TABLE)->where('descendant_id', $account)->where('depth', '>', 0)->delete();
        DB::table(ClosureTenantTree::TABLE)->insert([
            'ancestor_type'   => 'tenant',
            'ancestor_id'     => $organisation,
            'descendant_type' => 'tenant',
            'descendant_id'   => $account,
            'depth'           => 1,
        ]);
    }

    /**
     * Return the identity.
     *
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private static function person(): StubIdentity
    {
        return StubIdentity::query()->findOrFail('person');
    }

    /**
     * Return the principal with the key.
     *
     * @param  string  $id
     * @return \Tests\Feature\Stubs\StubSecondIdentity
     */
    private static function principal(string $id): StubSecondIdentity
    {
        return StubSecondIdentity::query()->findOrFail($id);
    }

    /**
     * Return the grant service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService
     */
    private static function grants(): GrantService
    {
        /** @var \SineMacula\Laravel\Authorization\Services\GrantService */
        return app(GrantService::class);
    }
}
