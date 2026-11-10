<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\FurtherChecks;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Administration\PolicyRewrite;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\CheckSources;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\SessionCaps;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\PolicyDocument;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `PolicyRewrite`: a delegated rewrite of a policy's
 * document, compared with the stored one conservatively.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PolicyRewrite::class)]
final class PolicyRewriteTest extends TestCase
{
    /** @var array<string, mixed> An allow of reading posts. */
    private const array READ = ['effect' => 'allow', 'actions' => ['posts:read']];

    /** @var array<string, mixed> An allow of editing posts. */
    private const array EDIT = ['effect' => 'allow', 'actions' => ['posts:edit']];

    /** @var array<string, mixed> A deny of deleting posts. */
    private const array DENY = ['effect' => 'deny', 'actions' => ['posts:delete']];

    /** @var list<string> The further checks asked, by action. */
    private array $asked = [];

    /**
     * A rewrite that only narrows passes without a further check; one that
     * lifts a deny, or whose document cannot be read, is unprovable; one that
     * adds allows to a policy no one holds widens no one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARewriteIsComparedWithTheStoredDocument(): void
    {
        $policy = self::policy([self::READ, self::EDIT, self::DENY]);

        self::assertNull($this->refusal($policy, [self::READ, self::DENY]));
        self::assertNull($this->refusal($policy, [self::EDIT, self::READ, self::DENY, ['effect' => 'deny', 'actions' => ['posts:read']]]));
        self::assertSame([], $this->asked);
        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, $this->refusal($policy, [self::READ, self::EDIT]));
        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, $this->refusal($policy, null));
        self::assertNull($this->refusal($policy, [self::READ, self::EDIT, self::DENY, ['effect' => 'allow', 'actions' => ['posts:archive']]]));
    }

    /**
     * A rewrite that adds allows to a policy someone holds needs the impact
     * check, then the policy route for the allows it adds alone; one that
     * widens a policy in use as a boundary needs `administration.unbounded`
     * before the route is asked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWideningRewriteNeedsTheImpactCheckAndTheRoute(): void
    {
        $policy  = self::policy([self::READ, self::DENY]);
        $archive = ['effect' => 'allow', 'actions' => ['posts:archive']];

        self::grants()->attachPolicy(StubIdentity::query()->create(['id' => 'holder']), $policy);
        self::grants()->grantPermission(self::actor(), Permission::query()->create(['name' => 'posts:edit']));

        self::assertNull($this->refusal($policy, [self::READ, self::EDIT, self::DENY]));
        self::assertSame(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, $this->refusal($policy, [self::READ, $archive, self::DENY]));

        BoundaryService::instance()?->set(StubIdentity::query()->create(['id' => 'bounded']), $policy);

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, $this->refusal($policy, [self::READ, self::EDIT, self::DENY]));
        self::assertNotContains('posts:edit', $this->asked);
        self::assertContains(PackagePermissions::ADMINISTRATION_UNBOUNDED, $this->asked);
        self::assertNull($this->refusal($policy, [self::READ, self::EDIT, self::DENY], true));
    }

    /**
     * The unbounded right a widening rewrite of a boundary policy needs is
     * weighed across the policy's whole reach: allowed while nothing limits it,
     * the rewrite refused as unprovable once the actor holds a role in one
     * tenant whose policy denies `authorization:administration.unbounded`,
     * though the right is allowed where the rewrite is decided.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheUnboundedRightIsWeighedAcrossThePolicysReach(): void
    {
        $policy = self::policy([self::READ, self::DENY]);
        $deny   = Policy::create(['name' => 'restricting', 'document' => ['statements' => [['effect' => 'deny', 'actions' => [PackagePermissions::ADMINISTRATION_UNBOUNDED]]]]]);
        $role   = Role::query()->create(['name' => 'restricted']);

        self::grants()->grantPermission(self::actor(), Permission::query()->create(['name' => 'posts:edit']));
        BoundaryService::instance()?->set(StubIdentity::query()->create(['id' => 'bounded']), $policy);

        self::assertNull($this->refusal($policy, [self::READ, self::EDIT, self::DENY], true));

        self::grants()->attachPolicy($role, $deny);
        self::grants()->grantRole(self::actor(), $role, tenant: new Reference('tenant', 't0'));

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, $this->refusal($policy, [self::READ, self::EDIT, self::DENY], true));
        self::assertNotContains('posts:edit', $this->asked);
    }

    /**
     * A rewrite that only narrows passes whoever holds the policy; one that
     * adds allows to a policy attached to a resource reaches the principals the
     * old document names as well as those of the new; and the rewrite of a
     * policy that is gone cannot be compared, so it is unprovable.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheHoldersOfBothDocumentsAreWeighed(): void
    {
        $peer = StubIdentity::query()->create(['id' => 'peer']);

        self::grants()->grantRole($peer, Role::query()->create(['name' => 'peer', 'rank' => 0]));

        $named  = Reference::of($peer);
        $policy = self::policy([[...self::READ, 'principals' => [$named->type . ':' . $named->id]], self::DENY]);

        ResourcePolicyService::instance()?->attach($policy, ['posts', 7]);

        self::assertNull($this->refusal($policy, [self::DENY]));
        self::assertSame(DecisionReason::ADMINISTRATION_RANK, $this->refusal($policy, [self::EDIT, self::DENY]));

        DB::table('policies')->where('id', $policy->getKey())->delete();

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, $this->refusal($policy, [self::DENY]));
    }

    /**
     * Return why rewriting the policy to the statements, or to a document that
     * cannot be read for null, is refused, the actor ranked most senior and
     * every further check allowed but `administration.unbounded`, unless given.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  list<array<string, mixed>>|null  $statements
     * @param  bool  $unbounded
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     *
     * @throws \Throwable
     */
    private function refusal(Policy $policy, ?array $statements, bool $unbounded = false): ?DecisionReason
    {
        $this->asked = [];

        $actor     = self::actor();
        $document  = $statements === null ? null : PolicyDocument::named(['statements' => $statements], $policy->name);
        $operation = OperationResource::definition(PackagePermissions::POLICY_UPDATE, $policy, [], $document);
        $decide    = function (string $action) use ($unbounded): Decision {
            $this->asked[] = $action;

            $isAllowed = $action !== PackagePermissions::ADMINISTRATION_UNBOUNDED || $unbounded;

            return $isAllowed ? Decision::allow(DecisionStage::ALLOW) : Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);
        };
        $sources = static fn (): CheckSources => new CheckSources([], null, [], new CheckContext, static fn (): ?string => null, new SessionCaps);
        $checks  = new FurtherChecks(new Subject($actor, $actor), $decide, $sources);

        return PolicyRewrite::refusal($operation, $policy, $document, $operation->toResourceReference(), $checks);
    }

    /**
     * Return the actor, holding the most senior rank, created on first use.
     *
     * @return \Tests\Feature\Stubs\StubIdentity
     *
     * @throws \Throwable
     */
    private static function actor(): StubIdentity
    {
        $actor = StubIdentity::query()->firstOrCreate(['id' => 'admin']);

        if (!$actor->hasRole('chief')) {
            self::grants()->grantRole($actor, Role::query()->create(['name' => 'chief', 'rank' => 0]));
        }

        return $actor;
    }

    /**
     * Create a policy of the statements.
     *
     * @param  list<array<string, mixed>>  $statements
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function policy(array $statements): Policy
    {
        return Policy::create(['name' => 'editor', 'document' => ['statements' => $statements]]);
    }

    /**
     * Return the grant service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService
     */
    private static function grants(): GrantService
    {
        return app(GrantService::class);
    }
}
