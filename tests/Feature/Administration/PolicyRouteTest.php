<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\DocumentComparison;
use SineMacula\Laravel\Authorization\Administration\FurtherChecks;
use SineMacula\Laravel\Authorization\Administration\OperationChange;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Administration\PolicyRoute;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\CheckSources;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\SessionCaps;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\DocumentDigest;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `PolicyRoute`: whether handing out a policy hands out only
 * what the actor may hand out, by containment or `policy.grantable` on the
 * policy's digest.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PolicyRoute::class)]
final class PolicyRouteTest extends TestCase
{
    /** @var list<array{string, \SineMacula\Laravel\Authorization\Support\ResourceReference|null}> Each further check asked, with its resource. */
    private array $asked = [];

    /**
     * A policy that allows nothing hands nothing out, so it passes without a
     * further check; its denies never count.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyThatAllowsNothingPasses(): void
    {
        $policy = self::policy('denying', [['effect' => 'deny', 'actions' => ['posts:*']]]);

        self::assertNull(PolicyRoute::refusal(...self::attach($policy), ...[$this->checks(self::user('admin'), false)]));
        self::assertSame([], $this->asked);
    }

    /**
     * A policy whose allows name their actions alone is contained when the
     * actor provably holds every action: one it holds passes, one it does not
     * is refused as not grantable, unless `policy.grantable` is allowed on the
     * descriptor naming the policy and its digest.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAContainedPolicyPassesThePermissionRoute(): void
    {
        $actor  = self::user('admin');
        $policy = self::policy('editor', [['effect' => 'allow', 'actions' => ['posts:read', 'posts:edit']], ['effect' => 'allow', 'actions' => ['posts:read']]]);

        self::grants()->grantPermission($actor, Permission::query()->create(['name' => 'posts:read']));

        self::assertSame(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, PolicyRoute::refusal(...[...self::attach($policy), $this->checks($actor, false)]));

        $descriptor = \array_values(\array_filter($this->asked, static fn (array $asked): bool => $asked[0] === PackagePermissions::POLICY_GRANTABLE))[0][1] ?? null;
        $source     = $descriptor?->source;

        self::assertInstanceOf(OperationResource::class, $source);
        self::assertSame(DocumentDigest::of($policy->document)->digest, $source->attributes()['digest']);
        self::assertSame('editor', $source->attributes()['policy']);
        self::assertNull(PolicyRoute::refusal(...[...self::attach($policy), $this->checks($actor, true)]));

        self::grants()->grantPermission($actor, Permission::query()->create(['name' => 'posts:edit']));

        self::assertNull(PolicyRoute::refusal(...[...self::attach($policy), $this->checks($actor, false)]));
    }

    /**
     * A policy whose allows name anything but their actions, resources,
     * conditions, `not_actions` or principals, cannot be proved contained, so
     * it is unprovable unless `policy.grantable` allows it; a resource policy's
     * principals are weighed by the impact check instead, so they never stand
     * in the way there.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyThatCannotBeContainedNeedsTheGrantableRight(): void
    {
        $actor = self::user('admin');

        self::grants()->grantPermission($actor, Permission::query()->create(['name' => 'posts:*']));

        $statements = [
            'resources'   => ['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['posts:1']],
            'excluded'    => ['effect' => 'allow', 'actions' => ['posts:read'], 'not_resources' => ['posts:1']],
            'not actions' => ['effect' => 'allow', 'not_actions' => ['posts:read']],
            'conditions'  => ['effect' => 'allow', 'actions' => ['posts:read'], 'conditions' => ['eq' => ['resource.id' => '1']]],
        ];

        foreach ($statements as $name => $statement) {
            $policy = self::policy($name, [$statement]);

            self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, PolicyRoute::refusal(...[...self::attach($policy), $this->checks($actor, false)]), $name);
            self::assertNull(PolicyRoute::refusal(...[...self::attach($policy), $this->checks($actor, true)]), $name);
        }

        $sharing = self::policy('sharing', [['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:1']]]);
        $onPosts = OperationResource::grant(PackagePermissions::RESOURCE_POLICY_ATTACH, new Reference('posts', '*'), $sharing, GrantScope::platform());

        self::assertNull(PolicyRoute::refusal($onPosts, self::changeOf($onPosts), $sharing, $this->checks($actor, false)));

        $toUser = OperationResource::grant(PackagePermissions::POLICY_ATTACH, self::user('user'), $sharing, GrantScope::platform());

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, PolicyRoute::refusal($toUser, self::changeOf($toUser), $sharing, $this->checks($actor, false)));
    }

    /**
     * Allows that cannot be read are unprovable, unless the grantable right
     * allows the document; a document whose digest cannot be taken is never
     * grantable.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAllowsThatCannotBeReadAreUnprovable(): void
    {
        $actor  = self::user('admin');
        $policy = self::policy('editor', [['effect' => 'allow', 'actions' => ['posts:read']]]);

        [$operation, $change] = self::attach($policy);

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, PolicyRoute::refusalOf($operation, $change, $policy, $policy->document, null, $this->checks($actor, false)));
        self::assertNull(PolicyRoute::refusalOf($operation, $change, $policy, $policy->document, null, $this->checks($actor, true)));
        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, PolicyRoute::refusalOf($operation, $change, $policy, 'not a document', null, $this->checks($actor, true)));
        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, PolicyRoute::refusalOf($operation, $change, $policy, ['bad' => \NAN], null, $this->checks($actor, true)));
        self::assertNull(PolicyRoute::allowsOf(null));
        self::assertCount(1, PolicyRoute::allowsOf(DocumentComparison::read($policy->document)) ?? []);
    }

    /**
     * Return the operation, its change and the policy of a proposed attachment
     * of the policy to a grantee, platform-wide.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return array{
     *     \SineMacula\Laravel\Authorization\Administration\OperationResource,
     *     \SineMacula\Laravel\Authorization\Administration\OperationChange,
     *     \SineMacula\Laravel\Authorization\Models\Policy
     * }
     */
    private static function attach(Policy $policy): array
    {
        $operation = OperationResource::grant(PackagePermissions::POLICY_ATTACH, self::user('grantee'), $policy, GrantScope::platform());

        return [$operation, self::changeOf($operation), $policy];
    }

    /**
     * Return the change of the operation.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @return \SineMacula\Laravel\Authorization\Administration\OperationChange
     */
    private static function changeOf(OperationResource $operation): OperationChange
    {
        $change = $operation->change;

        self::assertInstanceOf(OperationChange::class, $change);

        return $change;
    }

    /**
     * Return further checks for the actor: the grantable rights allowed, the
     * actor then holding `policy.grantable` for good, or refused, as given, any
     * other check allowed, every source read empty, recording what was asked.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $actor
     * @param  bool  $grantable
     * @return \SineMacula\Laravel\Authorization\Administration\FurtherChecks
     *
     * @throws \Throwable
     */
    private function checks(StubIdentity $actor, bool $grantable): FurtherChecks
    {
        $this->asked = [];

        if ($grantable) {
            self::grants()->grantPermission($actor, Permission::query()->firstOrCreate(['name' => PackagePermissions::POLICY_GRANTABLE]));
        }

        $decide = function (string $action, ?ResourceReference $on) use ($grantable): Decision {
            $this->asked[] = [$action, $on];

            $isGrantable = \in_array($action, [PackagePermissions::PERMISSION_GRANTABLE, PackagePermissions::POLICY_GRANTABLE], true);

            return !$isGrantable || $grantable ? Decision::allow(DecisionStage::ALLOW) : Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);
        };
        $sources = static fn (): CheckSources => new CheckSources([], null, [], new CheckContext, static fn (): ?string => null, new SessionCaps);

        return new FurtherChecks(new Subject($actor, $actor), $decide, $sources);
    }

    /**
     * Create a policy of the statements.
     *
     * @param  string  $name
     * @param  list<array<string, mixed>>  $statements
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function policy(string $name, array $statements): Policy
    {
        return Policy::create(['name' => \str_replace(' ', '-', $name), 'document' => ['statements' => $statements]]);
    }

    /**
     * Return the identity with the id, created on first use.
     *
     * @param  string  $id
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private static function user(string $id): StubIdentity
    {
        return StubIdentity::query()->firstOrCreate(['id' => $id]);
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
