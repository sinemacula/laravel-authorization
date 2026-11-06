<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Events\Policy\Created as PolicyCreated;
use SineMacula\Laravel\Authorization\Events\Policy\Deleted as PolicyDeleted;
use SineMacula\Laravel\Authorization\Events\Policy\Updated as PolicyUpdated;
use SineMacula\Laravel\Authorization\Exceptions\BoundaryException;
use SineMacula\Laravel\Authorization\Exceptions\GuardrailException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPolicyOwnerException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\OwnerChangedException;
use SineMacula\Laravel\Authorization\Exceptions\ResourcePolicyException;
use SineMacula\Laravel\Authorization\Exceptions\SystemInlinePolicyException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Observers\PolicyObserver;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\GuardrailService;
use SineMacula\Laravel\Authorization\Services\PolicyService;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Support\DocumentDigest;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\CatchesRefusals;
use Tests\Concerns\ComparesReferences;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the policy observer's tenant-columns invariant: a policy is
 * owned by the platform (both tenant columns null) or by one tenant (both set),
 * never half of each. The events the observer builds are pinned too: each
 * carries the digest of the document, never the document itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PolicyObserver::class)]
final class PolicyObserverTest extends TestCase
{
    use CatchesRefusals, ComparesReferences;

    /**
     * A platform-wide policy saves.
     *
     * @return void
     */
    public function testPlatformPolicySaves(): void
    {
        $policy = Policy::query()->create(['name' => 'readers', 'document' => self::document()]);

        self::assertNull($policy->tenant_type);
        self::assertNull($policy->tenant_id);
    }

    /**
     * A tenant-owned policy saves with both tenant columns.
     *
     * @return void
     */
    public function testTenantOwnedPolicySaves(): void
    {
        $policy = Policy::query()->create(['name' => 'readers', 'document' => self::document(), 'tenant_type' => 'tenant', 'tenant_id' => 'tenant-a']);

        $fresh = Policy::query()->findOrFail($policy->id);

        self::assertSame('tenant', $fresh->tenant_type);
        self::assertSame('tenant-a', $fresh->tenant_id);
    }

    /**
     * A tenant type without a tenant id is refused, naming the missing column.
     *
     * @return void
     */
    public function testTenantTypeWithoutIdIsRefused(): void
    {
        $this->expectException(InvalidTenantColumnsException::class);
        $this->expectExceptionMessage('Cannot save policy with inconsistent tenant columns — \'tenant_id\' is required');

        Policy::query()->create(['name' => 'readers', 'document' => self::document(), 'tenant_type' => 'tenant']);
    }

    /**
     * A tenant id without a tenant type is refused, naming the missing column.
     *
     * @return void
     */
    public function testTenantIdWithoutTypeIsRefused(): void
    {
        $this->expectException(InvalidTenantColumnsException::class);
        $this->expectExceptionMessage('Cannot save policy with inconsistent tenant columns — \'tenant_type\' is required');

        Policy::query()->create(['name' => 'readers', 'document' => self::document(), 'tenant_id' => 'tenant-a']);
    }

    /**
     * Clearing one tenant column of a stored policy is refused too.
     *
     * @return void
     */
    public function testClearingOneTenantColumnIsRefused(): void
    {
        $policy = Policy::query()->create(['name' => 'readers', 'document' => self::document(), 'tenant_type' => 'tenant', 'tenant_id' => 'tenant-a']);

        $this->expectException(InvalidTenantColumnsException::class);

        $policy->update(['tenant_id' => null]);
    }

    /**
     * An inline policy saves with both owner columns; one owner column without
     * the other is refused, naming the missing column.
     *
     * @return void
     */
    public function testAnInlinePolicyNeedsBothOwnerColumns(): void
    {
        $inline = Policy::query()->create(['name' => 'mine', 'document' => self::document(), 'owner_type' => 'user', 'owner_id' => '1']);

        self::assertSame('user', Policy::query()->findOrFail($inline->id)->owner_type);

        $this->expectException(InvalidPolicyOwnerException::class);
        $this->expectExceptionMessage('Cannot save policy \'half\' with inconsistent owner columns: \'owner_id\' is required');

        Policy::query()->create(['name' => 'half', 'document' => self::document(), 'owner_type' => 'user']);
    }

    /**
     * The grantee an inline policy belongs to cannot change once it is created,
     * nor can a managed policy become inline.
     *
     * @return void
     */
    public function testTheOwnerOfAPolicyCannotChange(): void
    {
        $inline  = Policy::query()->create(['name' => 'mine', 'document' => self::document(), 'owner_type' => 'user', 'owner_id' => '1']);
        $managed = Policy::query()->create(['name' => 'shared', 'document' => self::document()]);

        foreach ([[$inline, ['owner_id' => '2']], [$inline, ['owner_type' => 'team']], [$managed, ['owner_type' => 'user', 'owner_id' => '2']]] as [$policy, $change]) {
            $refusal = self::refusalOf(static fn () => $policy->update($change));

            self::assertInstanceOf(OwnerChangedException::class, $refusal);
            self::assertSame($policy->name, $refusal->getName());

            $policy->refresh();
        }

        self::assertSame('user', Policy::query()->findOrFail($inline->id)->owner_type);
        self::assertSame('1', Policy::query()->findOrFail($inline->id)->owner_id);
        self::assertNull(Policy::query()->findOrFail($managed->id)->owner_id);
    }

    /**
     * An inline policy is refused as a system policy, whether it is created as
     * one or flagged later, and nothing is written.
     *
     * @return void
     */
    public function testAnInlinePolicyCannotBeASystemPolicy(): void
    {
        $owner  = ['owner_type' => 'user', 'owner_id' => '1'];
        $inline = Policy::query()->create(['name' => 'mine', 'document' => self::document()] + $owner);

        $refusals = [
            'created as a system policy' => static fn () => Policy::query()->create(['name' => 'root', 'document' => self::document(), 'is_system' => true] + $owner),
            'flagged later'              => static fn () => $inline->update(['is_system' => true]),
        ];

        foreach ($refusals as $case => $refused) {
            self::assertInstanceOf(SystemInlinePolicyException::class, self::refusalOf($refused), $case);
        }

        self::assertSame(['mine'], Policy::query()->pluck('name')->all());
        self::assertFalse(Policy::query()->findOrFail($inline->id)->is_system);
    }

    /**
     * A rewrite that breaks the `principals` rule for where the policy is
     * attached is refused before it is written: principals on a policy attached
     * to a grantee, an allow naming none on a resource policy.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARewriteBreakingThePrincipalsRuleIsRefused(): void
    {
        $named   = ['statements' => [['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:1']]]];
        $unnamed = ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]];
        $own     = Policy::query()->create(['name' => 'own', 'document' => $unnamed]);
        $sharing = Policy::query()->create(['name' => 'sharing', 'document' => $named]);

        $this->app?->make(GrantService::class)->attachPolicy(new Reference('user', '1'), $own);
        $this->app?->make(ResourcePolicyService::class)->attach($sharing, 'posts');

        self::assertInstanceOf(ResourcePolicyException::class, self::refusalOf(static fn () => $own->update(['document' => $named])));
        self::assertInstanceOf(ResourcePolicyException::class, self::refusalOf(static fn () => $sharing->update(['document' => $unnamed])));
        self::assertNull(Policy::query()->findOrFail($own->id)->document['statements'][0]['principals'] ?? null);
        self::assertSame(['user:1'], Policy::query()->findOrFail($sharing->id)->document['statements'][0]['principals'] ?? null);
    }

    /**
     * Deleting a policy in use as a permission boundary is refused before
     * anything is read or reported; once the boundary is removed, it is
     * deleted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeletingAPolicyInUseAsABoundaryIsRefused(): void
    {
        $policy     = Policy::query()->create(['name' => 'cap', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]]);
        $boundaries = $this->app?->make(BoundaryService::class);

        self::assertNotNull($boundaries);

        $boundaries->set(new Reference('user', '1'), $policy);

        Event::fake([PolicyDeleted::class]);

        self::assertInstanceOf(BoundaryException::class, self::refusalOf(static fn () => $policy->delete()));
        self::assertNotNull(Policy::query()->find($policy->id));
        Event::assertNotDispatched(PolicyDeleted::class);

        $boundaries->remove(new Reference('user', '1'));

        self::assertTrue($policy->delete());
        Event::assertDispatched(PolicyDeleted::class);
    }

    /**
     * Editing or deleting a policy in use as a guardrail is refused before
     * anything is written or reported, through the model and the policy service
     * alike; once the guardrail is removed through the guardrail service, it is
     * edited and deleted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEditingOrDeletingAPolicyInUseAsAGuardrailIsRefused(): void
    {
        $policy     = Policy::query()->create(['name' => 'rail', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['authorization:*']]]]]);
        $guardrails = $this->app?->make(GuardrailService::class);
        $policies   = $this->app?->make(PolicyService::class);
        $actor      = StubIdentity::create(['id' => 'admin-1']);

        self::assertNotNull($guardrails);
        self::assertNotNull($policies);

        $actor->givePermission(Permission::create(['name' => PackagePermissions::GUARDRAILS_MANAGE]));
        $guardrails->set($policy, null, $actor);

        Event::fake([PolicyUpdated::class, PolicyDeleted::class]);

        $rewrite = ['statements' => [['effect' => 'allow', 'actions' => ['*']]]];

        foreach ([static fn () => $policy->update(['document' => $rewrite]), static fn () => $policies->rewrite($policy, $rewrite), static fn () => $policy->delete()] as $change) {
            $refusal = self::refusalOf($change);

            self::assertInstanceOf(GuardrailException::class, $refusal);
            self::assertSame(GuardrailException::IN_USE, $refusal->getReason());
        }

        self::assertSame(['authorization:*'], Policy::query()->findOrFail($policy->id)->document['statements'][0]['actions'] ?? null);
        Event::assertNotDispatched(PolicyUpdated::class);
        Event::assertNotDispatched(PolicyDeleted::class);

        $guardrails->remove($policy, null, $actor);

        self::assertTrue($policy->refresh()->update(['document' => $rewrite]));
        self::assertTrue($policy->delete());
        Event::assertDispatched(PolicyUpdated::class);
        Event::assertDispatched(PolicyDeleted::class);
    }

    /**
     * A rewrite that names principals is refused while the policy is a
     * grantee's boundary.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARewriteNamingPrincipalsIsRefusedForABoundary(): void
    {
        $policy = Policy::query()->create(['name' => 'cap', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]]);

        $this->app?->make(BoundaryService::class)->set(new Reference('user', '1'), $policy);

        $named = ['statements' => [['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:1']]]];

        self::assertInstanceOf(ResourcePolicyException::class, self::refusalOf(static fn () => $policy->update(['document' => $named])));
        self::assertNull(Policy::query()->findOrFail($policy->id)->document['statements'][0]['principals'] ?? null);
    }

    /**
     * Creating a policy reports its reference, name, tenant, system flag and
     * the version and digest of its document, never the document.
     *
     * @return void
     */
    public function testReportsThePolicyCreatedWithTheDigestOfItsDocument(): void
    {
        Event::fake([PolicyCreated::class]);

        $policy = Policy::query()->create(['name' => 'audit', 'document' => self::document(), 'tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-a']);
        $system = Policy::query()->create(['name' => 'root', 'document' => self::document(), 'is_system' => true]);

        Event::assertDispatchedTimes(PolicyCreated::class, 2);
        Event::assertDispatched(PolicyCreated::class, static fn (PolicyCreated $event): bool => self::refersTo($event->policy, $policy)
            && $event->name === 'audit'
            && self::refersTo($event->tenant, new Reference('stub_tenant', 'tenant-a'))
            && $event->document->digest  === DocumentDigest::of($policy->document)->digest
            && $event->document->version === 1
            && !$event->isSystem
            && $event->operation->actor === null);
        Event::assertDispatched(PolicyCreated::class, static fn (PolicyCreated $event): bool => self::refersTo($event->policy, $system)
            && $event->tenant === null
            && $event->isSystem);
    }

    /**
     * Rewriting a policy's document reports the digests of the document before
     * and after, and leaves the document out of the changed fields.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testReportsADocumentRewriteByItsDigests(): void
    {
        $policy    = Policy::query()->create(['name' => 'audit', 'document' => self::document()]);
        $rewritten = ['version' => 1, 'statements' => [['effect' => 'deny', 'actions' => ['posts:delete'], 'resources' => ['*']]]];

        $before = DocumentDigest::of($policy->document)->digest;

        Event::fake([PolicyUpdated::class]);

        $policy->update(['document' => $rewritten, 'description' => 'Audit']);

        $after = DocumentDigest::of($policy->document)->digest;

        Event::assertDispatchedTimes(PolicyUpdated::class, 1);
        Event::assertDispatched(PolicyUpdated::class, static fn (PolicyUpdated $event): bool => self::refersTo($event->policy, $policy)
            && $event->name                      === 'audit'
            && $event->document->digest          === $after
            && $event->previousDocument?->digest === $before
            && $before !== $after
            && !\array_key_exists('document', $event->changes['before'])
            && !\array_key_exists('document', $event->changes['after'])
            && ($event->changes['after']['description'] ?? null) === 'Audit');
    }

    /**
     * An update that leaves the document alone reports no previous document.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAnUpdateThatKeepsTheDocumentReportsNoPreviousDocument(): void
    {
        $policy = Policy::query()->create(['name' => 'audit', 'document' => self::document()]);

        $digest = DocumentDigest::of($policy->document)->digest;

        Event::fake([PolicyUpdated::class]);

        $policy->update(['name' => 'audits']);

        Event::assertDispatched(PolicyUpdated::class, static fn (PolicyUpdated $event): bool => $event->name === 'audits'
            && $event->previousDocument                                                                      === null
            && $event->document->digest                                                                      === $digest);
    }

    /**
     * Deleting a policy reports, in one event, the digest of its document and
     * every grantee it was attached to.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReportsThePolicyDeletedWithItsHolders(): void
    {
        $policy = Policy::query()->create(['name' => 'audit', 'document' => self::document()]);

        app(GrantService::class)->attachPolicy(new Reference('user', '2'), $policy);
        app(GrantService::class)->attachPolicy(new Reference('admin', '9'), $policy);

        $digest = DocumentDigest::of($policy->document)->digest;

        Event::fake([PolicyDeleted::class]);

        $policy->delete();

        Event::assertDispatchedTimes(PolicyDeleted::class, 1);
        Event::assertDispatched(PolicyDeleted::class, static fn (PolicyDeleted $event): bool => self::refersTo($event->policy, $policy)
            && $event->name                   === 'audit'
            && $event->document->digest       === $digest
            && self::keysOf($event->grantees) === ['admin:9', 'user:2']);
    }

    /**
     * A document that is not a decoded array is digested as an empty one.
     *
     * @return void
     */
    public function testAnUndecodedDocumentIsDigestedAsAnEmptyOne(): void
    {
        $policy = Policy::query()->create(['name' => 'audit', 'document' => self::document()]);

        Event::fake([PolicyDeleted::class]);

        $policy->setRawAttributes(['document' => 'null'] + $policy->getAttributes());
        $policy->delete();

        Event::assertDispatched(PolicyDeleted::class, static fn (PolicyDeleted $event): bool => $event->document->digest === DocumentDigest::of([])->digest);
    }

    /**
     * Return a minimal valid policy document.
     *
     * @return array<string, mixed>
     */
    private static function document(): array
    {
        return ['version' => 1, 'statements' => []];
    }
}
