<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Events\Policy\Created as PolicyCreated;
use SineMacula\Laravel\Authorization\Events\Policy\Deleted as PolicyDeleted;
use SineMacula\Laravel\Authorization\Events\Policy\Updated as PolicyUpdated;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGranteeException;
use SineMacula\Laravel\Authorization\Exceptions\SystemPolicyProtectedException;
use SineMacula\Laravel\Authorization\Exceptions\UnsavedRecordException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\PolicyService;
use SineMacula\Laravel\Authorization\Support\DeclaredActionCatalogue;
use SineMacula\Laravel\Authorization\Support\DocumentDigest;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\PolicyDocument;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ComparesReferences;
use Tests\Concerns\UsesAnAuthorizationConnection;
use Tests\Feature\Stubs\CustomPolicy;
use Tests\Feature\Stubs\Enums\CataloguePermission;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `PolicyService`, which creates managed and inline policies,
 * and renames, describes, rewrites, deletes and lists them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PolicyService::class)]
final class PolicyServiceTest extends TestCase
{
    use ComparesReferences, UsesAnAuthorizationConnection;

    /** @var array{statements: list<array<string, mixed>>} An allow on reading posts. */
    private const array READ = ['statements' => [['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['*']]]];

    /**
     * The service is bound once in the container.
     *
     * @return void
     */
    public function testIsBoundAsASingleton(): void
    {
        self::assertSame(self::service(), self::service());
    }

    /**
     * A policy is created from its document, through the configured class, and
     * reported by the observer.
     *
     * @return void
     */
    public function testCreatesAPolicy(): void
    {
        $this->config()->set('authorization.models.policy', CustomPolicy::class);

        Event::fake([PolicyCreated::class]);

        $policy = self::service()->create('readers', self::READ, 'Reads posts');

        self::assertInstanceOf(CustomPolicy::class, $policy);
        self::assertSame(['readers', 'Reads posts'], [$policy->fresh()?->name, $policy->fresh()?->description]);
        self::assertSame(['posts:read'], PolicyDocument::hydrate($policy)->statements[0]->actions);
        Event::assertDispatched(PolicyCreated::class);
    }

    /**
     * An inline policy is created for its grantee, a model or a reference,
     * through the configured class, reported by the observer as trusted work,
     * and validated as any policy is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCreatesAnInlinePolicy(): void
    {
        $this->config()->set('authorization.models.policy', CustomPolicy::class);

        Event::fake([PolicyCreated::class]);

        $user   = StubIdentity::create(['id' => 'user-1']);
        $policy = self::service()->createInline($user, 'mine', self::READ, 'Mine alone');
        $theirs = self::service()->createInline(new Reference('team', '7'), 'theirs', \json_encode(self::READ, \JSON_THROW_ON_ERROR));

        self::assertInstanceOf(CustomPolicy::class, $policy);
        self::assertSame(['mine', 'Mine alone', $user->getMorphClass(), 'user-1'], [$policy->name, $policy->description, $policy->owner_type, $policy->owner_id]);
        self::assertEquals(new Reference('team', '7'), InlinePolicies::ownerOf($theirs));
        self::assertNull(Reference::tenantOf($policy));
        Event::assertDispatched(PolicyCreated::class, static fn (PolicyCreated $event): bool => $event->name === 'mine' && $event->operation->actor === null);

        try {
            self::service()->createInline($user, 'broken', ['statements' => [['effect' => 'allow']]]);
            self::fail('The document was not refused.');
        } catch (InvalidPolicyDocumentException) {
            self::assertSame(2, Policy::query()->count());
        }
    }

    /**
     * An inline policy is refused for a grantee that is not saved, or a
     * reference without a type or a key, and nothing is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInlinePolicyNeedsASavedGrantee(): void
    {
        foreach ([new StubIdentity(['id' => 'user-1']), new Reference('', '1'), new Reference('user', '')] as $owner) {
            try {
                self::service()->createInline($owner, 'mine', self::READ);
                self::fail('The grantee was not refused.');
            } catch (InvalidGranteeException $exception) {
                self::assertStringStartsWith('A grant takes a saved grantee with a type and a key', $exception->getMessage());
            }
        }

        self::assertSame(0, Policy::query()->count());
    }

    /**
     * A document the evaluator cannot read is refused and nothing is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesAnInvalidDocument(): void
    {
        try {
            self::service()->create('broken', '[1');
            self::fail('The document was not refused.');
        } catch (InvalidPolicyDocumentException) {
            self::assertSame(0, Policy::query()->count());
        }
    }

    /**
     * A document over a limit, or naming an action the code does not declare,
     * is refused through the policy validator and nothing is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesADocumentThePolicyValidatorRefuses(): void
    {
        $this->config()->set('authorization.policies.limits.statements', 1);

        try {
            self::service()->create('wide', ['statements' => [self::READ['statements'][0], self::READ['statements'][0]]]);
            self::fail('The document was not refused.');
        } catch (InvalidPolicyDocumentException $exception) {
            self::assertSame('Invalid policy document \'wide\': Policy document has 2 statements, more than the 1 allowed.', $exception->getMessage());
        }

        $this->config()->set('authorization.permission_enums', [CataloguePermission::class]);
        $this->app?->instance(ActionCatalogue::class, $this->app->make(DeclaredActionCatalogue::class));

        $policy = self::service()->create('creators', ['statements' => [['effect' => 'allow', 'actions' => ['posts:create']]]]);

        try {
            self::service()->rewrite($policy, self::READ);
            self::fail('The document was not refused.');
        } catch (InvalidPolicyDocumentException $exception) {
            self::assertSame('Invalid policy document \'creators\': Policy statement #0 actions pattern \'posts:read\' matches no declared permission.', $exception->getMessage());
        }

        self::assertSame(['posts:create'], PolicyDocument::hydrate(Policy::query()->sole())->statements[0]->actions);
    }

    /**
     * A policy is written on the package's connection.
     *
     * @return void
     */
    public function testCreatesThePolicyOnThePackageConnection(): void
    {
        $this->useAnAuthorizationConnection();

        self::service()->create('readers', self::READ);

        self::assertSame(1, self::authorizationConnection()->table('policies')->count());
        self::assertSame(0, DB::table('policies')->count());
    }

    /**
     * A policy is renamed, described and rewritten.
     *
     * @return void
     */
    public function testRenamesDescribesAndRewritesAPolicy(): void
    {
        $policy = self::service()->create('readers', self::READ);

        self::service()->rename($policy, 'editors');
        self::service()->describe($policy, 'Edits posts');
        self::service()->rewrite($policy, ['statements' => [['effect' => 'allow', 'actions' => ['posts:edit'], 'resources' => ['*']]]]);

        $fresh = Policy::query()->whereKey($policy->id)->firstOrFail();

        self::assertSame(['editors', 'Edits posts'], [$fresh->name, $fresh->description]);
        self::assertSame(['posts:edit'], PolicyDocument::hydrate($fresh)->statements[0]->actions);
    }

    /**
     * A system policy keeps its protection through the service.
     *
     * @return void
     */
    public function testASystemPolicyCannotBeDeleted(): void
    {
        $policy = Policy::query()->create(['name' => 'baseline', 'document' => self::READ, 'is_system' => true]);

        $this->expectException(SystemPolicyProtectedException::class);

        self::service()->delete($policy);
    }

    /**
     * A policy is deleted.
     *
     * @return void
     */
    public function testDeletesAPolicy(): void
    {
        self::service()->delete(self::service()->create('readers', self::READ));

        self::assertSame(0, Policy::query()->count());
    }

    /**
     * An unsaved policy is refused by every change, so none creates a policy
     * outside `create()`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChangesRefuseAnUnsavedPolicy(): void
    {
        $calls = [
            'rename'   => static fn (PolicyService $service, Policy $policy): mixed => $service->rename($policy, 'editors'),
            'describe' => static fn (PolicyService $service, Policy $policy): mixed => $service->describe($policy, 'Edits'),
            'rewrite'  => static fn (PolicyService $service, Policy $policy): mixed => $service->rewrite($policy, self::READ),
            'delete'   => static function (PolicyService $service, Policy $policy): void {
                $service->delete($policy);
            },
        ];

        foreach ($calls as $name => $call) {
            try {
                $call(self::service(), new Policy(['name' => 'readers', 'document' => self::READ]));
                self::fail("The {$name} did not refuse the unsaved policy.");
            } catch (UnsavedRecordException $exception) {
                self::assertSame('policy', $exception->getKind());
            }
        }

        self::assertSame(0, Policy::query()->count());
    }

    /**
     * The policies are listed by name.
     *
     * @return void
     */
    public function testListsThePolicies(): void
    {
        self::service()->create('writers', self::READ);
        self::service()->create('auditors', self::READ);

        self::assertSame(['auditors', 'writers'], self::service()->list()->pluck('name')->all());
    }

    /**
     * Rewriting a policy reports, as trusted work, the version and digest of
     * the document before and after, never the documents.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARewriteReportsTheDigestsAndNotTheDocuments(): void
    {
        $policy = self::service()->create('audit', ['version' => 1, 'statements' => []]);
        $before = DocumentDigest::of($policy->document)->digest;

        Event::fake([PolicyUpdated::class]);

        $policy = self::service()->rewrite($policy, ['version' => 1, 'statements' => [['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['*']]]]);
        $after  = DocumentDigest::of($policy->document)->digest;

        Event::assertDispatchedTimes(PolicyUpdated::class, 1);
        Event::assertDispatched(PolicyUpdated::class, static function (PolicyUpdated $event) use ($before, $after): bool {
            $payload = \json_encode((array) $event, JSON_THROW_ON_ERROR);

            return $event->operation->actor          === null
                && $event->previousDocument?->digest === $before
                && $event->document->digest          === $after
                && $event->document->version         === 1
                && !\str_contains($payload, 'posts:read')
                && !\str_contains($payload, 'statements');
        });
    }

    /**
     * Deleting a policy through the service reports, as trusted work, every
     * grantee it was attached to.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeletingAPolicyReportsWhoLostIt(): void
    {
        $policy = self::service()->create('audit', ['version' => 1, 'statements' => []]);

        app(GrantService::class)->attachPolicy(new Reference('user', '1'), $policy);

        Event::fake([PolicyDeleted::class]);

        self::service()->delete($policy);

        Event::assertDispatchedTimes(PolicyDeleted::class, 1);
        Event::assertDispatched(PolicyDeleted::class, static fn (PolicyDeleted $event): bool => $event->operation->actor === null
            && self::keysOf($event->grantees)                                                                            === ['user:1']);
    }

    /**
     * A policy is created owned by the tenant given, and by the platform for
     * none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyIsCreatedOwnedByTheTenantGiven(): void
    {
        $owned = self::service()->create('readers', ['statements' => []], tenant: new Reference('tenant', 'acme'));

        self::assertSame(['tenant', 'acme'], [$owned->tenant_type, $owned->tenant_id]);
        self::assertSame('acme', Policy::query()->withoutGlobalScopes()->whereKey($owned->getKey())->firstOrFail()->tenant_id);
        self::assertNull(self::service()->create('writers', ['statements' => []])->tenant_type);
    }

    /**
     * Return the policy service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\PolicyService
     */
    private static function service(): PolicyService
    {
        return app(PolicyService::class);
    }

    /**
     * Return the configuration repository.
     *
     * @return \Illuminate\Config\Repository
     */
    private function config(): ConfigRepository
    {
        /** @var \Illuminate\Config\Repository */
        return $this->app?->make(ConfigRepository::class);
    }
}
