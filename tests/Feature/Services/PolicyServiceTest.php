<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Events\Policy\Created as PolicyCreated;
use SineMacula\Laravel\Authorization\Events\Policy\Deleted as PolicyDeleted;
use SineMacula\Laravel\Authorization\Events\Policy\Updated as PolicyUpdated;
use SineMacula\Laravel\Authorization\Exceptions\SystemPolicyProtectedException;
use SineMacula\Laravel\Authorization\Exceptions\UnsavedRecordException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\PolicyService;
use SineMacula\Laravel\Authorization\Support\DocumentDigest;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ComparesReferences;
use Tests\Concerns\UsesAnAuthorizationConnection;
use Tests\Feature\Stubs\CustomPolicy;
use Tests\TestCase;

/**
 * Feature tests for `PolicyService`, which creates, renames, describes,
 * rewrites, deletes and lists policies.
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
        self::assertSame(['posts:read'], $policy->toEvaluationPolicy()->statements[0]->actions);
        Event::assertDispatched(PolicyCreated::class);
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

        $fresh = $policy->fresh();

        self::assertSame(['editors', 'Edits posts'], [$fresh?->name, $fresh?->description]);
        self::assertSame(['posts:edit'], $fresh?->toEvaluationPolicy()->statements[0]->actions);
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
     * Rewriting a policy reports, with the caller's actor, the version and
     * digest of the document before and after, never the documents.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARewriteReportsTheDigestsAndNotTheDocuments(): void
    {
        $policy = self::service()->create('audit', ['version' => 1, 'statements' => []]);
        $before = DocumentDigest::of($policy->document)->digest;
        $actor  = new Reference('user', 'admin-1');

        Event::fake([PolicyUpdated::class]);

        $policy = self::service()->rewrite($policy, ['version' => 1, 'statements' => [['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['*']]]], $actor);
        $after  = DocumentDigest::of($policy->document)->digest;

        Event::assertDispatchedTimes(PolicyUpdated::class, 1);
        Event::assertDispatched(PolicyUpdated::class, static function (PolicyUpdated $event) use ($actor, $before, $after): bool {
            $payload = \json_encode((array) $event, JSON_THROW_ON_ERROR);

            return self::refersTo($event->operation->actor, $actor)
                && $event->previousDocument?->digest === $before
                && $event->document->digest          === $after
                && $event->document->version         === 1
                && !\str_contains($payload, 'posts:read')
                && !\str_contains($payload, 'statements');
        });
    }

    /**
     * Deleting a policy through the service reports, with the caller's actor,
     * every grantee it was attached to.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeletingAPolicyReportsWhoLostIt(): void
    {
        $policy = self::service()->create('audit', ['version' => 1, 'statements' => []]);
        $actor  = new Reference('user', 'admin-1');

        app(GrantService::class)->attachPolicy(new Reference('user', '1'), $policy);

        Event::fake([PolicyDeleted::class]);

        self::service()->delete($policy, $actor);

        Event::assertDispatchedTimes(PolicyDeleted::class, 1);
        Event::assertDispatched(PolicyDeleted::class, static fn (PolicyDeleted $event): bool => self::refersTo($event->operation->actor, $actor)
            && self::keysOf($event->grantees) === ['user:1']);
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
