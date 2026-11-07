<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Events\Resource\PolicyAttached;
use SineMacula\Laravel\Authorization\Events\Resource\PolicyDetached;
use SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidResourceException;
use SineMacula\Laravel\Authorization\Exceptions\ResourcePolicyException;
use SineMacula\Laravel\Authorization\Exceptions\UnwrittenGrantException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Concerns\ActsAsAdministrator;
use Tests\Concerns\ActsAsTenant;
use Tests\Concerns\ComparesReferences;
use Tests\Concerns\InterleavesWrites;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Feature\Stubs\FixedResourceTenantResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\TestCase;

/**
 * Feature tests for `ResourcePolicyService`, which attaches managed policies to
 * resources and resource types, and detaches them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ResourcePolicyService::class)]
final class ResourcePolicyServiceTest extends TestCase
{
    use ActsAsAdministrator, ActsAsTenant, ComparesReferences, InterleavesWrites, ReadsDispatchedEvents;

    /**
     * The service is bound once in the container.
     *
     * @return void
     */
    public function testIsBoundAsASingleton(): void
    {
        self::assertInstanceOf(ResourcePolicyService::class, self::service());
        self::assertSame(self::service(), self::service());
    }

    /**
     * A policy is attached to a record and to a whole type, each in its own
     * row, platform-wide and for every application by default, and each
     * attachment is reported once, as trusted work with no actor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttachesToARecordAndToAType(): void
    {
        Event::fake([PolicyAttached::class]);

        $policy = self::sharing();

        self::assertSame(GrantOutcome::GRANTED, self::service()->attach($policy, ['posts', 7]));
        self::assertSame(GrantOutcome::GRANTED, self::service()->attach($policy, 'posts'));

        $columns = ['resource_type', 'resource_id', 'tenant_type', 'tenant_id', 'include_subtree', 'application'];
        $rows    = DB::table('resource_policies')->orderByRaw('coalesce(resource_id, \'\')')->get($columns)->map(static fn (object $row): array => (array) $row)->all();

        self::assertCount(2, $rows);
        self::assertSame(['posts', null, null, null, null], \array_values(\array_diff_key($rows[0], ['include_subtree' => true])));
        self::assertSame(['posts', '7'], [$rows[1]['resource_type'], $rows[1]['resource_id']]);
        self::assertTrue((bool) $rows[1]['include_subtree']);

        $events = self::dispatchedEvents(PolicyAttached::class);

        self::assertCount(2, $events);
        self::assertSame(['posts', '7', 'sharing'], [$events[0]->resourceType, $events[0]->resourceId, $events[0]->name]);
        self::assertTrue(self::refersTo($events[0]->policy, $policy));
        self::assertNull($events[0]->operation->actor);
        self::assertSame([PackagePermissions::RESOURCE_POLICY_ATTACH], $events[0]->operation->actions);
        self::assertNull($events[0]->scope->tenant);
        self::assertSame(['posts', null], [$events[1]->resourceType, $events[1]->resourceId]);
        self::assertNull($events[1]->operation->actor);
    }

    /**
     * The resource may be a saved model, a resource reference, a model class or
     * a morph type named by a string.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTakesEveryFormOfResource(): void
    {
        $policy = self::sharing();
        $user   = StubIdentity::create(['id' => 'user-1']);

        self::service()->attach($policy, $user);
        self::service()->attach($policy, ResourceReference::record('docs', 'd-1'));
        self::service()->attach($policy, StubIdentity::class);
        self::service()->attach($policy, ResourceReference::type('docs'));

        $rows = \array_map(self::identifierOf(...), DB::table('resource_policies')->get(['resource_type', 'resource_id'])->all());

        \sort($rows);

        self::assertSame([$user->getMorphClass() . ':*', $user->getMorphClass() . ':user-1', 'docs:*', 'docs:d-1'], $rows);
    }

    /**
     * Attaching what the resource holds in the scope changes nothing and
     * reports nothing; another reach changes the reach alone, reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttachingAgainChangesOnlyTheReach(): void
    {
        $tenant = self::createTenant('tenant-a');
        $policy = self::sharing();

        self::service()->attach($policy, ['posts', 7], $tenant);

        Event::fake([PolicyAttached::class]);

        self::assertSame(GrantOutcome::UNCHANGED, self::service()->attach($policy, ['posts', 7], $tenant));
        self::assertSame([], self::dispatchedEvents(PolicyAttached::class));

        self::assertSame(GrantOutcome::REACH_CHANGED, self::service()->attach($policy, ['posts', 7], $tenant, false));
        self::assertFalse((bool) DB::table('resource_policies')->value('include_subtree'));
        self::assertSame(1, DB::table('resource_policies')->count());

        $events = self::dispatchedEvents(PolicyAttached::class);

        self::assertCount(1, $events);
        self::assertFalse($events[0]->scope->includeSubtree);
        self::assertTrue(self::refersTo($events[0]->scope->tenant, $tenant));
    }

    /**
     * An attachment holds in its scope: a tenant and an application are
     * written, and the same policy may be attached to the same resource once in
     * each scope.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttachesOncePerScope(): void
    {
        $tenant = self::createTenant('tenant-a');
        $policy = self::sharing();

        self::service()->attach($policy, ['posts', 7]);
        self::service()->attach($policy, ['posts', 7], $tenant);
        self::service()->attach($policy, ['posts', 7], $tenant, application: 'admin');
        self::service()->attach($policy, ['posts', 7], new Reference($tenant->getMorphClass(), 'tenant-a'), application: 'admin');

        self::assertSame(3, DB::table('resource_policies')->count());
        self::assertSame(['admin'], DB::table('resource_policies')->whereNotNull('application')->pluck('application')->all());
        self::assertSame(['tenant-a', 'tenant-a'], DB::table('resource_policies')->whereNotNull('tenant_id')->pluck('tenant_id')->all());
    }

    /**
     * A policy one tenant owns is attached in that tenant, the scope a call
     * names otherwise, and refused in another.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantsPolicyIsAttachedOnlyInItsTenant(): void
    {
        [$tenantA, $tenantB] = \array_map(self::createTenant(...), ['tenant-a', 'tenant-b']);

        $policy = self::sharing('owned', ['tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => 'tenant-a']);

        self::service()->attach($policy, 'posts');

        self::assertSame('tenant-a', DB::table('resource_policies')->value('tenant_id'));

        $this->expectException(GrantScopeMismatchException::class);

        self::service()->attach($policy, 'posts', $tenantB);
    }

    /**
     * A policy with an allow statement naming no principals is refused, with
     * the statements that name none, and nothing is written; a policy of denies
     * alone may be attached.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesAnAllowWithoutPrincipals(): void
    {
        $policy = self::policy('identity', [
            ['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:1']],
            ['effect' => 'allow', 'actions' => ['posts:edit']],
        ]);

        try {
            self::service()->attach($policy, ['posts', 7]);
            self::fail('The policy was not refused.');
        } catch (ResourcePolicyException $exception) {
            self::assertSame('identity', $exception->getPolicyName());
            self::assertSame([1], $exception->getStatements());
        }

        self::assertSame(0, DB::table('resource_policies')->count());

        self::service()->attach(self::policy('denies', [['effect' => 'deny', 'actions' => ['posts:delete']]]), ['posts', 7]);

        self::assertSame(1, DB::table('resource_policies')->count());
    }

    /**
     * An inline policy belongs to one grantee and is never attached to a
     * resource.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesAnInlinePolicy(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $inline = $user->createInlinePolicy('mine', ['statements' => [['effect' => 'deny', 'actions' => ['posts:delete']]]]);

        try {
            self::service()->attach($inline, 'posts');
            self::fail('The inline policy was not refused.');
        } catch (ResourcePolicyException $exception) {
            self::assertSame([], $exception->getStatements());
            self::assertStringContainsString('Inline policy \'mine\'', $exception->getMessage());
        }

        self::assertSame(0, DB::table('resource_policies')->count());
    }

    /**
     * A policy whose row is gone, or was never saved, is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesAPolicyThatIsNotStored(): void
    {
        $this->expectException(InvalidGrantTargetException::class);

        self::service()->attach(new Policy(['name' => 'unsaved']), 'posts');
    }

    /**
     * A policy deleted while it is attached, which on MySQL leaves no row once
     * `INSERT IGNORE` turns the foreign key failure into a warning, is refused
     * as gone, with nothing reported attached and no `PolicyAttached`
     * dispatched; an attachment a concurrent change keeps from being written
     * for another reason is refused as not written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAttachmentThatIsNotWrittenIsRefused(): void
    {
        $policy = self::sharing();

        self::service()->attach($policy, ['posts', '7']);

        Event::fake([PolicyAttached::class]);

        $messages = [];

        foreach ([InvalidGrantTargetException::class => true, UnwrittenGrantException::class => false] as $refusal => $isDeleted) {
            self::churn($policy, $isDeleted);

            try {
                self::service()->attach($policy, ['posts', '7'], null, false);
                self::fail("{$refusal} was not thrown.");
            } catch (\Throwable $exception) {
                self::assertInstanceOf($refusal, $exception);

                $messages[] = $exception->getMessage();
            }
        }

        $unwritten = 'The attachment of policy \'sharing\' to posts:7 was not written: no row was stored or found once the write was tried again; retry the call.';

        self::assertSame($unwritten, $messages[1]);
        self::assertSame([], self::dispatchedEvents(PolicyAttached::class));
        self::assertTrue((bool) DB::table('resource_policies')->sole()->include_subtree);
        self::assertNotNull(Policy::query()->find($policy->id));
    }

    /**
     * A value that names no type is refused before anything is read: an unsaved
     * model, an empty or NUL-holding type, a pair without a key, a reference
     * without a type, and a key longer than the table stores.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesAValueThatNamesNoResource(): void
    {
        $policy = self::sharing();

        $refused = [new StubIdentity, '', "po\0sts", ['posts', ''], new ResourceReference('opaque'), new ResourceReference('posts:', 'posts', '')];
        $refused = [...$refused, ['posts', \str_repeat('a', 192)], [\str_repeat('p', 192), '7'], \str_repeat('p', 192), null, 7];
        $refused = [...$refused, ['posts', '*'], ResourceReference::record('posts', '*')];

        foreach ($refused as $resource) {
            try {
                self::service()->attach($policy, $resource);
                self::fail('The resource was not refused.');
            } catch (InvalidResourceException $exception) {
                self::assertStringStartsWith('A resource policy is attached to a record or a resource type, not ', $exception->getMessage());
            }
        }

        $this->expectException(InvalidResourceException::class);

        self::service()->detach($policy, new ResourceReference('opaque'));
    }

    /**
     * The attachment's event is dispatched once the enclosing transaction
     * commits, and never when it rolls back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDispatchesOnlyOnceTheWriteCommits(): void
    {
        $policy = self::sharing();

        Event::fake([PolicyAttached::class]);

        try {
            DB::transaction(static function () use ($policy): void {
                self::service()->attach($policy, 'posts');

                self::assertSame([], self::dispatchedEvents(PolicyAttached::class));

                throw new \RuntimeException('roll back');
            });
        } catch (\RuntimeException) {
            // Expected.
        }

        self::assertSame([], self::dispatchedEvents(PolicyAttached::class));
        self::assertSame(0, DB::table('resource_policies')->count());

        DB::transaction(static function () use ($policy): void {
            self::service()->attach($policy, 'posts');

            self::assertSame([], self::dispatchedEvents(PolicyAttached::class));
        });

        self::assertCount(1, self::dispatchedEvents(PolicyAttached::class));
    }

    /**
     * A policy is detached in the scope it was attached in, reported with the
     * reach the attachment had; detaching it elsewhere, or again, detaches
     * nothing and reports nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDetachesInTheScope(): void
    {
        $tenant = self::createTenant('tenant-a');
        $policy = self::sharing();

        self::service()->attach($policy, ['posts', 7], $tenant, false, 'admin');
        self::service()->attach($policy, 'posts');

        Event::fake([PolicyDetached::class]);

        self::assertSame(0, self::service()->detach($policy, ['posts', 7]));
        self::assertSame(0, self::service()->detach($policy, ['posts', 7], $tenant));
        $admin = self::administrator();

        self::assertSame(1, self::service()->detach($policy, ['posts', 7], $tenant, 'admin', $admin));
        self::assertSame(0, self::service()->detach($policy, ['posts', 7], $tenant, 'admin'));
        self::assertSame(1, self::service()->detach($policy, 'posts'));
        self::assertSame(0, DB::table('resource_policies')->count());

        $events = self::dispatchedEvents(PolicyDetached::class);

        self::assertCount(2, $events);
        self::assertSame(['posts', '7', 'sharing', 'admin'], [$events[0]->resourceType, $events[0]->resourceId, $events[0]->name, $events[0]->scope->application]);
        self::assertFalse($events[0]->scope->includeSubtree);
        self::assertTrue(self::refersTo($events[0]->scope->tenant, $tenant));
        self::assertTrue(self::refersTo($events[0]->operation->actor, $admin->principal()));
        self::assertSame([null, null], [$events[1]->resourceId, $events[1]->scope->tenant]);
        self::assertTrue($events[1]->scope->includeSubtree);
    }

    /**
     * A policy one tenant owns is detached in that tenant when the call names
     * none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDetachesATenantsPolicyInItsTenant(): void
    {
        $tenant = self::createTenant('tenant-a');
        $policy = self::sharing('owned', ['tenant_type' => $tenant->getMorphClass(), 'tenant_id' => 'tenant-a']);

        self::service()->attach($policy, 'posts');

        self::assertSame(1, self::service()->detach($policy, 'posts'));
        self::assertSame(0, DB::table('resource_policies')->count());
    }

    /**
     * Deleting a policy removes its resource attachments with it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyDeletedTakesItsAttachments(): void
    {
        $policy = self::sharing();

        self::service()->attach($policy, 'posts');
        $policy->delete();

        self::assertSame(0, DB::table('resource_policies')->count());
    }

    /**
     * A type or key of exactly the bytes the table stores is attached whole,
     * and its policy is found for that resource.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttachesATypeOrKeyAtTheLimit(): void
    {
        $key  = \str_repeat('a', 191);
        $type = \str_repeat('p', 191);

        self::assertSame(GrantOutcome::GRANTED, self::service()->attach(self::sharing('long-key'), ['posts', $key]));
        self::assertSame(GrantOutcome::GRANTED, self::service()->attach(self::sharing('long-type'), ResourceReference::type($type)));

        $rows = \array_map(self::identifierOf(...), DB::table('resource_policies')->get(['resource_type', 'resource_id'])->all());

        \sort($rows);

        self::assertSame(['posts:' . $key, $type . ':*'], $rows);
        self::assertSame(['long-key'], self::namesFor(ResourceReference::record('posts', $key)));
        self::assertSame(['long-type'], self::namesFor(ResourceReference::type($type)));
    }

    /**
     * A pair names its record without asking the bound resource tenant
     * resolver, so a pair it cannot place is still attached and detached.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttachesAPairTheTenantResolverCannotPlace(): void
    {
        $resolver = new FixedResourceTenantResolver(null, false);

        $this->app?->instance(ResourceTenantResolver::class, $resolver);

        $policy = self::sharing();

        self::assertSame(GrantOutcome::GRANTED, self::service()->attach($policy, ['posts', 7]));
        self::assertSame(1, self::service()->detach($policy, ['posts', 7]));
        self::assertSame([], $resolver->askedRecords);
    }

    /**
     * Detaching a tenant's policy names the tenant below it that it was
     * attached in, leaving its attachment in its own tenant; naming a tenant it
     * was not attached in detaches nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDetachesATenantsPolicyInTheTenantBelowItNamed(): void
    {
        $parent = self::createTenant('tenant-a');
        $child  = self::createTenant('tenant-a1');
        $other  = self::createTenant('tenant-b');

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($child), Reference::of($parent)));

        $policy = self::sharing('owned', ['tenant_type' => $parent->getMorphClass(), 'tenant_id' => 'tenant-a']);

        self::service()->attach($policy, 'posts', $child);
        self::service()->attach($policy, 'posts');

        self::assertSame(0, self::service()->detach($policy, 'posts', $other));
        self::assertSame(['tenant-a', 'tenant-a1'], DB::table('resource_policies')->orderBy('tenant_id')->pluck('tenant_id')->all());
        self::assertSame(1, self::service()->detach($policy, 'posts', $child));
        self::assertSame(['tenant-a'], DB::table('resource_policies')->pluck('tenant_id')->all());
    }

    /**
     * Detaching every policy from a record detaches each attachment it holds,
     * in every scope, reporting each, and leaves its type's and another
     * record's; a whole type is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDetachesEveryPolicyFromARecord(): void
    {
        Event::fake([PolicyDetached::class]);

        $tenant = self::createTenant('tenant-a');
        $policy = self::sharing();
        $other  = self::sharing('other');

        self::service()->attach($policy, ['posts', 7]);
        self::service()->attach($policy, ['posts', 7], $tenant, false, 'admin');
        self::service()->attach($other, ['posts', 7]);
        self::service()->attach($policy, ['posts', 8]);
        self::service()->attach($policy, 'posts');

        $admin = self::administrator();

        self::assertSame(3, self::service()->detachAll(['posts', 7], $admin));
        self::assertSame(0, self::service()->detachAll(['posts', 7]));

        $rows = \array_map(self::identifierOf(...), DB::table('resource_policies')->get(['resource_type', 'resource_id'])->all());

        \sort($rows);

        self::assertSame(['posts:*', 'posts:8'], $rows);

        $events = self::dispatchedEvents(PolicyDetached::class);
        $scopes = \array_map(self::describedDetachment(...), $events);

        \sort($scopes);

        self::assertSame(['other@platform/every/subtree on posts:7', 'sharing@platform/every/subtree on posts:7', 'sharing@tenant-a/admin/own on posts:7'], $scopes);
        self::assertTrue(self::refersTo($events[0]->operation->actor, $admin->principal()));

        $this->expectException(InvalidResourceException::class);

        self::service()->detachAll('posts');
    }

    /**
     * A key that differs from another only in case names another record, on
     * every database: its attachments apply to it alone and are detached alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAKeyThatDiffersOnlyInCaseNamesAnotherRecord(): void
    {
        $policy = self::sharing();

        self::service()->attach($policy, ['docs', 'aB3']);

        self::assertSame([], self::namesFor(ResourceReference::record('docs', 'Ab3')));
        self::assertSame([], self::namesFor(ResourceReference::record('Docs', 'aB3')));

        self::service()->attach($policy, ['docs', 'Ab3']);

        self::assertSame(1, self::service()->detach($policy, ['docs', 'aB3']));
        self::assertSame(['Ab3'], DB::table('resource_policies')->pluck('resource_id')->all());
        self::assertSame(['sharing'], self::namesFor(ResourceReference::record('docs', 'Ab3')));
    }

    /**
     * Describe a detachment as its policy's name, its tenant, application and
     * reach, and its resource.
     *
     * @param  \SineMacula\Laravel\Authorization\Events\Resource\PolicyDetached  $event
     * @return string
     */
    private static function describedDetachment(PolicyDetached $event): string
    {
        $scope = ($event->scope->tenant->id ?? 'platform') . '/' . ($event->scope->application ?? 'every') . '/' . ($event->scope->includeSubtree ? 'subtree' : 'own');

        return $event->name . '@' . $scope . ' on ' . $event->resourceType . ':' . $event->resourceId;
    }

    /**
     * Return the names of the policies the resource reads, sorted.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @return list<string>
     */
    private static function namesFor(ResourceReference $resource): array
    {
        $names = \array_map(static fn (EvaluationPolicy $policy): string => $policy->name, (new ResourcePolicyResolver)->policiesFor($resource));

        \sort($names);

        return $names;
    }

    /**
     * Return an attachment row's resource as `type:id`, or `type:*` for the
     * whole type.
     *
     * @param  object{resource_type: string, resource_id: string|null}  $row
     * @return string
     */
    private static function identifierOf(object $row): string
    {
        return $row->resource_type . ':' . ($row->resource_id ?? '*');
    }

    /**
     * Interleave a concurrent change with each write of the policy's attachment
     * to `posts:7`: the row is removed once each insert is ignored and put back
     * once it is read back, so neither insert writes a row, and, when the
     * policy is to be deleted, it is deleted with the second removal, once
     * nothing refers to it.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  bool  $isDeleted
     * @return void
     */
    private static function churn(Policy $policy, bool $isDeleted): void
    {
        $row     = (array) DB::table('resource_policies')->sole();
        $removed = new \ArrayObject;

        self::interleaveWrites('resource_policies', static function () use ($policy, $isDeleted, $removed): void {
            DB::table('resource_policies')->delete();
            $removed->append(true);

            if (!$isDeleted || $removed->count() !== 2) {
                return;
            }

            DB::table('policies')->where('id', $policy->id)->delete();
        }, static function () use ($row): void {
            DB::table('resource_policies')->insert($row);
        }, 2, 1);
    }

    /**
     * Return the resource policy service the container binds.
     *
     * @return \SineMacula\Laravel\Authorization\Services\ResourcePolicyService
     */
    private static function service(): ResourcePolicyService
    {
        $service = ResourcePolicyService::instance();

        self::assertInstanceOf(ResourcePolicyService::class, $service);

        return $service;
    }

    /**
     * Create a policy whose allow names its principals.
     *
     * @param  string  $name
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function sharing(string $name = 'sharing', array $attributes = []): Policy
    {
        return self::policy($name, [['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:1']]], $attributes);
    }

    /**
     * Create a policy of the statements.
     *
     * @param  string  $name
     * @param  list<array<string, mixed>>  $statements
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function policy(string $name, array $statements, array $attributes = []): Policy
    {
        return Policy::create(['name' => $name, ...$attributes, 'document' => ['statements' => $statements]]);
    }
}
