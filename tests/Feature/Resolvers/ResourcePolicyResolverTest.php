<?php

declare(strict_types = 1);

namespace Tests\Feature\Resolvers;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Cache\VersionedStore;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\RecordingLogger;
use Tests\TestCase;

/**
 * Feature tests for the resolution of the resource policies a check on a
 * resource reads: the record's and its type's, in one query, within the scope
 * the check is decided in, through the resolution cache.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ResourcePolicyResolver::class)]
final class ResourcePolicyResolverTest extends TestCase
{
    use ActsAsTenant;

    /**
     * A check on a record reads the policies attached to it and to its type,
     * each as attached to what it is attached to; one attached to another
     * record or type is not read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARecordReadsItsOwnAndItsTypesPolicies(): void
    {
        self::service()->attach(self::sharing('record'), ['posts', 7]);
        self::service()->attach(self::sharing('type'), 'posts');
        self::service()->attach(self::sharing('other-record'), ['posts', 8]);
        self::service()->attach(self::sharing('other-type'), 'docs');

        self::assertSame(['record@posts:7', 'type@posts:*'], self::read(ResourceReference::record('posts', '7')));
    }

    /**
     * A check on a type alone reads only the policies attached to the type; an
     * opaque identifier, or no resource, reads none and asks nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATypeAloneReadsOnlyItsTypesPolicies(): void
    {
        self::service()->attach(self::sharing('record'), ['posts', 7]);
        self::service()->attach(self::sharing('type'), 'posts');

        self::assertSame(['type@posts:*'], self::read(ResourceReference::type('posts')));

        DB::enableQueryLog();
        DB::flushQueryLog();

        self::assertSame([], (new ResourcePolicyResolver)->policiesFor(new ResourceReference('posts:7')));
        self::assertSame([], (new ResourcePolicyResolver)->policiesFor(null));
        self::assertSame([], (new ResourcePolicyResolver)->policiesFor(ResourceReference::record('posts', \str_repeat('7', 192))));
        self::assertSame([], (new ResourcePolicyResolver)->policiesFor(ResourceReference::type(\str_repeat('p', 192))));
        self::assertSame([], DB::getQueryLog());

        DB::disableQueryLog();
    }

    /**
     * A policy attached to the record and to its type is read once, as the
     * record's, whichever row is read first.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyAttachedTwiceIsReadOnceAsTheRecords(): void
    {
        $policy = self::sharing('both');

        self::service()->attach($policy, 'posts');
        self::service()->attach($policy, ['posts', 7]);
        self::service()->attach($policy, ['posts', 7], self::createTenant('tenant-a'));

        self::assertSame(['both@posts:7'], self::read(ResourceReference::record('posts', '7')));
        self::assertSame(['both@posts:*'], self::read(ResourceReference::record('posts', '8')));
    }

    /**
     * Only the attachments that hold in the check's tenant and application
     * count: platform-wide ones, the tenant's own, an ancestor's that reaches
     * below, and those for every application or the check's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheAttachmentsOfTheScopeCount(): void
    {
        [$tenantA, $tenantB] = \array_map(self::createTenant(...), ['tenant-a', 'tenant-b']);

        self::service()->attach(self::sharing('platform'), 'posts');
        self::service()->attach(self::sharing('in-a'), 'posts', $tenantA);
        self::service()->attach(self::sharing('in-b'), 'posts', $tenantB);
        self::service()->attach(self::sharing('admin-app'), 'posts', application: 'admin');

        $record = ResourceReference::record('posts', '7');

        self::assertSame(['platform@posts:*'], self::read($record));
        self::assertSame(['in-a@posts:*', 'platform@posts:*'], TenantScope::within($tenantA, null, static fn (): array => self::read($record)));
        self::assertSame(['admin-app@posts:*', 'in-b@posts:*', 'platform@posts:*'], TenantScope::within($tenantB, 'admin', static fn (): array => self::read($record)));
    }

    /**
     * The record's and its type's policies are read in one query, and a check
     * that reads them again in the request asks nothing more.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReadsInOneQueryThenFromTheCache(): void
    {
        self::service()->attach(self::sharing('record'), ['posts', 7]);
        self::service()->attach(self::sharing('type'), 'posts');

        $record = ResourceReference::record('posts', '7');

        DB::enableQueryLog();
        DB::flushQueryLog();

        self::read($record);

        self::assertCount(1, DB::getQueryLog());

        DB::flushQueryLog();

        self::assertSame(['record@posts:7', 'type@posts:*'], self::read($record));
        self::assertSame([], DB::getQueryLog());

        DB::disableQueryLog();
    }

    /**
     * With a persistent store, the policies are kept across requests and read
     * afresh once a policy is attached to or detached from a resource of the
     * type, or any policy is rewritten.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPersistentEntryHoldsUntilAWriteChangesIt(): void
    {
        $store  = new Repository(new ArrayStore);
        $record = ResourceReference::record('posts', '7');
        $policy = self::sharing('record');

        self::request($store);
        self::service()->attach($policy, ['posts', 7]);

        self::assertSame(['record@posts:7'], self::read($record));

        self::request($store);

        self::assertSame(['record@posts:7'], self::readWithoutQueries($record));

        self::service()->attach(self::sharing('type'), 'posts');
        self::request($store);

        self::assertSame(['record@posts:7', 'type@posts:*'], self::read($record));

        $policy->update(['document' => ['statements' => [['effect' => 'deny', 'actions' => ['posts:read']]]]]);
        self::request($store);

        $effects = \array_map(static fn (EvaluationPolicy $read): string => $read->name . ':' . $read->statements[0]->effect->value, self::policies($record));

        \sort($effects);

        self::assertSame(['record:deny', 'type:allow'], $effects);

        self::service()->detach($policy, ['posts', 7]);
        self::request($store);

        self::assertSame(['type@posts:*'], self::read($record));

        self::service()->attach(self::sharing('docs'), 'docs');
        self::request($store);

        self::assertSame(['type@posts:*'], self::readWithoutQueries($record));
    }

    /**
     * The resolution pins the versions every resource policy and the type's
     * attachments share before it reads them.
     *
     * @return void
     */
    public function testPinsTheTypesAndEveryPolicysVersionsFirst(): void
    {
        $store = new VersionedStore(new Repository(new ArrayStore), 'authz');
        $pins  = new ResolutionPins($store);

        ResourcePolicyResolver::resolve('posts', '7', $pins);

        self::assertSame([$store->resourcePoliciesKey(), $store->resourcePoliciesKey('posts')], \array_keys($pins->tokens()));
    }

    /**
     * A resource policy whose document cannot be read is written to the log
     * channel and its exception thrown, so it denies rather than being skipped.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnreadablePolicyIsLoggedAndThrown(): void
    {
        $logger = new RecordingLogger;
        $this->app?->instance('log', $logger);

        $policy = self::sharing('broken');

        self::service()->attach($policy, 'posts');

        DB::table('policies')->where('id', $policy->id)->update(['document' => \json_encode(['statements' => [['effect' => 'deny', 'actions' => []]]])]);

        try {
            ResourcePolicyResolver::resolve('posts', null, new ResolutionPins);
            self::fail('An unreadable policy was not thrown.');
        } catch (InvalidPolicyDocumentException $exception) {
            self::assertStringContainsString('\'broken\'', $exception->getMessage());
        }

        self::assertCount(1, $logger->records);
        self::assertSame($policy->id, $logger->records[0]['context']['policy_id'] ?? null);
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
     * Start a new request: a resolution cache with an empty memo over the
     * persistent store.
     *
     * @param  \Illuminate\Cache\Repository  $store
     * @return void
     */
    private static function request(Repository $store): void
    {
        app()->instance(ResolutionCache::class, new ResolutionCache($store));
    }

    /**
     * Return the resource policies the resource reads.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    private static function policies(ResourceReference $resource): array
    {
        return (new ResourcePolicyResolver)->policiesFor($resource);
    }

    /**
     * Return each resource policy the resource reads as its name and the
     * resource it is attached to, sorted.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @return list<string>
     */
    private static function read(ResourceReference $resource): array
    {
        $read = \array_map(static fn (EvaluationPolicy $policy): string => $policy->name . '@' . $policy->resource, self::policies($resource));

        \sort($read);

        return $read;
    }

    /**
     * Read the resource policies, asserting no query is run.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @return list<string>
     */
    private static function readWithoutQueries(ResourceReference $resource): array
    {
        DB::enableQueryLog();
        DB::flushQueryLog();

        $read = self::read($resource);

        self::assertSame([], DB::getQueryLog());

        DB::disableQueryLog();

        return $read;
    }

    /**
     * Create a policy whose allow names its principals.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function sharing(string $name): Policy
    {
        return Policy::create(['name' => $name, 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:1']]]]]);
    }
}
