<?php

declare(strict_types = 1);

namespace Tests\Feature\Resolvers;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Cache\VersionedStore;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\RecordingLogger;
use Tests\Fixtures\QueryRecorder;
use Tests\Fixtures\QueryRecordingPolicy;
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
        self::assertSame([], (new ResourcePolicyResolver)->policiesFor(ResourceReference::type(\str_repeat('p', 192))));
        self::assertSame([], (new ResourcePolicyResolver)->policiesFor(ResourceReference::record(\str_repeat('p', 192), '7')));
        self::assertSame([], DB::getQueryLog());

        DB::disableQueryLog();
    }

    /**
     * A record whose key no attachment can name, longer than the table stores,
     * empty, `*` or holding a NUL byte, still reads its type's policies, its
     * denies included, and never another record's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARecordOfAKeyNoAttachmentCanNameReadsItsTypesPolicies(): void
    {
        self::service()->attach(Policy::create(['name' => 'locked', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['posts:view']]]]]), 'posts');
        self::service()->attach(self::sharing('record'), ['posts', 7]);

        foreach ([\str_repeat('a', 192), '', '*', "7\0"] as $key) {
            self::assertSame(['locked@posts:*'], self::read(ResourceReference::record('posts', $key)));
        }

        self::assertSame(['locked@posts:*'], self::read(ResourceReference::type('posts')));
        self::assertSame(['locked@posts:*', 'record@posts:7'], self::read(ResourceReference::record('posts', '7')));
    }

    /**
     * An administration operation's id names one operation alone, so nothing
     * attached to it is read, alone or among many: only the policies attached
     * to the operation type are, under the one entry every operation shares.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOperationReadsOnlyItsTypesPolicies(): void
    {
        self::service()->attach(self::sharing('record'), [OperationResource::TYPE, 'operation-1']);
        self::service()->attach(self::sharing('type'), OperationResource::TYPE);
        self::service()->attach(self::sharing('post'), ['posts', '7']);

        $operation = OperationResource::unchanged(PackagePermissions::ROLE_REVOKE, new Reference('user', '1'), null, GrantScope::platform())->actedBy(null, 'operation-1');
        $reference = $operation->toResourceReference();
        $many      = (new ResourcePolicyResolver)->policiesForMany(['operation' => $reference, 'post' => ResourceReference::record('posts', '7')]);

        $named = static fn (array $policies): array => \array_map(static fn (EvaluationPolicy $policy): string => $policy->name . '@' . $policy->resource, $policies);

        self::assertSame(['type@' . OperationResource::TYPE . ':*'], self::read($reference));
        self::assertSame(['type@' . OperationResource::TYPE . ':*'], $named($many['operation']));
        self::assertSame(['post@posts:7'], $named($many['post']));
    }

    /**
     * A type or key of exactly the bytes the table stores names its
     * attachments.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATypeOrKeyAtTheLimitReadsItsPolicies(): void
    {
        $key  = \str_repeat('7', 191);
        $type = \str_repeat('p', 191);

        self::service()->attach(self::sharing('long-key'), ['posts', $key]);
        self::service()->attach(self::sharing('long-type'), $type);

        self::assertSame(['long-key@posts:' . $key], self::read(ResourceReference::record('posts', $key)));
        self::assertSame(['long-type@' . $type . ':*'], self::read(ResourceReference::type($type)));
    }

    /**
     * A check on a type alone is kept apart from a check on any record, in the
     * memo and in the persistent store, so neither is ever served the other's
     * policies, whichever runs first.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATypeAloneIsCachedApartFromEveryRecord(): void
    {
        $store = new Repository(new ArrayStore);

        self::request($store);
        self::service()->attach(self::sharing('record'), ['posts', 7]);
        self::service()->attach(self::sharing('type'), 'posts');

        self::assertSame(['type@posts:*'], self::read(ResourceReference::type('posts')));
        self::assertSame(['record@posts:7', 'type@posts:*'], self::read(ResourceReference::record('posts', '7')));
        self::assertSame(['type@posts:*'], self::read(ResourceReference::type('posts')));

        self::request($store);

        self::assertSame(['record@posts:7', 'type@posts:*'], self::readWithoutQueries(ResourceReference::record('posts', '7')));
        self::assertSame(['type@posts:*'], self::readWithoutQueries(ResourceReference::type('posts')));
    }

    /**
     * A check on a resource of a tenant decided outside it, at platform scope,
     * reads the platform-wide attachments and the denies attached in the
     * resource's own tenant, each once, but not that tenant's allows; a check
     * decided in the tenant reads all of them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResourceDecidedOutsideItsTenantStillReadsThatTenantsDenies(): void
    {
        $tenant = self::createTenant('tenant-b');
        $lock   = Policy::create(['name' => 'lock', 'document' => ['statements' => [
            ['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:1']],
            ['sid' => 'no-delete', 'effect' => 'deny', 'actions' => ['posts:delete']],
        ]]]);

        self::service()->attach($lock, ['posts', 7], $tenant);
        self::service()->attach(self::sharing('in-b'), ['posts', 7], $tenant);
        self::service()->attach(Policy::create(['name' => 'platform', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['posts:purge']]]]]), 'posts');

        $record  = ResourceReference::record('posts', '7', Reference::of($tenant));
        $outside = self::byName(self::policies($record));

        DB::enableQueryLog();
        DB::flushQueryLog();

        $inside  = self::byName(TenantScope::within($tenant, null, static fn (): array => self::policies($record)));
        $queries = \count(DB::getQueryLog());

        DB::disableQueryLog();

        self::assertSame(1, $queries);

        self::assertSame(['lock', 'platform'], \array_keys($outside));
        self::assertSame([1], \array_keys($outside['lock']->statements));
        self::assertSame('no-delete', $outside['lock']->statements[1]->sid);
        self::assertSame(['posts:7', 'posts:*'], [$outside['lock']->resource, $outside['platform']->resource]);
        self::assertSame(['in-b', 'lock', 'platform'], \array_keys($inside));
        self::assertCount(2, $inside['lock']->statements);
    }

    /**
     * Without a resolution cache bound, the policies are read straight from the
     * database.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReadsFromTheDatabaseWithoutACache(): void
    {
        self::service()->attach(self::sharing('record'), ['posts', 7]);
        self::service()->attach(self::sharing('type'), 'posts');

        $this->app?->forgetInstance(ResolutionCache::class);
        $this->app?->offsetUnset(ResolutionCache::class);

        self::assertSame(['record@posts:7', 'type@posts:*'], self::read(ResourceReference::record('posts', '7')));
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
     * The policies attached to records of the type that hold in the current
     * scope and name the action are read, each once, as attached to the type's
     * records; one attached to the type alone, to another type's records, in
     * another tenant or for another application, or naming another action is
     * not; a type longer than the table stores has none, and a document that
     * cannot be read throws.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePoliciesAttachedToRecordsInTheScopeAreRead(): void
    {
        $service  = self::service();
        $resolver = new ResourcePolicyResolver;
        $long     = \str_repeat('p', Reference::MAX_BYTES);
        $names    = static fn (array $policies): array => \array_map(static fn (EvaluationPolicy $policy): string => $policy->name . ' ' . $policy->resource, $policies);

        $service->attach(self::sharing('type'), 'posts');
        $service->attach(self::sharing('other'), ['comments', '1']);
        $edit = self::sharing('edit', 'posts:edit');

        $service->attach($edit, ['posts', '1']);
        $service->attach($edit, ['posts', '3']);
        $service->attach(self::sharing('read'), ['posts', '2'], new Reference('teams', '5'), true, 'admin');
        $service->attach(self::sharing('long'), [$long, '1']);

        self::assertSame([], $resolver->recordPoliciesFor('posts', 'posts:read', 10));
        self::assertSame(['edit posts:*'], $names($resolver->recordPoliciesFor('posts', 'posts:edit', 10) ?? []));
        $read   = static fn (): array => $resolver->recordPoliciesFor('posts', 'posts:read', 10);
        $inTeam = static fn (?string $application): array => TenantScope::within(new Reference('teams', '5'), $application, $read);

        self::assertSame([], $inTeam(null));
        self::assertSame(['read posts:*'], $names($inTeam('admin')));
        self::assertCount(1, $resolver->recordPoliciesFor($long, 'posts:read', 10) ?? []);
        self::assertSame([], $resolver->recordPoliciesFor($long . 'p', 'posts:read', 10));

        $id = (string) Str::uuid();

        DB::table('policies')->insert(['id' => $id, 'name' => 'unreadable', 'document' => '{"statements":[{"effect":"allow"}]}', 'created_at' => now(), 'updated_at' => now()]);
        DB::table('resource_policies')->insert(['policy_id' => $id, 'resource_type' => 'comments', 'resource_id' => '9']);

        $this->expectException(InvalidPolicyDocumentException::class);

        $resolver->recordPoliciesFor('comments', 'posts:edit', 10);
    }

    /**
     * The attached policies are read a page at a time, on the write connection,
     * and none after one more than the limit has been found, or after four
     * times the limit have been scanned whatever their actions: either is
     * reported as more than allowed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRecordPoliciesAreReadAPageAtATimeUpToOneOverTheLimit(): void
    {
        $service = self::service();

        for ($index = 0; $index < 101; $index++) {
            $service->attach(self::sharing('read-' . $index), ['posts', (string) $index]);
        }

        config()->set('authorization.models.policy', QueryRecordingPolicy::class);
        QueryRecorder::reset();

        /** @var \ArrayObject<int, string> $pages */
        $pages = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($pages): void {
            $pages[] = \strtolower($query->sql);
        });

        self::assertNull((new ResourcePolicyResolver)->recordPoliciesFor('posts', 'posts:read', 3));
        self::assertCount(1, $pages);
        self::assertStringContainsString('limit 100', $pages[0] ?? '');
        self::assertTrue(QueryRecorder::recorded()[0]->useWritePdo);
        self::assertCount(101, (new ResourcePolicyResolver)->recordPoliciesFor('posts', 'posts:read', 101) ?? []);

        $pages->exchangeArray([]);

        self::assertSame([], (new ResourcePolicyResolver)->recordPoliciesFor('posts', 'posts:edit', 26));
        self::assertCount(2, $pages);
        self::assertNull((new ResourcePolicyResolver)->recordPoliciesFor('posts', 'posts:edit', 25));

        DB::getEventDispatcher()?->forget(QueryExecuted::class);
    }

    /**
     * Many resources read exactly what each reads on its own, keyed as they
     * are: the records of a type in one query, a type alone in one, and the
     * denies a tenant decided outside attached in one more; a resource with no
     * type, or one longer than the table stores, none; and once read, each
     * record reads its own from the cache.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testManyResourcesReadWhatEachReadsAlone(): void
    {
        $tenant = self::createTenant('tenant-b');
        $both   = self::sharing('both');

        self::service()->attach($both, 'posts');
        self::service()->attach($both, ['posts', 7]);
        self::service()->attach(self::sharing('record'), ['posts', 8]);
        self::service()->attach(self::sharing('docs'), 'docs');
        self::service()->attach(Policy::create(['name' => 'lock', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['posts:delete']]]]]), ['posts', 7], $tenant);

        $resources = [
            'seven'   => ResourceReference::record('posts', '7'),
            'eight'   => ResourceReference::record('posts', '8'),
            9         => ResourceReference::record('posts', '7'),
            'type'    => ResourceReference::type('posts'),
            'star'    => ResourceReference::record('posts', '*'),
            'doc'     => ResourceReference::record('docs', '1'),
            'opaque'  => new ResourceReference('posts:7'),
            'none'    => null,
            'long'    => ResourceReference::record(\str_repeat('p', 192), '7'),
            'outside' => ResourceReference::record('posts', '7', Reference::of($tenant)),
        ];

        $alone = \array_map(static fn (?ResourceReference $resource): array => (new ResourcePolicyResolver)->policiesFor($resource), $resources);

        // The attachments table's key column is inspected once a request.
        ResourcePolicyResolver::resolveMany('posts', [], new ResolutionPins);

        $this->app?->forgetInstance(ResolutionCache::class);

        DB::enableQueryLog();
        DB::flushQueryLog();

        $many    = (new ResourcePolicyResolver)->policiesForMany($resources);
        $queries = \count(DB::getQueryLog());

        DB::disableQueryLog();

        self::assertSame(\array_map(self::described(...), $alone), \array_map(self::described(...), $many));
        self::assertSame(\array_keys($resources), \array_keys($many));
        self::assertSame(['lock@posts:7'], \array_map(static fn (EvaluationPolicy $policy): string => $policy->name . '@' . $policy->resource, \array_slice($many['outside'], 1)));
        self::assertSame(4, $queries);
        self::assertSame(['both@posts:7'], self::readWithoutQueries(ResourceReference::record('posts', '7')));
        self::assertSame(['both@posts:*', 'record@posts:8'], self::readWithoutQueries(ResourceReference::record('posts', '8')));

        $this->app?->forgetInstance(ResolutionCache::class);
        $this->app?->offsetUnset(ResolutionCache::class);

        self::assertSame(\array_map(self::described(...), $alone), \array_map(self::described(...), (new ResourcePolicyResolver)->policiesForMany($resources)));
        self::assertSame([], (new ResourcePolicyResolver)->policiesForMany([]));
    }

    /**
     * A record named more than once is read for once, its key bound once in the
     * query, and each resource naming it reads its policies.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARecordNamedMoreThanOnceIsReadForOnce(): void
    {
        self::service()->attach(self::sharing('record'), ['posts', 'seven']);

        // The attachments table's key column is inspected once a request.
        ResourcePolicyResolver::resolveMany('posts', [], new ResolutionPins);

        $this->app?->forgetInstance(ResolutionCache::class);

        DB::enableQueryLog();
        DB::flushQueryLog();

        $many = (new ResourcePolicyResolver)->policiesForMany([
            'a' => ResourceReference::record('posts', 'seven'),
            'b' => ResourceReference::record('posts', 'seven'),
            'c' => ResourceReference::record('posts', 'eight'),
        ]);
        $bindings = \array_merge(...\array_map(static fn (array $query): array => $query['bindings'], DB::getQueryLog()));

        DB::disableQueryLog();

        $named = static fn (array $policies): array => \array_map(static fn (EvaluationPolicy $policy): string => $policy->name . '@' . $policy->resource, $policies);

        self::assertSame(['record@posts:seven'], $named($many['a']));
        self::assertSame(['record@posts:seven'], $named($many['b']));
        self::assertSame([], $many['c']);
        self::assertSame([1, 1], [\count(\array_keys($bindings, 'seven', true)), \count(\array_keys($bindings, 'eight', true))]);
    }

    /**
     * A record whose policies include a document that cannot be read is left
     * out of the bulk read, its document read once, and is read on its own,
     * which throws; a record of a key that is not UTF-8 is read on its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARecordThatCannotBeReadInBulkIsReadOnItsOwn(): void
    {
        $logger = new RecordingLogger;
        $this->app?->instance('log', $logger);

        $broken = self::sharing('broken');

        self::service()->attach(self::sharing('type'), 'posts');
        self::service()->attach($broken, ['posts', 8]);

        DB::table('policies')->where('id', $broken->id)->update(['document' => \json_encode(['statements' => [['effect' => 'deny', 'actions' => []]]])]);

        $read = ResourcePolicyResolver::resolveMany('posts', ['7', '8', '9'], new ResolutionPins);

        self::assertSame([7, 9], \array_keys($read));
        self::assertSame(['type'], \array_map(static fn (EvaluationPolicy $policy): string => $policy->name, $read[7]->value));
        self::assertCount(1, $logger->records);

        if (DB::connection()->getDriverName() !== 'pgsql') {
            $read = (new ResourcePolicyResolver)->policiesForMany([ResourceReference::record('posts', "\xff")])[0];

            self::assertSame(['type@posts:*'], \array_map(static fn (EvaluationPolicy $policy): string => $policy->name . '@' . $policy->resource, $read));
        }

        $this->expectException(InvalidPolicyDocumentException::class);

        (new ResourcePolicyResolver)->policiesForMany([ResourceReference::record('posts', '7'), ResourceReference::record('posts', '8')]);
    }

    /**
     * Several records of one tenant decided outside it each read the denies
     * attached to them in that tenant, as each does on its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRecordsOfOneTenantDecidedOutsideItEachReadItsDenies(): void
    {
        $tenant = self::createTenant('tenant-b');

        foreach (['7', '8'] as $id) {
            $lock = Policy::create(['name' => "lock-{$id}", 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['posts:delete']]]]]);

            self::service()->attach($lock, ['posts', $id], $tenant);
        }

        $resources = ['seven' => ResourceReference::record('posts', '7', Reference::of($tenant)), 'eight' => ResourceReference::record('posts', '8', Reference::of($tenant))];
        $alone     = \array_map(static fn (ResourceReference $resource): array => (new ResourcePolicyResolver)->policiesFor($resource), $resources);

        $this->app?->forgetInstance(ResolutionCache::class);

        $many  = (new ResourcePolicyResolver)->policiesForMany($resources);
        $names = static fn (array $policies): array => \array_map(static fn (EvaluationPolicy $policy): string => $policy->name . '@' . $policy->resource, $policies);

        self::assertSame(['seven' => ['lock-7@posts:7'], 'eight' => ['lock-8@posts:8']], \array_map($names, $many));
        self::assertSame(\array_map(self::described(...), $alone), \array_map(self::described(...), $many));
    }

    /**
     * A document attached to the type that cannot be read is hydrated once
     * however many records are read with it, so it is written to the log
     * channel once, and every record is left out, to be read on its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATypesUnreadableDocumentIsHydratedOnce(): void
    {
        $logger = new RecordingLogger;
        $this->app?->instance('log', $logger);

        $broken = self::sharing('broken');

        self::service()->attach($broken, 'posts');

        DB::table('policies')->where('id', $broken->id)->update(['document' => \json_encode(['statements' => [['effect' => 'deny', 'actions' => []]]])]);

        self::assertSame([], ResourcePolicyResolver::resolveMany('posts', ['7', '8', '9'], new ResolutionPins));
        self::assertCount(1, $logger->records);
    }

    /**
     * A type exactly as long as the table stores is read as any other; one byte
     * longer has no attachments.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATypeAsLongAsTheTableStoresIsRead(): void
    {
        $type = \str_repeat('p', Reference::MAX_BYTES);

        self::service()->attach(self::sharing('longest'), $type);

        $read = (new ResourcePolicyResolver)->policiesForMany([ResourceReference::record($type, '7'), ResourceReference::record($type . 'p', '7')]);

        self::assertSame(['longest'], \array_map(static fn (EvaluationPolicy $policy): string => $policy->name, $read[0]));
        self::assertSame([], $read[1]);
    }

    /**
     * A table whose key column folds case is never read in bulk: each record
     * reads its own, under the column's comparison, so a record finds an
     * attachment of its key in another case as it does on its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATableFoldingKeysIsReadForEachRecordOnItsOwn(): void
    {
        $this->app?->make('config')->set('authorization.tables.resource_policies', 'scoped_folded_resource_policies');

        $policy = self::sharing('folded');

        DB::table('scoped_folded_resource_policies')->insert(['policy_id' => $policy->getKey(), 'resource_type' => 'docs', 'resource_id' => 'ABC']);

        $records = [ResourceReference::record('docs', 'abc'), ResourceReference::record('docs', 'ABC'), ResourceReference::record('docs', 'abd')];
        $alone   = \array_map(static fn (ResourceReference $resource): array => (new ResourcePolicyResolver)->policiesFor($resource), $records);

        $this->app?->forgetInstance(ResolutionCache::class);

        self::assertSame([], ResourcePolicyResolver::resolveMany('docs', ['abc', 'ABC'], new ResolutionPins));
        self::assertSame(\array_map(self::described(...), $alone), \array_map(self::described(...), (new ResourcePolicyResolver)->policiesForMany($records)));
        self::assertSame(['folded@docs:ABC'], \array_map(static fn (EvaluationPolicy $policy): string => $policy->name . '@' . $policy->resource, $alone[0]));
    }

    /**
     * Describe each policy by its id, its name, what it is attached to and its
     * document, sorted, as the order the rows are read in decides nothing.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @return list<string>
     */
    private static function described(array $policies): array
    {
        $described = \array_map(static fn (EvaluationPolicy $policy): string => "{$policy->id} {$policy->name}@{$policy->resource} " . \json_encode($policy->toArray()), $policies);

        \sort($described);

        return $described;
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
     * Key the policies by name, sorted.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @return array<string, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    private static function byName(array $policies): array
    {
        $named = [];

        foreach ($policies as $policy) {
            $named[$policy->name] = $policy;
        }

        \ksort($named);

        return $named;
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
     * Create a policy whose allow of the action names its principals.
     *
     * @param  string  $name
     * @param  string  $action
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function sharing(string $name, string $action = 'posts:read'): Policy
    {
        return Policy::create(['name' => $name, 'document' => ['statements' => [['effect' => 'allow', 'actions' => [$action], 'principals' => ['user:1']]]]]);
    }
}
