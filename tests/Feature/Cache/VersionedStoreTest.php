<?php

declare(strict_types = 1);

namespace Tests\Feature\Cache;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Events\RetrievingManyKeys;
use Illuminate\Cache\Repository;
use Illuminate\Events\Dispatcher;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\VersionedStore;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\FailingCacheStore;
use Tests\Feature\Stubs\RecordingLogger;
use Tests\TestCase;

/**
 * Feature tests for the persistent tier's entries and version tokens, and for a
 * store that fails.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VersionedStore::class)]
final class VersionedStoreTest extends TestCase
{
    /**
     * Version keys name the grantee, role or policy under the prefix.
     *
     * @return void
     */
    public function testVersionKeysAreNamespaced(): void
    {
        $store = new VersionedStore(new Repository(new ArrayStore), 'authz');

        self::assertSame('authz:version:grantee:user:user-1', $store->granteeKey(new Reference('user', 'user-1')));
        self::assertSame('authz:version:role:role-1', $store->roleKey('role-1'));
        self::assertSame('authz:version:policy:policy-1', $store->policyKey('policy-1'));
        self::assertSame('authz:version:role-policies', $store->rolePoliciesKey());
        self::assertSame('authz:version:resource-policies', $store->resourcePoliciesKey());
        self::assertSame('authz:version:resource-policies:posts', $store->resourcePoliciesKey('posts'));
        self::assertSame('authz:version:boundaries', $store->boundariesKey());
        self::assertSame('authz:version:guardrails', $store->guardrailsKey());
        self::assertSame('authz:version:tenant:stub_tenant:tenant-a', $store->tenantKey(new Reference('stub_tenant', 'tenant-a')));
    }

    /**
     * An entry is stored for the given number of seconds and read back.
     *
     * @return void
     */
    public function testEntriesAreStoredForTheirLifetime(): void
    {
        $repository = new Repository(new ArrayStore);
        $store      = new VersionedStore($repository, 'authz');

        $store->put('entry', ['value' => ['posts:read']], 60);

        self::assertSame(['value' => ['posts:read']], $store->get('entry'));
        self::assertNull($store->get('missing'));
    }

    /**
     * Many entries are read in one read, and their recorded versions in one
     * more: an entry holds only while every version it recorded is unchanged,
     * text, and still there; a key with no entry, or one that is not an entry,
     * is left out; no keys ask the store nothing.
     *
     * @return void
     */
    public function testManyEntriesAreReadAndCheckedTogether(): void
    {
        $repository = new Repository(new ArrayStore);
        $store      = new VersionedStore($repository, 'authz');
        $entry      = static fn (array $versions): array => ['versions' => $versions, 'value' => ['posts:read'], 'until' => 100];

        $repository->forever('v1', 'token-1');
        $repository->forever('v2', 'token-2');
        $repository->forever('v4', ['token-4']);

        $repository->putMany([
            'held'    => $entry(['v1' => 'token-1']),
            'both'    => $entry(['v1' => 'token-1', 'v2' => 'token-2']),
            'bumped'  => $entry(['v1' => 'token-1', 'v2' => 'old-token']),
            'evicted' => $entry(['v3' => 'token-3']),
            'listed'  => $entry(['v1' => ['token-1']]),
            'odd'     => $entry(['v4' => 'token-4']),
            'shaped'  => ['value' => ['posts:read']],
        ], 60);

        self::assertSame(['held', 'both'], \array_keys($store->entries(['held', 'both', 'bumped', 'evicted', 'listed', 'odd', 'shaped', 'missing'])));
        self::assertSame($entry(['v1' => 'token-1']), $store->entries(['held'])['held']);
        /** @var \ArrayObject<int, list<int|string>> $reads */
        $reads  = new \ArrayObject;
        $events = new Dispatcher;

        $events->listen(RetrievingManyKeys::class, static function (RetrievingManyKeys $event) use ($reads): void {
            $reads[] = \array_keys($event->keys);
        });

        $repository->setEventDispatcher($events);

        self::assertSame([], $store->entries(['missing', 'shaped']));
        self::assertSame([['missing', 'shaped']], $reads->getArrayCopy());

        $driver = new FailingCacheStore;
        $empty  = new VersionedStore(new Repository($driver), 'authz');

        self::assertSame([], $empty->entries([]));
        self::assertSame(0, $driver->calls);
    }

    /**
     * Many entries are written in one write for each lifetime, and a store that
     * fails writes none, without throwing.
     *
     * @return void
     */
    public function testManyEntriesAreWrittenForEachLifetime(): void
    {
        $repository = new Repository(new ArrayStore);
        $store      = new VersionedStore($repository, 'authz');

        $store->putMany([60 => ['a' => ['value' => [1]], 'b' => ['value' => [2]]], 0 => ['c' => ['value' => [3]]]]);

        self::assertSame(['value' => [1]], $repository->get('a'));
        self::assertSame(['value' => [2]], $repository->get('b'));
        self::assertNull($repository->get('c'));

        $logger = new RecordingLogger;

        $this->app?->instance('log', $logger);

        (new VersionedStore(new Repository(new FailingCacheStore), 'authz'))->putMany([60 => ['a' => ['value' => [1]]]]);

        self::assertCount(1, $logger->records);
    }

    /**
     * Pinning gives a token to every key that has none, keeps the tokens of
     * those that have one, and reads the same tokens back until they are
     * bumped.
     *
     * @return void
     */
    public function testPinningCreatesMissingTokensAndKeepsTheRest(): void
    {
        $repository = new Repository(new ArrayStore);
        $store      = new VersionedStore($repository, 'authz');

        $repository->forever('kept', 'existing-token');

        $pinned = $store->pin(['kept', 'new']);

        self::assertNotNull($pinned);
        self::assertSame(['kept', 'new'], \array_keys($pinned));
        self::assertSame('existing-token', $pinned['kept']);
        self::assertSame(16, \strlen($pinned['new']));
        self::assertSame($pinned, $store->pin(['kept', 'new']));
        self::assertSame($pinned, $store->tokens(['kept', 'new']));
    }

    /**
     * A bump gives each key a new token, different from the one before.
     *
     * @return void
     */
    public function testBumpingReplacesTheTokens(): void
    {
        $store  = new VersionedStore(new Repository(new ArrayStore), 'authz');
        $before = $store->pin(['role', 'policy']);

        $store->bump(['role', 'policy']);

        $after = $store->tokens(['role', 'policy']);

        self::assertNotNull($before);
        self::assertNotNull($after);
        self::assertNotSame($before['role'], $after['role']);
        self::assertNotSame($before['policy'], $after['policy']);
        self::assertSame($after['role'], $after['policy']);

        $store->bump([]);

        self::assertSame($after, $store->tokens(['role', 'policy']));
    }

    /**
     * A store that fails returns nothing, is written to the log channel once,
     * and is not asked again, while a strict bump still tries it and throws.
     *
     * @return void
     */
    public function testAFailingStoreIsSkippedAfterItsFirstFailure(): void
    {
        $logger = new RecordingLogger;
        $this->app?->instance('log', $logger);

        $driver = new FailingCacheStore;
        $store  = new VersionedStore(new Repository($driver), 'authz');

        self::assertNull($store->get('entry'));
        self::assertSame(1, $driver->calls);

        self::assertNull($store->tokens(['key']));
        self::assertNull($store->pin(['key']));
        $store->put('entry', [], 60);
        $store->bumpQuietly(['key']);

        self::assertSame(2, $driver->calls);
        self::assertSame([
            'Authorization: the resolution cache store failed, so checks read the database for the rest of this request or job — cache unavailable',
            'Authorization: the resolution cache store failed, so checks read the database for the rest of this request or job — cache unavailable',
        ], $logger->messages());
        self::assertSame('warning', $logger->records[0]['level']);
        self::assertInstanceOf(\RuntimeException::class, $logger->records[0]['context']['exception']);

        $this->expectExceptionObject(new \RuntimeException('cache unavailable'));

        $store->bump(['key']);
    }

    /**
     * Pinning fails as a whole when a token cannot be read back.
     *
     * @return void
     */
    public function testPinningFailsWhenATokenCannotBeReadBack(): void
    {
        $store = new VersionedStore(new Repository(new class extends ArrayStore {
            /**
             * @imperative
             *
             * @param  mixed  $key
             * @param  mixed  $value
             * @param  mixed  $seconds
             * @return bool
             */
            #[\Override]
            public function put(mixed $key, mixed $value, mixed $seconds): bool
            {
                return false;
            }

            /**
             * @imperative
             *
             * @param  mixed  $key
             * @param  mixed  $value
             * @return bool
             */
            #[\Override]
            public function forever(mixed $key, mixed $value): bool
            {
                return false;
            }
        }), 'authz');

        self::assertNull($store->pin(['key']));
        self::assertSame([], $store->pin([]));
    }
}
