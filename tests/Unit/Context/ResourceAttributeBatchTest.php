<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Context\ResourceAttributeBatch;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Feature\Stubs\FailingResourceAttributes;
use Tests\Feature\Stubs\RecordingResourceAttributes;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Fixtures\BulkChecks\AnsweringBulkAttributes;
use Tests\Fixtures\BulkChecks\FailingTenantTree;

/**
 * Unit tests for `ResourceAttributeBatch`, the resource attributes of a bulk
 * check's records, read in bulk as its checks first need them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ResourceAttributeBatch::class)]
final class ResourceAttributeBatchTest extends TestCase
{
    /** @var \Illuminate\Container\Container|null The container in place before the test, put back after it. */
    private ?Container $container = null;

    /**
     * Give each test a container of its own, binding the tenant tree it uses.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->container = Container::getInstance();

        Container::setInstance(new Container);
    }

    /**
     * Put the container in place before the test back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Container::setInstance($this->container);

        parent::tearDown();
    }

    /**
     * Nothing is read until a record's values are first asked for; then every
     * record of its type still to be decided is read in one call, each item
     * with its own model, and each answer is its own item's.
     *
     * @return void
     */
    public function testTheRecordsOfATypeAreReadTogetherWhenFirstNeeded(): void
    {
        $model    = new StubIdentity(['id' => '1']);
        $first    = ResourceReference::record('posts', '1', null, $model);
        $second   = ResourceReference::record('posts', '2');
        $note     = ResourceReference::record('notes', '1');
        $provider = new AnsweringBulkAttributes(['1' => ['status' => 'published'], '2' => ['status' => 'draft']]);
        $batch    = new ResourceAttributeBatch([$first, 'opaque', null, false, ResourceReference::type('posts'), $note, $second, $first]);

        $before = \count($provider->calls);

        self::assertSame(['status' => 'published'], $batch->valuesFor($first, $provider));
        self::assertSame(['status' => 'draft'], $batch->valuesFor($second, $provider));
        self::assertSame([0, 1], [$before, \count($provider->calls)]);
        self::assertSame(['item-0', 'item-2'], \array_keys($provider->calls[0]));
        self::assertSame($first, $provider->calls[0]['item-0']['resource']);
        self::assertSame($model, $provider->calls[0]['item-0']['model']);
        self::assertNull($provider->calls[0]['item-2']['model']);
        self::assertSame([], $batch->valuesFor(ResourceReference::record('posts', '1'), $provider));
    }

    /**
     * A record decided is forgotten, so it is never read for again, and the
     * next record of its type is read for without it.
     *
     * @return void
     */
    public function testARecordDecidedIsForgotten(): void
    {
        $first    = ResourceReference::record('posts', '1');
        $second   = ResourceReference::record('posts', '2');
        $provider = new AnsweringBulkAttributes(['1' => ['status' => 'published'], '2' => ['status' => 'draft']]);
        $batch    = new ResourceAttributeBatch([$first, $second]);

        $batch->forget($first);
        $batch->forget('opaque');
        $batch->forget(ResourceReference::record('posts', '3'));

        self::assertSame([], $batch->valuesFor($first, $provider));
        self::assertSame(['status' => 'draft'], $batch->valuesFor($second, $provider));
        self::assertSame([['item-1']], \array_map(array_keys(...), $provider->calls));

        $batch->forget($second);

        self::assertSame([], $batch->valuesFor($second, $provider));
    }

    /**
     * An item's failure is thrown for that item alone; an item the answer
     * leaves out, or gives no values for, and every item when the call throws,
     * have none, so each is asked about on its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testFailuresAndGapsAreKeptToTheirOwnItems(): void
    {
        $failure  = new \RuntimeException('lookup failed');
        $refs     = \array_map(static fn (string $id): ResourceReference => ResourceReference::record('posts', $id), ['1', '2', '3', '4']);
        $provider = new AnsweringBulkAttributes(['1' => ['status' => 'published'], '2' => $failure, '4' => 'not values']);
        $batch    = new ResourceAttributeBatch($refs);

        self::assertSame(['status' => 'published'], $batch->valuesFor($refs[0], $provider));
        self::assertSame([], $batch->valuesFor($refs[2], $provider));
        self::assertSame([], $batch->valuesFor($refs[3], $provider));

        try {
            $batch->valuesFor($refs[1], $provider);

            self::fail('The item fails.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        $broken = new AnsweringBulkAttributes([], true);
        $batch  = new ResourceAttributeBatch($refs);

        self::assertSame([], $batch->valuesFor($refs[0], $broken));
        self::assertSame([], $batch->valuesFor($refs[1], $broken));
        self::assertCount(1, $broken->calls);
    }

    /**
     * A record's values are read with those of the other records of its type
     * decided in the same scope alone: those with no tenant where the request
     * is, those of each tenant within the decision's in their own, and those of
     * any other tenant at platform scope, each scope told once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRecordsOfEachScopeAreReadApart(): void
    {
        $org  = new Reference('teams', 'o1');
        $tree = $this->tree(['a1' => $org, 'a2' => $org]);
        $refs = [
            'here'  => ResourceReference::record('posts', '1'),
            'a1'    => ResourceReference::record('posts', '2', new Reference('teams', 'a1')),
            'again' => ResourceReference::record('posts', '3', new Reference('teams', 'a1')),
            'a2'    => ResourceReference::record('posts', '4', new Reference('teams', 'a2')),
            'out'   => ResourceReference::record('posts', '5', new Reference('teams', 'o2')),
            'other' => ResourceReference::record('posts', '6', new Reference('teams', 'o3')),
            'own'   => ResourceReference::record('posts', '7', $org),
        ];
        $provider = new AnsweringBulkAttributes(\array_fill_keys(['1', '2', '3', '4', '5', '6', '7'], ['status' => 'published']));
        $batch    = new ResourceAttributeBatch(\array_values($refs), $org);

        foreach (['a1', 'out', 'here', 'a2', 'own', 'again', 'other'] as $name) {
            self::assertSame(['status' => 'published'], $batch->valuesFor($refs[$name], $provider));
        }

        $ids = static fn (array $items): array => \array_values(\array_map(static fn (array $item): string => (string) $item['resource']->id, $items));

        self::assertSame([['2', '3'], ['5', '6'], ['1'], ['4'], ['7']], \array_map($ids, $provider->calls));
        self::assertSame(6, $tree->reads);
    }

    /**
     * With no decision's tenant, every record of a tenant is decided at
     * platform scope, so they are read together, apart from those with none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutATenantEveryOwnedRecordIsReadAtPlatformScope(): void
    {
        $tree = $this->tree();
        $refs = [
            ResourceReference::record('posts', '1', new Reference('teams', 'a1')),
            ResourceReference::record('posts', '2'),
            ResourceReference::record('posts', '3', new Reference('teams', 'a2')),
        ];
        $provider = new AnsweringBulkAttributes(['1' => ['status' => 'draft']]);
        $batch    = new ResourceAttributeBatch($refs);

        self::assertSame(['status' => 'draft'], $batch->valuesFor($refs[0], $provider));
        self::assertSame([['item-0', 'item-2']], \array_map(array_keys(...), $provider->calls));
        self::assertSame(0, $tree->reads);
    }

    /**
     * A record whose tenant's place in the tree cannot be read is read alone,
     * never with another, and never with another whose place cannot be read
     * either.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARecordWhoseScopeCannotBeToldIsReadAlone(): void
    {
        $org = new Reference('teams', 'o1');
        $this->tree(['a1' => $org], ['boom', 'bang']);
        $refs = [
            ResourceReference::record('posts', '1', new Reference('teams', 'boom')),
            ResourceReference::record('posts', '2', new Reference('teams', 'a1')),
            ResourceReference::record('posts', '3', new Reference('teams', 'bang')),
        ];
        $provider = new AnsweringBulkAttributes(['1' => ['status' => 'a'], '2' => ['status' => 'b'], '3' => ['status' => 'c']]);
        $batch    = new ResourceAttributeBatch($refs, $org);

        self::assertSame(['status' => 'b'], $batch->valuesFor($refs[1], $provider));
        self::assertSame(['status' => 'a'], $batch->valuesFor($refs[0], $provider));
        self::assertSame(['status' => 'c'], $batch->valuesFor($refs[2], $provider));
        self::assertSame([['item-1'], ['item-0'], ['item-2']], \array_map(array_keys(...), $provider->calls));
    }

    /**
     * An item the answer leaves out, read before one it gives values for,
     * leaves the later item's values in place.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGapBeforeAnAnswerKeepsTheAnswer(): void
    {
        $refs     = [ResourceReference::record('posts', '3'), ResourceReference::record('posts', '1')];
        $provider = new AnsweringBulkAttributes(['1' => ['status' => 'published']]);
        $batch    = new ResourceAttributeBatch($refs);

        self::assertSame([], $batch->valuesFor($refs[0], $provider));
        self::assertSame(['status' => 'published'], $batch->valuesFor($refs[1], $provider));
        self::assertCount(1, $provider->calls);
    }

    /**
     * A reference tracked again, by a later chunk say, stays the item it is,
     * read once; a record tracked after it was forgotten is an item of its own,
     * under a token never given before.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReferenceTrackedAgainStaysOneItem(): void
    {
        $shared   = ResourceReference::record('posts', '1');
        $other    = ResourceReference::record('posts', '2');
        $provider = new AnsweringBulkAttributes(['1' => ['status' => 'published'], '2' => ['status' => 'draft']]);
        $batch    = new ResourceAttributeBatch([$shared]);

        self::assertSame(['status' => 'published'], $batch->valuesFor($shared, $provider));

        $batch->track([$shared, 'opaque', ResourceReference::type('posts'), $other, $shared]);

        self::assertSame(['status' => 'published'], $batch->valuesFor($shared, $provider));
        self::assertSame(['status' => 'draft'], $batch->valuesFor($other, $provider));

        $batch->forget($shared);
        $batch->track([$shared]);

        self::assertSame(['status' => 'published'], $batch->valuesFor($shared, $provider));
        self::assertSame([['item-0'], ['item-1'], ['item-2']], \array_map(array_keys(...), $provider->calls));
    }

    /**
     * A provider that does not read in bulk is asked about a tracked record
     * once, its values or its failure kept for every check on it until the
     * record is forgotten; a record the batch does not track is asked about
     * every time.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProviderThatDoesNotReadInBulkIsAskedOnceForEachItem(): void
    {
        $model    = new StubIdentity(['id' => '1']);
        $record   = ResourceReference::record('posts', '1', null, $model);
        $loose    = ResourceReference::record('posts', '2');
        $provider = new RecordingResourceAttributes('published');
        $batch    = new ResourceAttributeBatch([$record]);

        self::assertSame('published', $batch->valuesFor($record, $provider)['status']);
        self::assertSame('published', $batch->valuesFor($record, $provider)['status']);
        $calls = $provider->calls;

        self::assertSame([[$record, $model]], $calls);

        $batch->valuesFor($loose, $provider);
        $batch->valuesFor($loose, $provider);
        $batch->forget($record);
        $batch->valuesFor($record, $provider);

        self::assertSame([$record, $loose, $loose, $record], \array_column($provider->calls, 0));

        $failing = new FailingResourceAttributes;
        $batch   = new ResourceAttributeBatch([$record]);

        foreach ([1, 2] as $attempt) {
            try {
                $batch->valuesFor($record, $failing);

                self::fail("Attempt {$attempt} fails.");
            } catch (\RuntimeException $exception) {
                self::assertSame(FailingResourceAttributes::MESSAGE, $exception->getMessage());
            }
        }

        self::assertSame(1, $failing->calls);
    }

    /**
     * Bind a tenant tree holding the tenants under the parents given, failing
     * for those given, and return it.
     *
     * @param  array<string, \SineMacula\Laravel\Authorization\Support\Reference>  $parents
     * @param  list<string>  $failing
     * @return \Tests\Fixtures\BulkChecks\FailingTenantTree
     */
    private function tree(array $parents = [], array $failing = []): FailingTenantTree
    {
        $tree = new FailingTenantTree($parents, $failing);

        Container::getInstance()->instance(TenantTree::class, $tree);

        return $tree;
    }
}
