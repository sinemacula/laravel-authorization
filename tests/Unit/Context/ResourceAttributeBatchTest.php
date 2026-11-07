<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Context\ResourceAttributeBatch;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Feature\Stubs\RecordingResourceAttributes;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Fixtures\BulkChecks\AnsweringBulkAttributes;

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
        self::assertNull($batch->valuesFor(ResourceReference::record('posts', '1'), $provider));
        self::assertNull($batch->valuesFor($first, new RecordingResourceAttributes));
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

        self::assertNull($batch->valuesFor($first, $provider));
        self::assertSame(['status' => 'draft'], $batch->valuesFor($second, $provider));
        self::assertSame([['item-1']], \array_map(array_keys(...), $provider->calls));

        $batch->forget($second);

        self::assertNull($batch->valuesFor($second, $provider));
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
        self::assertNull($batch->valuesFor($refs[2], $provider));
        self::assertNull($batch->valuesFor($refs[3], $provider));

        try {
            $batch->valuesFor($refs[1], $provider);

            self::fail('The item fails.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        $broken = new AnsweringBulkAttributes([], true);
        $batch  = new ResourceAttributeBatch($refs);

        self::assertNull($batch->valuesFor($refs[0], $broken));
        self::assertNull($batch->valuesFor($refs[1], $broken));
        self::assertCount(1, $broken->calls);
    }
}
