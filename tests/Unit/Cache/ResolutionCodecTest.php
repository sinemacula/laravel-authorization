<?php

declare(strict_types = 1);

namespace Tests\Unit\Cache;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Cache\ResolutionCodec;
use SineMacula\Laravel\Authorization\Evaluation\Policy;

/**
 * Unit tests for `ResolutionCodec`, which writes what a resolution finds to the
 * persistent tier and reads it back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ResolutionCodec::class)]
final class ResolutionCodecTest extends TestCase
{
    /**
     * An entry holds its versions, its value and when it lapses.
     *
     * @return void
     */
    public function testRecognisesAnEntry(): void
    {
        self::assertTrue(ResolutionCodec::isEntry(['versions' => ['k' => 't'], 'value' => [], 'until' => 1]));
    }

    /**
     * Anything else is not an entry.
     *
     * @return iterable<string, array{mixed}>
     */
    public static function nonEntries(): iterable
    {
        yield 'not an array' => ['entry'];
        yield 'no lapse' => [['versions' => ['k' => 't'], 'value' => []]];
        yield 'a lapse that is not a time' => [['versions' => ['k' => 't'], 'value' => [], 'until' => '1']];
        yield 'no value' => [['versions' => ['k' => 't'], 'until' => 1]];
        yield 'a value that is not a list' => [['versions' => ['k' => 't'], 'value' => 'v', 'until' => 1]];
        yield 'no versions' => [['value' => [], 'until' => 1]];
        yield 'versions that are not a map' => [['versions' => 'k', 'value' => [], 'until' => 1]];
        yield 'no version at all' => [['versions' => [], 'value' => [], 'until' => 1]];
    }

    /**
     * A value without the shape of an entry is refused.
     *
     * @param  mixed  $entry
     * @return void
     */
    #[DataProvider('nonEntries')]
    public function testRefusesAValueWithoutTheShapeOfAnEntry(mixed $entry): void
    {
        self::assertFalse(ResolutionCodec::isEntry($entry));
    }

    /**
     * Names are read back as they were written, and anything but a name is
     * refused.
     *
     * @return void
     */
    public function testReadsNamesBack(): void
    {
        self::assertSame(['editor', 'viewer'], ResolutionCodec::names(['editor', 'viewer']));

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Cached name is not a string.');

        ResolutionCodec::names(['editor', 7]);
    }

    /**
     * A policy is written as its key, its document and the resource it is
     * attached to, and read back as it was.
     *
     * @return void
     */
    public function testWritesAndReadsAPolicyBack(): void
    {
        $sharing  = ['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:1']];
        $policy   = Policy::fromArray(['name' => 'sharing', 'statements' => [$sharing]])->withId('key')->withResource('posts:7');
        $unkeyed  = Policy::fromArray(['name' => 'readers', 'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]);
        $written  = [ResolutionCodec::encodePolicy($policy), ResolutionCodec::encodePolicy($unkeyed)];
        $hydrated = ResolutionCodec::policies($written);

        self::assertSame(['id' => 'key', 'document' => $policy->toArray(), 'resource' => 'posts:7'], $written[0]);
        self::assertSame(['id' => null, 'document' => $unkeyed->toArray(), 'resource' => null], $written[1]);
        self::assertEquals([$policy, $unkeyed], $hydrated);
        self::assertSame('key', $hydrated[0]->id);
        self::assertSame('posts:7', $hydrated[0]->resource);
    }

    /**
     * Stored policies that are not documents with their keys.
     *
     * @return iterable<string, array{array<mixed>}>
     */
    public static function corruptPolicies(): iterable
    {
        $document = ['name' => 'p', 'statements' => []];

        yield 'not an array' => [['policy']];
        yield 'no document' => [[['id' => 'k']]];
        yield 'a document that is not an array' => [[['id' => 'k', 'document' => 'p']]];
        yield 'a key that is not a string' => [[['id' => 7, 'document' => $document]]];
        yield 'a resource that is not a string' => [[['id' => 'k', 'document' => $document, 'resource' => 7]]];
    }

    /**
     * A stored policy that is not a document with its key is refused.
     *
     * @param  array<mixed>  $stored
     * @return void
     */
    #[DataProvider('corruptPolicies')]
    public function testRefusesACorruptPolicy(array $stored): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Cached policy entry is not a policy document with its key.');

        ResolutionCodec::policies($stored);
    }
}
