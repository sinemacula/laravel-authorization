<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Support\DocumentDigest;

/**
 * Unit tests for `DocumentDigest`, a policy document reported by its version
 * and the SHA-256 of its canonical JSON.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(DocumentDigest::class)]
final class DocumentDigestTest extends TestCase
{
    /**
     * The digest is the SHA-256 of the document's JSON with every object's keys
     * sorted, at every depth.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDigestsTheCanonicalJson(): void
    {
        $digest = DocumentDigest::of(['version' => 1, 'statements' => [['effect' => 'allow', 'actions' => ['posts:*']]]]);

        self::assertSame(1, $digest->version);
        self::assertSame(\hash('sha256', '{"statements":[{"actions":["posts:*"],"effect":"allow"}],"version":1}'), $digest->digest);
        self::assertSame('aa6ce750c714df5663cd0ca20d1a467b8e6d9272622ce46818797e2628e41496', $digest->digest);
    }

    /**
     * Two documents with the same content have the same digest whatever order
     * their keys were written in.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testKeyOrderDoesNotChangeTheDigest(): void
    {
        $first  = DocumentDigest::of(['version' => 1, 'statements' => [['effect' => 'deny', 'actions' => ['a'], 'resources' => ['*']]]]);
        $second = DocumentDigest::of(['statements' => [['resources' => ['*'], 'actions' => ['a'], 'effect' => 'deny']], 'version' => 1]);

        self::assertSame($first->digest, $second->digest);
    }

    /**
     * Lists keep their order, so reordering a list is a different document.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testListOrderChangesTheDigest(): void
    {
        $first  = DocumentDigest::of(['statements' => [['actions' => ['a', 'b']]]]);
        $second = DocumentDigest::of(['statements' => [['actions' => ['b', 'a']]]]);

        self::assertNotSame($first->digest, $second->digest);
    }

    /**
     * Keys are sorted as strings, and slashes, Unicode and zero fractions are
     * written as they are.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testSortsKeysAsStringsAndLeavesValuesUnescaped(): void
    {
        $digest = DocumentDigest::of(['z' => 1.0, 'a' => 'a/é', '9' => 'nine', '10' => 'ten']);

        self::assertSame(\hash('sha256', '{"10":"ten","9":"nine","a":"a/é","z":1.0}'), $digest->digest);
        self::assertSame('52e6bae0c2e3542080cfa1a170de0b7f183768e7753d17eb4122470df97e5b9b', $digest->digest);
    }

    /**
     * The version is read from the document, and a document that names none, or
     * names one that is not an integer, is the current version.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testReadsTheVersionAndFallsBackToTheCurrentOne(): void
    {
        self::assertSame(2, DocumentDigest::of(['version' => 2])->version);
        self::assertSame(1, DocumentDigest::of(['version' => '2'])->version);
        self::assertSame(1, DocumentDigest::of([])->version);
        self::assertSame(\hash('sha256', '[]'), DocumentDigest::of([])->digest);
    }
}
