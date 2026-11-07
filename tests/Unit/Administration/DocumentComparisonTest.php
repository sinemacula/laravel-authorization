<?php

declare(strict_types = 1);

namespace Tests\Unit\Administration;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Administration\DocumentComparison;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\Statement;

/**
 * Unit tests for `DocumentComparison`: two versions of a policy document
 * compared conservatively, statement by statement.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DocumentComparison::class)]
final class DocumentComparisonTest extends TestCase
{
    /** @var array<string, mixed> An allow of reading posts. */
    private const array READ = ['effect' => 'allow', 'actions' => ['posts:read']];

    /** @var array<string, mixed> An allow of editing posts. */
    private const array EDIT = ['effect' => 'allow', 'actions' => ['posts:edit']];

    /** @var array<string, mixed> A deny of deleting posts. */
    private const array DENY = ['effect' => 'deny', 'actions' => ['posts:delete']];

    /**
     * A stored document is read as the policy it holds, named or not; anything
     * that is not a readable document reads as none.
     *
     * @return void
     */
    public function testADocumentIsReadAsItsPolicy(): void
    {
        $named   = DocumentComparison::read(['name' => 'readers', 'statements' => [self::READ]]);
        $unnamed = DocumentComparison::read(['statements' => [self::READ]]);

        self::assertInstanceOf(Policy::class, $named);
        self::assertSame('readers', $named->name);
        self::assertCount(1, $unnamed->statements ?? []);
        self::assertNull(DocumentComparison::read('{"statements":[]}'));
        self::assertNull(DocumentComparison::read(null));
        self::assertNull(DocumentComparison::read(['statements' => [['effect' => 'allow']]]));
        self::assertNull(DocumentComparison::read(['statements' => 'none']));
    }

    /**
     * A document narrows when it only removes allows or adds denies, the same
     * document in another order or with other sids included; one that adds or
     * changes an allow, or lifts a deny, does not, and neither does one of
     * another version or one that cannot be read.
     *
     * @return void
     */
    public function testOnlyARemovedAllowOrAnAddedDenyNarrows(): void
    {
        $old = self::document([self::READ, self::EDIT, self::DENY]);

        self::assertTrue(DocumentComparison::isNarrower($old, self::document([self::DENY, self::EDIT, self::READ])));
        self::assertTrue(DocumentComparison::isNarrower($old, self::document([[...self::READ, 'sid' => 'read'], self::EDIT, self::DENY])));
        self::assertTrue(DocumentComparison::isNarrower($old, self::document([self::READ, self::DENY])));
        self::assertTrue(DocumentComparison::isNarrower($old, self::document([self::READ, self::EDIT, self::DENY, ['effect' => 'deny', 'actions' => ['posts:read']]])));
        self::assertFalse(DocumentComparison::isNarrower($old, self::document([self::READ, self::EDIT])));
        self::assertFalse(DocumentComparison::isNarrower($old, self::document([self::READ, self::EDIT, self::DENY, ['effect' => 'allow', 'actions' => ['posts:archive']]])));
        self::assertFalse(DocumentComparison::isNarrower($old, self::document([['effect' => 'allow', 'actions' => ['posts:read', 'posts:edit']], self::DENY])));
        self::assertFalse(DocumentComparison::isNarrower($old, self::document([[...self::READ, 'resources' => ['posts:1']], self::EDIT, self::DENY])));
        self::assertFalse(DocumentComparison::isNarrower($old, self::document([self::READ, self::EDIT, self::DENY], 2)));
        self::assertFalse(DocumentComparison::isNarrower(self::document([self::DENY]), self::document([[...self::DENY, 'effect' => 'allow']])));
        self::assertFalse(DocumentComparison::isNarrower(null, $old));
        self::assertFalse(DocumentComparison::isNarrower($old, null));
    }

    /**
     * A document keeps the denies when it holds every deny the old one held, in
     * the same version.
     *
     * @return void
     */
    public function testADocumentKeepsTheDeniesItHoldsStill(): void
    {
        $old = self::document([self::READ, self::DENY]);

        self::assertTrue(DocumentComparison::keepsDenies($old, self::document([self::EDIT, self::DENY])));
        self::assertFalse(DocumentComparison::keepsDenies($old, self::document([self::READ])));
        self::assertFalse(DocumentComparison::keepsDenies($old, self::document([self::DENY], 2)));
        self::assertFalse(DocumentComparison::keepsDenies(self::document([self::DENY]), self::document([[...self::DENY, 'effect' => 'allow']])));
        self::assertFalse(DocumentComparison::keepsDenies(null, $old));
        self::assertFalse(DocumentComparison::keepsDenies($old, null));
    }

    /**
     * The allows a document adds are those the old one did not hold, every
     * allow when there is no old one, never a deny.
     *
     * @return void
     */
    public function testTheAllowsAddedAreThoseNotHeldBefore(): void
    {
        $new = self::document([self::READ, self::EDIT, self::DENY]);

        $added = DocumentComparison::added(self::document([self::READ]), $new);

        self::assertCount(1, $added);
        self::assertSame(['posts:edit'], $added[0]->actions);
        self::assertSame([['posts:read'], ['posts:edit']], \array_map(static fn (Statement $statement): ?array => $statement->actions, DocumentComparison::added(null, $new)));
        self::assertSame([], DocumentComparison::added($new, self::document([self::READ, self::DENY])));
    }

    /**
     * Return the policy of the statements, in the version, built in code so a
     * version no document may name yet can be compared.
     *
     * @param  list<array<string, mixed>>  $statements
     * @param  int  $version
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     */
    private static function document(array $statements, int $version = 1): Policy
    {
        return new Policy('document', \array_map(Statement::fromArray(...), $statements), $version);
    }
}
