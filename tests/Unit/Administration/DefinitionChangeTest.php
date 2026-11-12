<?php

declare(strict_types = 1);

namespace Tests\Unit\Administration;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Administration\DefinitionChange;

/**
 * Unit tests for `DefinitionChange`: the change to a definition an operation
 * proposes, as values.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DefinitionChange::class)]
final class DefinitionChangeTest extends TestCase
{
    /**
     * The change holds the record, the values, the document and the other role
     * of a pair given, and proposes exactly the attributes among its values, a
     * null one included.
     *
     * @return void
     */
    public function testItHoldsWhatTheChangeProposes(): void
    {
        $record   = new class extends Model {};
        $document = ['name' => 'readers', 'statements' => []];
        $change   = new DefinitionChange($record, ['name' => 'writer', 'parent' => null], $document);

        self::assertSame($record, $change->record);
        self::assertSame(['name' => 'writer', 'parent' => null], $change->values);
        self::assertSame($document, $change->document);
        self::assertNull($change->related);
        self::assertTrue($change->proposes('name'));
        self::assertTrue($change->proposes('parent'));
        self::assertFalse($change->proposes('rank'));

        $bare = new DefinitionChange($record);

        self::assertSame([], $bare->values);
        self::assertNull($bare->document);
        self::assertFalse($bare->proposes('name'));

        $excluded = new class extends Model {};

        self::assertSame($excluded, (new DefinitionChange($record, [], null, $excluded))->related);
    }
}
