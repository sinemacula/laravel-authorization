<?php

declare(strict_types = 1);

namespace Tests\Feature\Query;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Database\ComposedExpression;
use SineMacula\Laravel\Authorization\Query\Enums\ColumnKind;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Query\KeyConditions;
use SineMacula\Laravel\Authorization\Query\KeyTarget;
use SineMacula\Laravel\Authorization\Query\QueryAuthorizer;
use SineMacula\Laravel\Authorization\Query\ResourceShape;
use SineMacula\Laravel\Authorization\Query\SchemaInspector;
use Tests\Concerns\ReshapesResources;
use Tests\Fixtures\QueryScoping\FoldedDocument;
use Tests\Fixtures\QueryScoping\KeyedPost;
use Tests\Fixtures\QueryScoping\LooseKeyedPost;
use Tests\Fixtures\QueryScoping\ScopedDocument;
use Tests\Fixtures\QueryScoping\UuidScopedDocument;
use Tests\TestCase;

/**
 * Feature tests for the conditions a row's key meets for the records a pattern
 * names, on the connection under test, and the keys that cannot be compared.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(KeyConditions::class)]
final class KeyConditionsTest extends TestCase
{
    use ReshapesResources;

    /**
     * An integer key equals only an integer's canonical text within 64 bits,
     * inlined as its digits, the least as a sum: `-0`, `+1`, `01`, `1.0` and a
     * space name no record, and a canonical id beyond 64 bits is refused.
     *
     * @return void
     */
    public function testAnIntegerKeyEqualsOnlyItsCanonicalText(): void
    {
        foreach ([0, 1, -1, \PHP_INT_MAX, \PHP_INT_MIN] as $id) {
            KeyedPost::query()->create(['id' => $id, 'title' => 'post']);
        }

        $shape = self::shape(new KeyedPost);

        foreach (['0' => [0], '1' => [1], '-1' => [-1], (string) \PHP_INT_MAX => [\PHP_INT_MAX], (string) \PHP_INT_MIN => [\PHP_INT_MIN]] as $value => $expected) {
            [$condition, $reason] = KeyConditions::equals($shape, (string) $value);

            self::assertNull($reason);
            self::assertSame($expected, KeyedPost::query()->whereRaw(new ComposedExpression($condition))->pluck('id')->all(), (string) $value);
        }

        foreach (['-0', '+1', '01', '1.0', ' 1', 'abc', ''] as $value) {
            self::assertSame([QueryAuthorizer::NO_ROW, null], KeyConditions::equals($shape, $value), $value);
        }

        self::assertSame([QueryAuthorizer::NO_ROW, RefusalReason::RESOURCE_PATTERN], KeyConditions::equals($shape, '9223372036854775808'));
        self::assertSame([QueryAuthorizer::NO_ROW, RefusalReason::RESOURCE_PATTERN], KeyConditions::equals($shape, '-9223372036854775809'));
        self::assertSame(["{$shape->key} = (-9223372036854775807 - 1)", null], KeyConditions::equals($shape, (string) \PHP_INT_MIN));
        self::assertSame(["{$shape->key} = -1", null], KeyConditions::equals($shape, '-1'));
    }

    /**
     * A string key equals a value byte for byte, whatever case, padding or
     * normalisation the database might fold, the plain comparison an index can
     * serve first, and starts with one the same way, a key exactly the start
     * left out when asked.
     *
     * @return void
     */
    public function testAStringKeyComparesBytes(): void
    {
        foreach (['abc', 'ABC', 'abc ', ' abc', 'ábc', "a\u{0301}bc", 'x:*', 'x:*y'] as $code) {
            ScopedDocument::query()->create(['code' => $code]);
        }

        $shape = self::shape(new ScopedDocument);
        $codes = static fn (string $condition): array => ScopedDocument::query()->whereRaw(new ComposedExpression($condition))->orderBy('row_id')->pluck('code')->all();

        self::assertSame(['abc'], $codes(KeyConditions::equals($shape, 'abc')[0]));
        self::assertStringStartsWith('(' . $shape->dialect->equalsIndexed($shape->key, ColumnKind::STRING, 'abc') . ' AND ', KeyConditions::equals($shape, 'abc')[0]);
        self::assertSame(['ábc'], $codes(KeyConditions::equals($shape, 'ábc')[0]));
        self::assertSame(['abc', 'abc '], $codes(KeyConditions::of($shape, KeyTarget::prefix('abc', false))[0]));
        self::assertSame(['x:*y'], $codes(KeyConditions::of($shape, KeyTarget::prefix('x:*', true))[0]));
        self::assertSame([QueryAuthorizer::EVERY_ROW, null], KeyConditions::of($shape, KeyTarget::all()));
        self::assertSame([QueryAuthorizer::NO_ROW, null], KeyConditions::of($shape, KeyTarget::none()));
    }

    /**
     * An integer key's text starts with a value as its decimal digits do.
     *
     * @return void
     */
    public function testAnIntegerKeyStartsWithItsDigits(): void
    {
        foreach ([1, 10, 12, -1, 21] as $id) {
            KeyedPost::query()->create(['id' => $id, 'title' => 'post']);
        }

        $shape = self::shape(new KeyedPost);

        $prefixed = new ComposedExpression(KeyConditions::of($shape, KeyTarget::prefix('1', false))[0]);

        self::assertSame([1, 10, 12], KeyedPost::query()->whereRaw($prefixed)->orderBy('id')->pluck('id')->all());
        self::assertSame([-1], KeyedPost::query()->whereRaw(new ComposedExpression(KeyConditions::of($shape, KeyTarget::prefix('-', false))[0]))->pluck('id')->all());
    }

    /**
     * On PostgreSQL a uuid key equals only a uuid's canonical lower-case text,
     * the form PHP reads; any other value names no record.
     *
     * @return void
     */
    public function testAUuidKeyEqualsOnlyItsCanonicalText(): void
    {
        if (DB::connection()->getDriverName() !== 'pgsql') {
            self::markTestSkipped('Only PostgreSQL has a uuid key.');
        }

        $uuid = '0b1d2c3e-4f50-4a6b-8c7d-9e0f1a2b3c4d';

        UuidScopedDocument::query()->create(['id' => $uuid]);

        $shape = self::shape(new UuidScopedDocument);

        self::assertSame([$uuid], UuidScopedDocument::query()->whereRaw(new ComposedExpression(KeyConditions::equals($shape, $uuid)[0]))->pluck('id')->all());
        self::assertSame([QueryAuthorizer::NO_ROW, null], KeyConditions::equals($shape, \strtoupper($uuid)));
        self::assertSame([QueryAuthorizer::NO_ROW, null], KeyConditions::equals($shape, '{' . $uuid . '}'));
    }

    /**
     * A uuid key's condition is the same on every database: it equals only a
     * uuid's canonical lower-case text, inlined as it is; any other value names
     * no record.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testAUuidKeyIsComparedWithItsCanonicalTextOnEveryDatabase(): void
    {
        $uuid  = '0b1d2c3e-4f50-4a6b-8c7d-9e0f1a2b3c4d';
        $shape = self::shapeOf(ColumnKind::UUID);

        self::assertSame(["\"k\" = '{$uuid}'", null], KeyConditions::equals($shape, $uuid));
        self::assertSame([QueryAuthorizer::NO_ROW, null], KeyConditions::equals($shape, \strtoupper($uuid)));
    }

    /**
     * A key that cannot be compared at all is refused for that, before any
     * collation it has that is not exact.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testAKeysOwnRefusalComesBeforeItsCollation(): void
    {
        $shape = self::shapeOf(ColumnKind::STRING, RefusalReason::COLUMN_TYPE, false);

        self::assertSame([QueryAuthorizer::NO_ROW, RefusalReason::COLUMN_TYPE], KeyConditions::of($shape, KeyTarget::equals('a')));
        self::assertSame([QueryAuthorizer::NO_ROW, RefusalReason::COLUMN_COLLATION], KeyConditions::of(self::shapeOf(ColumnKind::STRING, null, false), KeyTarget::equals('a')));
    }

    /**
     * A key PHP may read otherwise than the database holds it is refused when
     * compared: an integer key that is not SQLite's rowid (which may hold
     * `1.5`, read as `1`), or an unsigned `BIGINT` on MySQL; and a string key
     * whose collation folds case, `NOCASE` on SQLite, `utf8mb4_unicode_ci` on
     * MySQL or a nondeterministic one on PostgreSQL. Every record and no record
     * still compile.
     *
     * @return void
     */
    public function testAKeyThatCannotBeComparedIsRefused(): void
    {
        $isLoose = DB::connection()->getDriverName() !== 'pgsql';

        // SQLite keeps a real number in an integer key that is not the rowid,
        // which PHP's integer cast would read as another key.
        if (DB::connection()->getDriverName() === 'sqlite') {
            DB::table('scoped_loose_posts')->insert(['id' => 1.5]);

            self::assertSame('real', DB::table('scoped_loose_posts')->selectRaw('typeof(id) as kind')->value('kind'));
        }

        $loose  = self::shape(new LooseKeyedPost);
        $folded = self::shape(new FoldedDocument);

        self::assertSame($isLoose ? RefusalReason::COLUMN_TYPE : null, KeyConditions::of($loose, KeyTarget::equals('1'))[1]);
        self::assertSame($isLoose ? RefusalReason::COLUMN_TYPE : null, KeyConditions::of($loose, KeyTarget::prefix('1', false))[1]);
        self::assertSame(RefusalReason::COLUMN_COLLATION, KeyConditions::of($folded, KeyTarget::equals('abc'))[1]);
        self::assertSame([QueryAuthorizer::EVERY_ROW, null], KeyConditions::of($folded, KeyTarget::all()));
        self::assertSame([QueryAuthorizer::NO_ROW, null], KeyConditions::of($loose, KeyTarget::none()));
    }

    /**
     * Return the shape of the model.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return \SineMacula\Laravel\Authorization\Query\ResourceShape
     */
    private static function shape(Model $model): ResourceShape
    {
        return ResourceShape::of($model, 'posts:view', new SchemaInspector);
    }

    /**
     * Return the documents' shape with its key `"k"` of the kind given, its own
     * refusal and whether its collation is exact.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\ColumnKind  $kind
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\RefusalReason|null  $refusal
     * @param  bool  $isExact
     * @return \SineMacula\Laravel\Authorization\Query\ResourceShape
     *
     * @throws \ReflectionException
     */
    private static function shapeOf(ColumnKind $kind, ?RefusalReason $refusal = null, bool $isExact = true): ResourceShape
    {
        $parts = ['key' => '"k"', 'keyKind' => $kind, 'isIntegerCast' => false, 'keyRefusal' => $refusal, 'isKeyCollationExact' => $isExact];

        return self::reshaped(self::shape(new ScopedDocument), $parts);
    }
}
