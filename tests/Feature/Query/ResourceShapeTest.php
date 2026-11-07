<?php

declare(strict_types = 1);

namespace Tests\Feature\Query;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException;
use SineMacula\Laravel\Authorization\Query\Enums\ColumnKind;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Query\ResourceShape;
use SineMacula\Laravel\Authorization\Query\SchemaInspector;
use SineMacula\Laravel\Authorization\Support\ResourceTenancy;
use Tests\Fixtures\QueryScoping\AbstractQueryablePost;
use Tests\Fixtures\QueryScoping\FoldedDocument;
use Tests\Fixtures\QueryScoping\LooseKeyedPost;
use Tests\Fixtures\QueryScoping\ScopedDocument;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\Fixtures\QueryScoping\ScopedTicket;
use Tests\Fixtures\QueryScoping\SealedModels;
use Tests\Fixtures\QueryScoping\TenantScopedDocument;
use Tests\TestCase;

/**
 * Feature tests for what a query scope knows of the model it scopes, and the
 * models it refuses before compiling anything.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ResourceShape::class)]
final class ResourceShapeTest extends TestCase
{
    /**
     * A tenantless post keyed by an integer it casts as one, a document keyed
     * by a string with tenant columns, and a ticket whose tenant is a team, are
     * described with their columns qualified and wrapped, and the kind of the
     * tenant id column.
     *
     * @return void
     */
    public function testTheShapeDescribesTheModel(): void
    {
        $grammar = DB::connection()->getQueryGrammar();
        $post    = self::shapeOf(new ScopedPost);

        self::assertSame(ScopedPost::class, $post->type);
        self::assertSame('scoped_posts', $post->table);
        self::assertSame($grammar->wrap('scoped_posts.id'), $post->key);
        self::assertSame(ColumnKind::INTEGER, $post->keyKind);
        self::assertTrue($post->isIntegerCast);
        self::assertTrue($post->tenancy->isTenantless());
        self::assertNull($post->typeColumn);
        self::assertNull($post->idColumn);
        self::assertNull($post->idKind);

        $document = self::shapeOf(new TenantScopedDocument);

        self::assertSame(ColumnKind::STRING, $document->keyKind);
        self::assertFalse($document->isIntegerCast);
        self::assertSame($grammar->wrap('scoped_documents.tenant_type'), $document->typeColumn);
        self::assertSame($grammar->wrap('scoped_documents.tenant_id'), $document->idColumn);
        self::assertSame(ColumnKind::STRING, $document->idKind);

        $ticket = self::shapeOf(new ScopedTicket);

        self::assertNull($ticket->typeColumn);
        self::assertSame($grammar->wrap('scoped_tickets.team_id'), $ticket->idColumn);
        self::assertSame(ColumnKind::INTEGER, $ticket->idKind);
        self::assertSame('teams', $ticket->tenancy->type);
    }

    /**
     * A model that does not declare its tenancy is refused.
     *
     * @return void
     */
    public function testAnUndeclaredModelIsRefused(): void
    {
        self::assertRefused(RefusalReason::MODEL_UNDECLARED, SealedModels::undeclared());
    }

    /**
     * A model that names its own resource is refused.
     *
     * @return void
     */
    public function testAModelNamingItsOwnResourceIsRefused(): void
    {
        self::assertRefused(RefusalReason::MODEL_CONTRACT, SealedModels::namingItsResource());
    }

    /**
     * Return each method a model may not override.
     *
     * @return iterable<string, array{string}>
     */
    public static function sealedMethods(): iterable
    {
        foreach (ResourceShape::SEALED as $method) {
            yield $method => [$method];
        }
    }

    /**
     * A model overriding a method that could change what a loaded record reads
     * as is refused, naming the method.
     *
     * @param  string  $method
     * @return void
     */
    #[DataProvider('sealedMethods')]
    public function testAModelOverridingASealedMethodIsRefused(string $method): void
    {
        self::assertSame($method, self::assertRefused(RefusalReason::MODEL_OVERRIDE, SealedModels::overriding($method)));
    }

    /**
     * A model with a `retrieved` listener, or dispatching its own event when
     * retrieved, is refused.
     *
     * @return void
     */
    public function testAModelWithARetrievedHookIsRefused(): void
    {
        $dispatching = new class extends AbstractQueryablePost {
            /** @var array<string, class-string> The events the model dispatches. */
            protected $dispatchesEvents = ['retrieved' => \stdClass::class];
        };

        self::assertRefused(RefusalReason::MODEL_LISTENER, $dispatching);

        ScopedDocument::retrieved(static function (ScopedDocument $document): void {
            $document->setAttribute('code', 'changed');
        });

        self::assertRefused(RefusalReason::MODEL_LISTENER, new ScopedDocument);
        self::assertInstanceOf(ResourceShape::class, self::shapeOf(new ScopedPost));
    }

    /**
     * A model with an accessor on its key or a tenant column is refused, naming
     * the column.
     *
     * @return void
     */
    public function testAnAccessorIsRefused(): void
    {
        self::assertSame('id', self::assertRefused(RefusalReason::COLUMN_ACCESSOR, SealedModels::withAccessor(true)));

        AbstractQueryablePost::$tenancy = ResourceTenancy::columns();

        self::assertSame('tenant_id', self::assertRefused(RefusalReason::COLUMN_ACCESSOR, SealedModels::withAccessor(false)));
    }

    /**
     * A key may be cast to its own kind alone, and a tenant column not at all.
     *
     * @return void
     */
    public function testACastIsRefusedUnlessItIsTheKeysOwnKind(): void
    {
        self::assertSame('id', self::assertRefused(RefusalReason::COLUMN_CAST, SealedModels::withCasts(['id' => 'string'])));
        self::assertTrue(self::shapeOf(SealedModels::withCasts(['id' => 'integer']))->isIntegerCast);
        self::assertTrue(self::shapeOf(SealedModels::withCasts(['id' => 'Integer']))->isIntegerCast);

        AbstractQueryablePost::$tenancy = ResourceTenancy::columns();

        self::assertSame('tenant_type', self::assertRefused(RefusalReason::COLUMN_CAST, SealedModels::withCasts(['tenant_type' => 'string'])));

        $document = (new ScopedDocument)->mergeCasts(['code' => 'string']);

        self::assertSame(ColumnKind::STRING, self::shapeOf($document)->keyKind);
        self::assertSame(ColumnKind::STRING, self::shapeOf((new ScopedDocument)->mergeCasts(['code' => 'STRING']))->keyKind);
        self::assertSame('code', self::assertRefused(RefusalReason::COLUMN_CAST, (new ScopedDocument)->mergeCasts(['code' => 'int'])));
    }

    /**
     * A tenant column the table lacks, or a tenant type column that is not a
     * string, is refused, naming the column.
     *
     * @return void
     */
    public function testATenantColumnThatCannotBeComparedIsRefused(): void
    {
        self::assertSame('owner_type', self::assertRefused(RefusalReason::COLUMN_TYPE, SealedModels::withTenantColumns('owner_type', 'owner_id')));
        self::assertSame('id', self::assertRefused(RefusalReason::COLUMN_TYPE, SealedModels::withTenantColumns('id', 'tenant_id')));
    }

    /**
     * A connection whose driver the scope does not support is refused before
     * anything is read from it.
     *
     * @return void
     */
    public function testAnUnsupportedDriverIsRefused(): void
    {
        $connection = ['driver' => 'mariadb', 'host' => '127.0.0.1', 'database' => 'none', 'username' => 'none', 'password' => ''];

        $this->config()->set('database.connections.maria', $connection);

        $model = (new ScopedPost)->setConnection('maria');

        self::assertSame('mariadb', self::assertRefused(RefusalReason::DRIVER, $model));
    }

    /**
     * A connection that is not UTF-8 is refused: on SQLite a database of
     * another encoding, on PostgreSQL a client encoding, and on MySQL a
     * character set, of another.
     *
     * @return void
     */
    public function testAConnectionThatIsNotUtf8IsRefused(): void
    {
        $driver = DB::connection()->getDriverName();
        $model  = new ScopedPost;

        if ($driver === 'sqlite') {
            $this->config()->set('database.connections.utf16', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);

            DB::connection('utf16')->statement('PRAGMA encoding = "UTF-16le"');
            DB::connection('utf16')->statement('create table scoped_posts (id integer primary key)');

            $model->setConnection('utf16');
        }

        $set     = ['pgsql' => 'SET client_encoding TO \'LATIN1\'', 'mysql' => 'SET NAMES latin1'][$driver]                           ?? null;
        $restore = ['pgsql' => 'SET client_encoding TO \'UTF8\'', 'mysql' => 'SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci'][$driver] ?? null;

        if ($set !== null) {
            DB::statement($set);
        }

        try {
            self::assertRefused(RefusalReason::CONNECTION_CHARSET, $model);
        } finally {
            if ($restore !== null) {
                DB::statement($restore);
            }
        }

        self::assertInstanceOf(ResourceShape::class, self::shapeOf(new ScopedPost));
    }

    /**
     * A morph type so long that no record's identifier could be matched is
     * refused.
     *
     * @return void
     */
    public function testAMorphTypeTooLongIsRefused(): void
    {
        Relation::morphMap([\str_repeat('m', \PHP_MAXPATHLEN - 65) => ScopedPost::class]);

        self::assertSame('the morph type is too long to identify a record', self::assertRefused(RefusalReason::MODEL_CONTRACT, new ScopedPost, 'detail'));

        Relation::morphMap([\str_repeat('m', \PHP_MAXPATHLEN - 66) => ScopedPost::class], false);

        self::assertSame(\PHP_MAXPATHLEN - 66, \strlen(self::shapeOf(new ScopedPost)->type));
    }

    /**
     * The shape says whether its key can be compared with a value: a rowid or
     * any PostgreSQL integer can, a loose integer key cannot (`column_type`); a
     * string key under a collation that folds case is told apart; and the
     * connection and the key's bare name are kept.
     *
     * @return void
     */
    public function testTheShapeTellsWhetherItsKeyCanBeCompared(): void
    {
        $inspector = new SchemaInspector;
        $post      = ResourceShape::of(new ScopedPost, 'posts:view', $inspector);
        $loose     = ResourceShape::of(new LooseKeyedPost, 'posts:view', $inspector);
        $folded    = ResourceShape::of(new FoldedDocument, 'posts:view', $inspector);
        $document  = ResourceShape::of(new ScopedDocument, 'posts:view', $inspector);

        self::assertSame([null, true, 'id'], [$post->keyRefusal, $post->isKeyCollationExact, $post->keyName]);
        self::assertSame(DB::connection()->getDriverName() === 'pgsql' ? null : RefusalReason::COLUMN_TYPE, $loose->keyRefusal);
        self::assertSame([null, false, 'code'], [$folded->keyRefusal, $folded->isKeyCollationExact, $folded->keyName]);
        self::assertTrue($document->isKeyCollationExact);
        self::assertSame(DB::connection()->getName(), $post->connection?->getName());
    }

    /**
     * A key PHP reads otherwise than its integer is not exact: on MySQL one
     * declared `ZEROFILL`, which PHP and the column's text read padded with
     * zeros, and on SQLite one declared `INTEGER PRIMARY KEY DESC`, which is
     * not the rowid and holds reals and text; so is refused once a comparison
     * of the key is material.
     *
     * @return void
     */
    public function testAPaddedOrNonRowidIntegerKeyIsNotExact(): void
    {
        $driver = DB::connection()->getDriverName();
        $create = [
            'mysql'  => 'create table scoped_padded_posts (id int(5) unsigned zerofill not null primary key, title varchar(191))',
            'sqlite' => 'create table scoped_padded_posts (id integer primary key desc, title text)',
        ][$driver] ?? null;

        if ($create === null) {
            self::markTestSkipped('Every PostgreSQL integer key is exact.');
        }

        DB::statement($create);

        $padded = new class extends AbstractQueryablePost {
            /** @var bool The key is given, never generated. */
            public $incrementing = false;

            /** @var string|null Backing table. */
            protected $table = 'scoped_padded_posts';
        };

        $shape = ResourceShape::of($padded, 'posts:view', new SchemaInspector);

        self::assertSame([ColumnKind::INTEGER, RefusalReason::COLUMN_TYPE], [$shape->keyKind, $shape->keyRefusal]);
    }

    /**
     * Forget the tenancy and the morph map a test declared.
     *
     * @return void
     */
    #[After]
    protected function forgetDeclarations(): void
    {
        AbstractQueryablePost::$tenancy = null;

        Relation::morphMap([], false);
    }

    /**
     * Return the shape of the model.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return \SineMacula\Laravel\Authorization\Query\ResourceShape
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    private static function shapeOf(Model $model): ResourceShape
    {
        return ResourceShape::of($model, 'posts:view', new SchemaInspector);
    }

    /**
     * Assert that the model is refused for the reason, at once, and return the
     * refusal's key, or its detail when asked.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\RefusalReason  $reason
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $field
     * @return string|null
     */
    private static function assertRefused(RefusalReason $reason, Model $model, string $field = 'key'): ?string
    {
        try {
            self::shapeOf($model);
        } catch (QueryScopeRefusedException $exception) {
            self::assertSame([$reason], $exception->reasons(), $exception->getMessage());
            self::assertSame('posts:view', $exception->action);
            self::assertSame($model->getMorphClass(), $exception->resourceType);

            return $field === 'key' ? $exception->refusals[0]->key : $exception->refusals[0]->detail;
        }

        self::fail("The model was not refused as {$reason->value}.");
    }

    /**
     * Return the application's configuration.
     *
     * @return \Illuminate\Contracts\Config\Repository
     */
    private function config(): ConfigRepository
    {
        $config = $this->app?->make(ConfigRepository::class);

        self::assertInstanceOf(ConfigRepository::class, $config);

        return $config;
    }
}
