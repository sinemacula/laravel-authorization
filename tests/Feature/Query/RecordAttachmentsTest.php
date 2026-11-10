<?php

declare(strict_types = 1);

namespace Tests\Feature\Query;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Database\ComposedExpression;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Query\RecordAttachments;
use SineMacula\Laravel\Authorization\Query\Refusal;
use SineMacula\Laravel\Authorization\Query\ResourceShape;
use SineMacula\Laravel\Authorization\Query\SchemaInspector;
use SineMacula\Laravel\Authorization\Query\StatementScreen;
use SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ReshapesResources;
use Tests\Concerns\ScopesQueries;
use Tests\Concerns\UsesAnAuthorizationConnection;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Fixtures\QueryScoping\LooseKeyedPost;
use Tests\Fixtures\QueryScoping\OtherConnectionPost;
use Tests\Fixtures\QueryScoping\ReplicatedPost;
use Tests\Fixtures\QueryScoping\ScopedDocument;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\TestCase;

/**
 * Feature tests for the policies attached to records a class of rows reads, and
 * the condition a row meets when one is attached to its record.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(RecordAttachments::class)]
final class RecordAttachmentsTest extends TestCase
{
    use ReshapesResources, ScopesQueries, UsesAnAuthorizationConnection;

    /**
     * With no policy attached to a record of the type, nothing is read further
     * and nothing is refused, on whatever connection.
     *
     * @return void
     */
    public function testNoAttachmentReadsNothingFurther(): void
    {
        [$attachments, $screen] = $this->reader(new ScopedPost);

        self::attachToResource(ScopedPost::class, [['effect' => 'deny', 'actions' => ['posts:view']]]);

        self::assertSame([], $attachments->inScope('posts:view', $screen, false));
        self::assertSame([], $screen->refusals());
    }

    /**
     * A policy attached to a record holds on that record alone, in the scope it
     * holds in: another record, a policy attached in another tenant, the same
     * policy attached there to another record, and a key no attachment can name
     * (`*`, one over 191 bytes) do not meet it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAttachmentHoldsOnItsRecordInItsScope(): void
    {
        foreach (['abc', 'ABC', 'abc ', '*', \str_repeat('k', 192)] as $code) {
            ScopedDocument::query()->create(['code' => $code]);
        }

        $policy = self::attachToResource([ScopedDocument::class, 'abc'], [['effect' => 'deny', 'actions' => ['posts:*']]]);

        self::attachToResource([ScopedDocument::class, 'ABC'], [['effect' => 'deny', 'actions' => ['posts:*']]]);

        $elsewhere = self::attachToResource([ScopedDocument::class, 'abc '], [['effect' => 'deny', 'actions' => ['posts:*']]]);

        $attached = ['policy_id' => $policy->getKey(), 'resource_type' => (new ScopedDocument)->getMorphClass()];

        DB::table('resource_policies')->where('policy_id', $elsewhere->getKey())->update(['tenant_type' => 'teams', 'tenant_id' => '5']);
        DB::table('resource_policies')->insert([...$attached, 'resource_id' => '*']);
        DB::table('resource_policies')->insert([...$attached, 'resource_id' => 'abc ', 'tenant_type' => 'teams', 'tenant_id' => '5']);

        // SQLite keeps a key longer than the column, which no other database
        // would store, and which `check()` never looks up.
        if (DB::connection()->getDriverName() === 'sqlite') {
            DB::table('resource_policies')->insert([...$attached, 'resource_id' => \str_repeat('k', 192)]);
        }

        [$attachments, $screen] = $this->reader(new ScopedDocument);

        $attached = $attachments->inScope('posts:view', $screen, true);
        $byPolicy = [];

        foreach ($attached as [$read, $condition, $isDenyOnly]) {
            self::assertTrue($isDenyOnly);

            $byPolicy[$read->name] = ScopedDocument::query()->whereRaw(new ComposedExpression($condition))->pluck('code')->all();
        }

        self::assertSame([], $screen->refusals());
        self::assertCount(2, $attached);
        $name = $policy->getAttribute('name');

        self::assertSame(['abc'], $byPolicy[\is_string($name) ? $name : '']);
        self::assertCount(2, TenantScope::within(new Reference('teams', '6'), null, static fn (): array => $attachments->inScope('posts:view', $screen, false)));
        self::assertCount(3, TenantScope::within(new Reference('teams', '5'), null, static fn (): array => $attachments->inScope('posts:view', $screen, false)));
    }

    /**
     * More policies attached to records than allowed are refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMorePoliciesThanAllowedAreRefused(): void
    {
        self::attachToResource([ScopedPost::class, '1'], [['effect' => 'deny', 'actions' => ['posts:*']]]);
        self::attachToResource([ScopedPost::class, '2'], [['effect' => 'deny', 'actions' => ['posts:*']]]);

        [$attachments, $screen] = $this->reader(new ScopedPost, 1);

        self::assertSame([], $attachments->inScope('posts:view', $screen, false));
        self::assertSame([[RefusalReason::TOO_MANY_ATTACHMENTS, 'resource_id']], self::refused($screen));

        [$enough, $screen] = $this->reader(new ScopedPost, 2);

        self::assertCount(2, $enough->inScope('posts:view', $screen, false));
    }

    /**
     * A document attached to a record that cannot be read is refused.
     *
     * @return void
     */
    public function testAnUnreadableDocumentIsRefused(): void
    {
        DB::table('resource_policies')->insert(['policy_id' => self::unreadablePolicy(), 'resource_type' => (new ScopedPost)->getMorphClass(), 'resource_id' => '1']);

        [$attachments, $screen] = $this->reader(new ScopedPost);

        self::assertSame([], $attachments->inScope('posts:view', $screen, false));
        self::assertSame([[RefusalReason::INVALID_POLICY, null]], self::refused($screen));
    }

    /**
     * Attachments kept on another connection than the model's are refused,
     * since no condition of the model's query can read them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttachmentsOnAnotherConnectionAreRefused(): void
    {
        $default = DB::getDefaultConnection();

        $this->app?->make(ConfigRepository::class)->set('database.connections.' . OtherConnectionPost::CONNECTION, config("database.connections.{$default}"));

        if (DB::connection(OtherConnectionPost::CONNECTION)->getDriverName() === 'sqlite') {
            Schema::connection(OtherConnectionPost::CONNECTION)->create('scoped_posts', static function (Blueprint $schema): void {
                $schema->increments('id');
            });
        }

        self::attachToResource([OtherConnectionPost::class, '1'], [['effect' => 'deny', 'actions' => ['posts:*']]]);

        [$attachments, $screen] = $this->reader(new OtherConnectionPost);

        self::assertSame([], $attachments->inScope('posts:view', $screen, false));
        self::assertSame([[RefusalReason::ATTACHMENT_CONNECTION, 'resource_id']], self::refused($screen));
    }

    /**
     * An attachment's key is compared under its column's own collation: one
     * that folds case is refused on SQLite and PostgreSQL, whose comparison
     * here is byte for byte, and followed on MySQL, so a record's attachment
     * holds on every key `check()` finds it attached to.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAttachmentsKeyIsComparedUnderItsColumnsCollation(): void
    {
        $this->app?->make(ConfigRepository::class)->set('authorization.tables.resource_policies', 'scoped_folded_resource_policies');

        $user    = StubIdentity::create(['id' => 'u1']);
        $manager = $this->resolveRequest($user);
        $policy  = self::storedPolicy('folded', [['effect' => 'allow', 'actions' => ['posts:view'], 'principals' => [$user->getMorphClass() . ':u1']]]);

        DB::table('scoped_folded_resource_policies')->insert(['policy_id' => $policy->getKey(), 'resource_type' => (new ScopedDocument)->getMorphClass(), 'resource_id' => 'ABC']);

        foreach (['abc', 'ABC', 'abd'] as $code) {
            ScopedDocument::query()->create(['code' => $code]);
        }

        [$attachments, $screen] = $this->reader(new ScopedDocument);

        $attached = $attachments->inScope('posts:view', $screen, false);

        if (DB::connection()->getDriverName() !== 'mysql') {
            self::assertSame([], $attached);
            self::assertSame([[RefusalReason::ATTACHMENT_COLLATION, 'resource_id']], self::refused($screen));

            return;
        }

        $isAllowed = static fn (string $code): bool => $manager->can('posts:view', ScopedDocument::query()->where('code', $code)->first());
        $checked   = \array_values(\array_filter(['abc', 'ABC', 'abd'], $isAllowed));

        self::assertSame(['abc', 'ABC'], $checked);
        self::assertSame($checked, ScopedDocument::query()->whereRaw(new ComposedExpression($attached[0][1]))->orderBy('row_id')->pluck('code')->all());
    }

    /**
     * An integer key PHP may read otherwise than the database holds it is
     * refused once a policy is attached to a record of the type, on SQLite and
     * MySQL; PostgreSQL's is exact.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALooseIntegerKeyIsRefusedOnceAttachedTo(): void
    {
        self::attachToResource([LooseKeyedPost::class, '1'], [['effect' => 'deny', 'actions' => ['posts:*']]]);

        [$attachments, $screen] = $this->reader(new LooseKeyedPost);

        $attached = $attachments->inScope('posts:view', $screen, false);

        self::assertSame(DB::connection()->getDriverName() === 'pgsql' ? [] : [[RefusalReason::COLUMN_TYPE, 'id']], self::refused($screen));
        self::assertCount(DB::connection()->getDriverName() === 'pgsql' ? 1 : 0, $attached);
    }

    /**
     * A policy attached to one record for an application and to another for
     * every application holds on the first only in that application, and on the
     * second in every application and with none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAttachmentHoldsOnlyInItsApplication(): void
    {
        $keys = [];

        foreach (['admin-only', 'everywhere', 'neither'] as $title) {
            $keys[] = (string) ScopedPost::query()->create(['title' => $title])->getKey(); // @phpstan-ignore cast.string
        }

        $policy = self::attachToResource([ScopedPost::class, $keys[1]], [['effect' => 'deny', 'actions' => ['posts:*']]]);

        DB::table('resource_policies')->insert([
            'policy_id'     => $policy->getKey(),
            'resource_type' => (new ScopedPost)->getMorphClass(),
            'resource_id'   => $keys[0],
            'application'   => 'admin',
        ]);

        [$attachments, $screen] = $this->reader(new ScopedPost);

        $kept = static fn (?string $application): array => TenantScope::within(null, $application, static function () use ($attachments, $screen): array {
            $attached = $attachments->inScope('posts:view', $screen, false);

            self::assertCount(1, $attached);

            return ScopedPost::query()->whereRaw(new ComposedExpression($attached[0][1]))->orderBy('id')->pluck('title')->all();
        });

        self::assertSame(['everywhere'], $kept('web'));
        self::assertSame(['admin-only', 'everywhere'], $kept('admin'));
        self::assertSame(['everywhere'], $kept(null));
        self::assertSame([], $screen->refusals());
    }

    /**
     * Tenants and applications holding question marks, doubled ones, quotes,
     * backslashes and, where the database stores one, a NUL byte are inlined
     * exactly: a policy attached in such a tenant holds on its record there and
     * nowhere else, as `check()` finds it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantOrApplicationOfAnyBytesIsInlinedExactly(): void
    {
        $isPostgres = DB::connection()->getDriverName() === 'pgsql';
        $tenants    = ['a??b', 'a?b', 'a\'b', 'a\\', 'a\\\'b', '??', ...($isPostgres ? [] : ["a\0b"])];

        foreach ($tenants as $index => $tenant) {
            $post = ScopedPost::query()->create(['title' => \bin2hex($tenant)]);

            $policy = self::storedPolicy('escaped-' . $index, [['effect' => 'deny', 'actions' => ['posts:*']]]);

            DB::table('resource_policies')->insert([
                'policy_id'     => $policy->getKey(),
                'resource_type' => (new ScopedPost)->getMorphClass(),
                'resource_id'   => (string) $post->getKey(), // @phpstan-ignore cast.string
                'tenant_type'   => 'teams',
                'tenant_id'     => $tenant,
                'application'   => $tenant,
            ]);
        }

        [$attachments, $screen] = $this->reader(new ScopedPost);

        foreach ($tenants as $tenant) {
            $kept = TenantScope::within(new Reference('teams', $tenant), $tenant, static function () use ($attachments, $screen): array {
                $titles = [];

                foreach ($attachments->inScope('posts:view', $screen, false) as [, $condition]) {
                    \array_push($titles, ...ScopedPost::query()->whereRaw(new ComposedExpression($condition))->pluck('title')->all());
                }

                return $titles;
            });

            self::assertSame([\bin2hex($tenant)], $kept, \bin2hex($tenant));
        }

        self::assertSame([], $screen->refusals());
    }

    /**
     * On PostgreSQL, which no text holds a NUL byte in, a tenant holding one
     * cannot be inlined, so the attachments are refused rather than compared
     * with nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantThatCannotBeInlinedIsRefused(): void
    {
        if (DB::connection()->getDriverName() !== 'pgsql') {
            self::markTestSkipped('Only PostgreSQL cannot hold a NUL byte in text.');
        }

        self::attachToResource([ScopedPost::class, '1'], [['effect' => 'deny', 'actions' => ['posts:*']]]);

        [$attachments, $screen] = $this->reader(new ScopedPost);

        TenantScope::within(new Reference('teams', "a\0b"), null, static fn (): array => $attachments->inScope('posts:view', $screen, false));

        self::assertSame([[RefusalReason::INLINE_VALUE, 'resource_id']], self::refused($screen));
    }

    /**
     * The attachments are compiled whatever read connection the model's has:
     * where the query carrying them runs is the scope's to settle.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function testAttachmentsAreCompiledWhateverTheReadConnection(): void
    {
        $this->useAnAuthorizationConnection();

        Schema::connection(ReplicatedPost::CONNECTION)->create('scoped_posts', static function (Blueprint $schema): void {
            $schema->increments('id');
            $schema->string('tenant_type')->nullable();
            $schema->string('tenant_id')->nullable();
        });

        self::attachToResource([ReplicatedPost::class, '1'], [['effect' => 'deny', 'actions' => ['posts:*']]]);

        /** @var \Illuminate\Database\Connection $connection */
        $connection = DB::connection(ReplicatedPost::CONNECTION);

        [$attachments, $screen] = $this->reader(new ReplicatedPost);
        [, $kept]               = $this->reader(new ReplicatedPost);

        // Read once without a read connection, so what is read of the tables is
        // known before one is set.
        self::assertCount(1, $attachments->inScope('posts:view', $screen, false));

        $connection->setReadPdo(static fn (): never => throw new \LogicException('The read connection was used.'));

        self::assertCount(1, $attachments->inScope('posts:view', $kept, false));
        self::assertSame([], $kept->refusals());

        $connection->setReadPdo(null);
    }

    /**
     * The policies attached in one scope are read once however many classes are
     * decided there, and afresh in another scope.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAttachmentsOfAScopeAreReadOnce(): void
    {
        self::attachToResource([ScopedPost::class, '1'], [['effect' => 'deny', 'actions' => ['posts:*']]]);

        [$attachments, $screen] = $this->reader(new ScopedPost);

        /** @var \ArrayObject<int, string> $reads */
        $reads = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($reads): void {
            if (!\str_contains($query->sql, 'policy_id')) {
                return;
            }

            $reads[] = $query->sql;
        });

        $attachments->inScope('posts:view', $screen, false);
        $attachments->inScope('posts:view', $screen, true);

        self::assertCount(1, $reads);

        TenantScope::within(new Reference('teams', '5'), null, static fn (): array => $attachments->inScope('posts:view', $screen, false));

        self::assertCount(2, $reads);

        DB::getEventDispatcher()?->forget(QueryExecuted::class);
    }

    /**
     * The policies read in one application are not reused in another, where a
     * policy attached only there holds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePoliciesOfOneApplicationAreNotReusedInAnother(): void
    {
        $policy = self::attachToResource([ScopedPost::class, '1'], [['effect' => 'deny', 'actions' => ['posts:*']]]);

        DB::table('resource_policies')->where('policy_id', $policy->getKey())->update(['application' => 'admin']);

        [$attachments, $screen] = $this->reader(new ScopedPost);

        self::assertSame([], TenantScope::within(null, 'web', static fn (): array => $attachments->inScope('posts:view', $screen, false)));
        self::assertCount(1, TenantScope::within(null, 'admin', static fn (): array => $attachments->inScope('posts:view', $screen, false)));
    }

    /**
     * A key whose text holds a question mark that is no placeholder cannot be
     * inlined, so the attachments are refused, on every database; a model whose
     * connection is not known is refused as kept on another connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAKeyThatCannotBeInlinedOrAnUnknownConnectionIsRefused(): void
    {
        self::attachToResource([ScopedPost::class, '1'], [['effect' => 'deny', 'actions' => ['posts:*']]]);

        $shape  = ResourceShape::of(new ScopedPost, 'posts:view', new SchemaInspector);
        $marked = $this->readerOf(self::reshaped($shape, ['key' => '"k?"']));

        self::assertCount(1, $marked[0]->inScope('posts:view', $marked[1], false));
        self::assertSame([[RefusalReason::INLINE_VALUE, 'resource_id']], self::refused($marked[1]));

        $unknown = $this->readerOf(self::reshaped($shape, ['connection' => null]));

        self::assertSame([], $unknown[0]->inScope('posts:view', $unknown[1], false));
        self::assertSame([[RefusalReason::ATTACHMENT_CONNECTION, 'resource_id']], self::refused($unknown[1]));
    }

    /**
     * Return a reader of the model's record attachments, at most the limit of
     * them, and a screen of `posts:view` to keep its refusals.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  int  $limit
     * @return array{\SineMacula\Laravel\Authorization\Query\RecordAttachments, \SineMacula\Laravel\Authorization\Query\StatementScreen}
     */
    private function reader(Model $model, int $limit = 64): array
    {
        return $this->readerOf(ResourceShape::of($model, 'posts:view', new SchemaInspector), $limit);
    }

    /**
     * Return a reader of the shape's record attachments, at most the limit of
     * them, and a screen of `posts:view` to keep its refusals.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ResourceShape  $shape
     * @param  int  $limit
     * @return array{\SineMacula\Laravel\Authorization\Query\RecordAttachments, \SineMacula\Laravel\Authorization\Query\StatementScreen}
     */
    private function readerOf(ResourceShape $shape, int $limit = 64): array
    {
        $user = StubIdentity::query()->firstOrCreate(['id' => 'reader']);

        return [new RecordAttachments(new ResourcePolicyResolver, $shape, new SchemaInspector, $limit), new StatementScreen('posts:view', $shape, new Subject($user, $user))];
    }

    /**
     * Return each refusal the screen kept, as its reason and key.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\StatementScreen  $screen
     * @return list<array{\SineMacula\Laravel\Authorization\Query\Enums\RefusalReason, string|null}>
     */
    private static function refused(StatementScreen $screen): array
    {
        return \array_map(static fn (Refusal $refusal): array => [$refusal->reason, $refusal->key], $screen->refusals());
    }
}
