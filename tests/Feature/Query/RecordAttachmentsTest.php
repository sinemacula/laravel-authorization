<?php

declare(strict_types = 1);

namespace Tests\Feature\Query;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
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
use Tests\Concerns\ScopesQueries;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Fixtures\QueryScoping\LooseKeyedPost;
use Tests\Fixtures\QueryScoping\OtherConnectionPost;
use Tests\Fixtures\QueryScoping\ScopedDocument;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\TestCase;

/**
 * Feature tests for the policies attached to records a class of rows reads, and
 * the condition a row meets when one is attached to its record (C7).
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
    use ScopesQueries;

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
     * holds in: another record, a policy attached in another tenant and a key
     * no attachment can name (`*`, one over 191 bytes) do not meet it.
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

        DB::table('resource_policies')->where('policy_id', $elsewhere->getKey())->update(['tenant_type' => 'teams', 'tenant_id' => '5']);
        DB::table('resource_policies')->insert(['policy_id' => $policy->getKey(), 'resource_type' => (new ScopedDocument)->getMorphClass(), 'resource_id' => '*']);

        [$attachments, $screen] = $this->reader(new ScopedDocument);

        $attached = $attachments->inScope('posts:view', $screen, true);
        $byPolicy = [];

        foreach ($attached as [$read, $condition, $isDenyOnly]) {
            self::assertTrue($isDenyOnly);

            $byPolicy[$read->name] = ScopedDocument::query()->whereRaw($condition)->pluck('code')->all();
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
        self::assertSame($checked, ScopedDocument::query()->whereRaw($attached[0][1])->orderBy('row_id')->pluck('code')->all());
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
     * Return a reader of the model's record attachments, at most the limit of
     * them, and a screen of `posts:view` to keep its refusals.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  int  $limit
     * @return array{\SineMacula\Laravel\Authorization\Query\RecordAttachments, \SineMacula\Laravel\Authorization\Query\StatementScreen}
     */
    private function reader(Model $model, int $limit = 64): array
    {
        $user      = StubIdentity::query()->firstOrCreate(['id' => 'reader']);
        $inspector = new SchemaInspector;
        $shape     = ResourceShape::of($model, 'posts:view', $inspector);

        return [new RecordAttachments(new ResourcePolicyResolver, $shape, $inspector, $limit), new StatementScreen('posts:view', $shape, new Subject($user, $user))];
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
