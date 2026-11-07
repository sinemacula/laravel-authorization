<?php

declare(strict_types = 1);

namespace Tests\Feature\Query;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\DecisionPipeline;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Query\Dialects\SqliteDialect;
use SineMacula\Laravel\Authorization\Query\Enums\ColumnKind;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Query\QueryAuthorizer;
use SineMacula\Laravel\Authorization\Query\Refusal;
use SineMacula\Laravel\Authorization\Query\SchemaInspector;
use SineMacula\Laravel\Authorization\Resolvers\DefaultPolicyResolver;
use SineMacula\Laravel\Authorization\Resolvers\GuardrailResolver;
use SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ScopesQueries;
use Tests\Feature\Stubs\FixedResourceTenantResolver;
use Tests\Feature\Stubs\PlanContextSource;
use Tests\Feature\Stubs\RecordingSubjectAttributes;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubRequirementChecker;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\SuspendableIdentity;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\Fixtures\QueryScoping\NumberedTenantPost;
use Tests\Fixtures\QueryScoping\ScopedDocument;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\Fixtures\QueryScoping\ScopedTicket;
use Tests\Fixtures\QueryScoping\TenantScopedPost;
use Tests\TestCase;

/**
 * Feature tests for the compiler of the condition `whereAuthorized()` adds: the
 * rows of each class it keeps, decided as `check()` decides them, and every
 * refusal it raises.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(QueryAuthorizer::class)]
final class QueryAuthorizerTest extends TestCase
{
    use ScopesQueries;

    /**
     * A guest, and a subject that is inactive, keep no row, without reading a
     * grant.
     *
     * @return void
     */
    public function testAGuestOrAnInactiveSubjectKeepsNoRow(): void
    {
        $inactive = SuspendableIdentity::create(['id' => 'inactive']);

        $inactive->suspended = true;

        self::assertSame(QueryAuthorizer::NO_ROW, self::authorizer()->compile(null, new ScopedPost, 'posts:view'));
        self::assertSame(QueryAuthorizer::NO_ROW, self::authorizer()->compile(new Subject($inactive, $inactive), new ScopedPost, 'posts:view'));
    }

    /**
     * A tenantless model keeps every row whose key identifies a record when the
     * subject holds the action, and none when it does not.
     *
     * @return void
     */
    public function testATenantlessModelKeepsEveryIdentifiedRowWhenAllowed(): void
    {
        $user    = StubIdentity::create(['id' => 'u1']);
        $subject = new Subject($user, $user);
        $key     = DB::connection()->getQueryGrammar()->wrap('scoped_posts.id');

        self::assertSame(QueryAuthorizer::NO_ROW, self::authorizer()->compile($subject, new ScopedPost, 'posts:view'));

        $user->givePermission(Permission::create(['name' => 'posts:view']));

        self::assertSame("{$key} IS NOT NULL", self::authorizer()->compile($subject, new ScopedPost, 'posts:view'));
    }

    /**
     * A tenant-bearing model keeps the rows of no tenant, decided in the
     * request's scope, and the rows of the active tenant exactly, decided in
     * its own; rows of any other tenant, or partly of the active one, are left
     * out, as `check()` denies them.
     *
     * @return void
     */
    public function testATenantBearingModelKeepsTheRowsOfNoTenantAndOfTheActiveOne(): void
    {
        [$t1, $t2] = [StubTenant::query()->create(['id' => 't1']), StubTenant::query()->create(['id' => 't2'])];
        $type      = $t1->getMorphClass();
        $user      = StubIdentity::create(['id' => 'u1']);
        $manager   = $this->resolveRequest($user, $t1);

        $user->givePermission(Permission::create(['name' => 'posts:view']), null, $t1);

        $rows = [
            'none'    => [null, null],
            'partial' => [$type, null],
            'active'  => [$type, 't1'],
            'other'   => [$type, 't2'],
            'case'    => [$type, 'T1'],
            'type'    => ['other', 't1'],
        ];

        $kept = [];

        foreach ($rows as $name => [$tenantType, $tenantId]) {
            $post = TenantScopedPost::query()->create(['title' => $name, 'tenant_type' => $tenantType, 'tenant_id' => $tenantId]);

            if (!$manager->can('posts:view', $post)) {
                continue;
            }

            $kept[] = $name;
        }

        $condition = self::authorizer()->compile($manager->currentSubject(), new TenantScopedPost, 'posts:view');

        self::assertSame(['none', 'partial', 'active'], $kept);
        self::assertSame($kept, TenantScopedPost::query()->whereRaw($condition)->orderBy('id')->pluck('title')->all());
        $elsewhere = self::authorizer()->compile($this->resolveRequest($user, $t2)->currentSubject(), new TenantScopedPost, 'posts:view');

        self::assertSame([], TenantScopedPost::query()->whereRaw($elsewhere)->pluck('title')->all());
    }

    /**
     * With no tenant active, only the rows of no tenant can be kept.
     *
     * @return void
     */
    public function testWithNoActiveTenantOnlyRowsOfNoTenantAreKept(): void
    {
        $tenant = StubTenant::query()->create(['id' => 't1']);
        $user   = StubIdentity::create(['id' => 'u1']);

        $user->attachPolicy(self::storedPolicy('allow', [['effect' => 'allow', 'actions' => ['posts:view']]]));

        TenantScopedPost::query()->create(['title' => 'none']);
        TenantScopedPost::query()->create(['title' => 'owned', 'tenant_type' => $tenant->getMorphClass(), 'tenant_id' => 't1']);

        $condition = self::authorizer()->compile($this->resolveRequest($user)->currentSubject(), new TenantScopedPost, 'posts:view');

        self::assertSame(['none'], TenantScopedPost::query()->whereRaw($condition)->pluck('title')->all());
    }

    /**
     * A model whose every tenant is of one type compares the key alone, as
     * text, so the active tenant of another type keeps none of its tenants'
     * rows, and a key PHP would read otherwise, such as `05`, keeps none.
     *
     * @return void
     */
    public function testAFixedTenantTypeComparesTheKeyAlone(): void
    {
        $user = StubIdentity::create(['id' => 'u1']);

        $user->attachPolicy(self::storedPolicy('allow', [['effect' => 'allow', 'actions' => ['posts:view']]]));

        foreach ([null, 5, 7] as $team) {
            ScopedTicket::query()->create(['team_id' => $team, 'title' => 'team ' . ($team ?? 'none')]);
        }

        $kept = function (object $tenant) use ($user): array {
            $condition = self::authorizer()->compile($this->resolveRequest($user, $tenant)->currentSubject(), new ScopedTicket, 'posts:view');

            return ScopedTicket::query()->whereRaw($condition)->orderBy('id')->pluck('title')->all();
        };

        self::assertSame(['team none', 'team 5'], $kept(new Reference('teams', '5')));
        self::assertSame(['team none'], $kept(new Reference('teams', '05')));
        self::assertSame(['team none'], $kept(StubTenant::query()->create(['id' => '5'])));

        // The rows of another tenant type compile to no row, which drops out.
        $condition = self::authorizer()->compile($this->resolveRequest($user, StubTenant::query()->findOrFail('5'))->currentSubject(), new ScopedTicket, 'posts:view');

        self::assertStringNotContainsString(QueryAuthorizer::NO_ROW, $condition);
    }

    /**
     * A row of no tenant whose tenant id column holds a real number, which
     * SQLite alone keeps in an integer column and on which `check()` throws, is
     * left out, whichever tenant column is null.
     *
     * @return void
     */
    public function testARowOfNoTenantCheckCannotReadIsLeftOut(): void
    {
        if (DB::connection()->getDriverName() !== 'sqlite') {
            self::markTestSkipped('Only SQLite keeps a real number in an integer column.');
        }

        $user = StubIdentity::create(['id' => 'u1']);

        $user->attachPolicy(self::storedPolicy('allow', [['effect' => 'allow', 'actions' => ['posts:view']]]));

        foreach (['none' => [null, null], 'type' => ['teams', null], 'half' => [null, 1.5], 'huge' => [null, 1e20], 'typed' => ['teams', 2.5]] as $title => [$type, $id]) {
            NumberedTenantPost::query()->create(['title' => $title, 'tenant_type' => $type, 'tenant_id' => $id]);
        }

        $manager   = $this->resolveRequest($user);
        $condition = self::authorizer()->compile($manager->currentSubject(), new NumberedTenantPost, 'posts:view');
        $allowed   = [];

        // A throw counts as a deny.
        foreach (NumberedTenantPost::query()->orderBy('id')->get() as $post) {
            $allowed = rescue(static fn (): bool => $manager->can('posts:view', $post), false, false) === true ? [...$allowed, $post->getAttribute('title')] : $allowed;
        }

        $kinds = DB::select('select typeof(tenant_id) as kind from scoped_numbered_posts where title in (\'half\', \'huge\', \'typed\')');

        self::assertSame(['real', 'real', 'real'], \array_column($kinds, 'kind'));
        self::assertSame(['none', 'type'], $allowed);
        self::assertSame($allowed, NumberedTenantPost::query()->whereRaw($condition)->orderBy('id')->pluck('title')->all());
    }

    /**
     * A row of the active tenant is matched by comparing the bare tenant
     * columns first, which an index on them serves, then byte for byte.
     *
     * @return void
     */
    public function testARowOfTheActiveTenantIsMatchedThroughAnIndex(): void
    {
        $user    = StubIdentity::create(['id' => 'u1']);
        $tenant  = new Reference('teams', '5');
        $model   = new NumberedTenantPost;
        $grammar = DB::connection()->getQueryGrammar();

        $user->attachPolicy(self::storedPolicy('allow', [['effect' => 'allow', 'actions' => ['posts:view']]]));

        foreach ([['teams', 5], ['teams', 7], ['other', 5], [null, null]] as $index => [$type, $id]) {
            NumberedTenantPost::query()->create(['title' => 'p' . $index, 'tenant_type' => $type, 'tenant_id' => $id]);
        }

        $condition = self::authorizer()->compile($this->resolveRequest($user, $tenant)->currentSubject(), $model, 'posts:view');
        $shape     = DB::connection()->getDriverName();

        foreach (['tenant_type' => 'teams', 'tenant_id' => '5'] as $column => $value) {
            $wrapped = $grammar->wrap($model->qualifyColumn($column));

            self::assertStringContainsString($wrapped . ($shape === 'sqlite' ? ' IN (' : ' = '), $condition);
        }

        self::assertSame(['p0', 'p3'], NumberedTenantPost::query()->whereRaw($condition)->orderBy('id')->pluck('title')->all());

        if ($shape !== 'sqlite') {
            return;
        }

        $dialect = new SqliteDialect;
        $match   = \implode(' AND ', [
            $dialect->equalsIndexed('tenant_type', ColumnKind::STRING, 'teams'),
            $dialect->equalsIndexed('tenant_id', ColumnKind::INTEGER, '5'),
            $dialect->equalsBytes('tenant_type', 'teams'),
            $dialect->equalsBytes('tenant_id', '5'),
        ]);

        $plan = \array_column(DB::select('EXPLAIN QUERY PLAN select * from scoped_numbered_posts where ' . $match), 'detail');

        self::assertMatchesRegularExpression('/USING (COVERING )?INDEX/', \implode("\n", $plan));
    }

    /**
     * When a statement the check weighs matches a pattern against each row's
     * identifier, a row whose identifier is too long for `fnmatch()` is left
     * out, as `check()` throws on it; with no pattern to match, it is kept.
     *
     * @return void
     */
    public function testARowTooLongForAPatternIsLeftOutWhenAPatternIsMatched(): void
    {
        $user    = StubIdentity::create(['id' => 'u1']);
        $subject = new Subject($user, $user);
        $type    = (new ScopedDocument)->getMorphClass();
        $limit   = \PHP_MAXPATHLEN - \strlen($type) - 1;

        $user->givePermission(Permission::create(['name' => 'posts:view']));

        foreach (['short' => 'abc', 'longest' => \str_repeat('k', $limit - 1), 'too long' => \str_repeat('k', $limit)] as $title => $code) {
            ScopedDocument::query()->create(['title' => $title, 'code' => $code]);
        }

        $kept = static function () use ($subject): array {
            $condition = self::authorizer()->compile($subject, new ScopedDocument, 'posts:view');

            return ScopedDocument::query()->whereRaw($condition)->orderBy('row_id')->pluck('title')->all();
        };

        self::assertSame(['short', 'longest', 'too long'], $kept());

        $user->attachPolicy(self::storedPolicy('patterned', [['effect' => 'deny', 'actions' => ['posts:view'], 'not_resources' => ['*']]]));

        self::assertSame(['short', 'longest'], $kept());
    }

    /**
     * A morph type holding a NUL byte names no record, so no row is kept.
     *
     * @return void
     */
    public function testAMorphTypeWithANulByteKeepsNoRow(): void
    {
        $user = StubIdentity::create(['id' => 'u1']);

        $user->givePermission(Permission::create(['name' => 'posts:view']));

        Relation::morphMap(["po\0sts" => ScopedPost::class]);

        self::assertSame(QueryAuthorizer::NO_ROW, self::authorizer()->compile(new Subject($user, $user), new ScopedPost, 'posts:view'));
    }

    /**
     * A resource tenant resolver other than the declared one is refused.
     *
     * @return void
     */
    public function testAnUndeclaredTenantResolverIsRefused(): void
    {
        $this->app?->instance(ResourceTenantResolver::class, new FixedResourceTenantResolver);

        $refusal = self::refusalOf(static fn (): string => self::authorizer()->compile(null, new ScopedPost, 'posts:view'));

        self::assertSame([RefusalReason::TENANT_RESOLVER], $refusal->reasons());
        self::assertSame(FixedResourceTenantResolver::class, $refusal->refusals[0]->key);
    }

    /**
     * A subject holding the action platform-wide is admitted to the rows of
     * every tenant, decided at platform scope, as `check()` admits them; a
     * tenant's guardrail still caps the rows of that tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlatformWideGrantAdmitsTheRowsOfEveryTenant(): void
    {
        $t1      = StubTenant::query()->create(['id' => 't1']);
        $type    = $t1->getMorphClass();
        $user    = StubIdentity::create(['id' => 'u1']);
        $manager = $this->resolveRequest($user);

        StubTenant::query()->create(['id' => 't2']);

        $user->givePermission(Permission::create(['name' => 'posts:view']));

        foreach (['none' => [null, null], 't1' => [$type, 't1'], 't2' => [$type, 't2']] as $title => [$tenantType, $tenantId]) {
            TenantScopedPost::query()->create(['title' => $title, 'tenant_type' => $tenantType, 'tenant_id' => $tenantId]);
        }

        $condition = self::authorizer()->compile($manager->currentSubject(), new TenantScopedPost, 'posts:view');

        self::assertSame(['none', 't1', 't2'], TenantScopedPost::query()->whereRaw($condition)->orderBy('id')->pluck('title')->all());
        self::assertSame(['none', 't1', 't2'], self::allowed($manager));
    }

    /**
     * A policy attached to a record is weighed on that record alone: its deny
     * applies to everyone, its allow to the subjects it names, as `check()`
     * weighs it; an override, which reads no attachment, ignores it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARecordAttachmentIsWeighedOnItsRecord(): void
    {
        $user    = StubIdentity::create(['id' => 'u1']);
        $manager = $this->resolveRequest($user);
        $subject = $manager->currentSubject();

        foreach ([3, 4, 5] as $id) {
            ScopedPost::query()->create(['id' => $id, 'title' => 'post']);
        }

        self::attachToResource([ScopedPost::class, '4'], [['effect' => 'deny', 'actions' => ['posts:*']]]);
        self::attachToResource([ScopedPost::class, '5'], [['effect' => 'allow', 'actions' => ['posts:view'], 'principals' => [$user->getMorphClass() . ':u1']]]);

        $condition = self::authorizer()->compile($subject, new ScopedPost, 'posts:view');
        $checked   = \array_values(\array_filter([3, 4, 5], static fn (int $id): bool => $manager->can('posts:view', ScopedPost::query()->find($id))));

        self::assertSame([5], $checked);
        self::assertSame($checked, ScopedPost::query()->whereRaw($condition)->pluck('id')->all());

        $user->givePermission(Permission::create(['name' => 'posts:view']));

        self::assertSame([3, 5], ScopedPost::query()->whereRaw(self::authorizer()->compile($subject, new ScopedPost, 'posts:view'))->orderBy('id')->pluck('id')->all());
        $overridden = self::authorizer(self::pipeline()->withPolicies([]))->compile($subject, new ScopedPost, 'posts:view');

        self::assertSame([3, 4, 5], ScopedPost::query()->whereRaw($overridden)->orderBy('id')->pluck('id')->all());
    }

    /**
     * An allow attached to a record grants only the subjects it names: one
     * naming another subject grants nothing on its record, one naming the
     * subject grants its own, as `check()` decides each.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAttachedAllowGrantsOnlyThePrincipalsItNames(): void
    {
        $user    = StubIdentity::create(['id' => 'u1']);
        $manager = $this->resolveRequest($user);

        foreach ([4, 5] as $id) {
            ScopedPost::query()->create(['id' => $id, 'title' => 'post']);
        }

        self::attachToResource([ScopedPost::class, '4'], [['effect' => 'allow', 'actions' => ['posts:view'], 'principals' => [$user->getMorphClass() . ':u2']]]);
        self::attachToResource([ScopedPost::class, '5'], [['effect' => 'allow', 'actions' => ['posts:view'], 'principals' => [$user->getMorphClass() . ':u1']]]);

        $condition = self::authorizer()->compile($manager->currentSubject(), new ScopedPost, 'posts:view');
        $checked   = \array_values(\array_filter([4, 5], static fn (int $id): bool => $manager->can('posts:view', ScopedPost::query()->find($id))));

        self::assertSame([5], $checked);
        self::assertSame($checked, ScopedPost::query()->whereRaw($condition)->orderBy('id')->pluck('id')->all());
    }

    /**
     * A tenant, and an application, holding question marks, a doubled one, a
     * quote, a backslash or, where the database stores one, a NUL byte decide
     * exactly the rows `check()` allows, a deny attached to a record there
     * included.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantOfAnyBytesDecidesAsCheckDoes(): void
    {
        $user = StubIdentity::create(['id' => 'u1']);
        $ids  = ['a??b', 'a?b', 'a\'b', 'a\\', 'a\\\'b', ...(DB::connection()->getDriverName() === 'pgsql' ? [] : ["a\0b"])];

        foreach ($ids as $index => $id) {
            $tenant      = StubTenant::query()->create(['id' => $id]);
            $application = 'app?' . $index . '??';
            $deny        = self::storedPolicy('deny-' . $index, [['effect' => 'deny', 'actions' => ['posts:view']]]);

            $user->givePermission(Permission::firstOrCreate(['name' => 'posts:view']), null, $tenant, true, $application);

            $denied = TenantScopedPost::query()->create(['title' => "denied-{$index}", 'tenant_type' => $tenant->getMorphClass(), 'tenant_id' => $id]);

            TenantScopedPost::query()->create(['title' => "kept-{$index}", 'tenant_type' => $tenant->getMorphClass(), 'tenant_id' => $id]);
            app(ResourcePolicyService::class)->attach($deny, [TenantScopedPost::class, (string) $denied->getKey()], $tenant, true, $application); // @phpstan-ignore cast.string

            $manager = $this->resolveRequest($user, $tenant, $application);
            $checked = [];

            foreach (TenantScopedPost::query()->orderBy('id')->get() as $post) {
                if (!$manager->can('posts:view', $post)) {
                    continue;
                }

                $checked[] = $post->getAttribute('title');
            }

            $condition = self::authorizer()->compile($manager->currentSubject(), new TenantScopedPost, 'posts:view');

            self::assertSame(["kept-{$index}"], $checked, \bin2hex($id));
            self::assertSame($checked, TenantScopedPost::query()->whereRaw($condition)->orderBy('id')->pluck('title')->all(), \bin2hex($id));
        }
    }

    /**
     * A document that cannot be read is refused, never compiled to no rows: one
     * the subject holds, and one attached to a record of the type.
     *
     * @return void
     */
    public function testAnUnreadableDocumentIsRefused(): void
    {
        $user    = StubIdentity::create(['id' => 'u1']);
        $subject = new Subject($user, $user);
        $id      = self::unreadablePolicy();

        DB::table('resource_policies')->insert(['policy_id' => $id, 'resource_type' => (new ScopedDocument)->getMorphClass(), 'resource_id' => 'abc']);

        $refusal = self::refusalOf(static fn (): string => self::authorizer()->compile($subject, new ScopedDocument, 'posts:view'));

        self::assertSame([RefusalReason::INVALID_POLICY], $refusal->reasons());
        self::assertSame('a policy attached to a record cannot be read', $refusal->refusals[0]->detail);

        DB::table('authorizable_policies')->insert(['policy_id' => $id, 'authorizable_type' => $user->getMorphClass(), 'authorizable_id' => 'u1']);

        // Written past the grant service, so the request's memo is dropped.
        $this->app?->forgetInstance(ResolutionCache::class);

        self::assertSame([RefusalReason::INVALID_POLICY], self::refusalOf(static fn (): string => self::authorizer()->compile($subject, new ScopedPost, 'posts:view'))->reasons());
    }

    /**
     * A material statement that cannot be evaluated is refused; one that does
     * not name the action is not.
     *
     * @return void
     */
    public function testAnInvalidMaterialStatementIsRefused(): void
    {
        $user      = StubIdentity::create(['id' => 'u1']);
        $subject   = new Subject($user, $user);
        $broken    = ['no_such_operator' => ['input.x' => 1]];
        $invalid   = static fn (string $action): EvaluationPolicy => new EvaluationPolicy('broken', [new Statement(PolicyEffect::ALLOW, [$action], null, $broken)]);
        $authorize = static fn (string $action): string => self::authorizer(self::pipeline()->withPolicies([$invalid($action)]))->compile($subject, new ScopedPost, 'posts:view');

        self::assertSame(QueryAuthorizer::NO_ROW, $authorize('posts:edit'));

        $refusal = self::refusalOf(static fn (): string => $authorize('posts:view'));

        self::assertSame([RefusalReason::INVALID_STATEMENT], $refusal->reasons());
        self::assertSame('broken#0', $refusal->refusals[0]->statement);
    }

    /**
     * Every material statement that reads the resource, or whose pattern no key
     * can be compared with, is refused, all of them together, naming each, the
     * denies first as a check weighs them; none of their operands, patterns or
     * values is named. A statement naming records by their keys compiles.
     *
     * @return void
     */
    public function testStatementsTheScopeCannotCompileAreRefusedTogether(): void
    {
        $user    = StubIdentity::create(['id' => 'u1']);
        $subject = new Subject($user, $user);
        $type    = (new ScopedPost)->getMorphClass();

        $user->attachPolicy(self::storedPolicy('records', [
            ['sid' => 'Literal', 'effect' => 'deny', 'actions' => ['posts:view'], 'resources' => [$type . ':1']],
            ['sid' => 'MinusZero', 'effect' => 'allow', 'actions' => ['posts:view'], 'resources' => [$type . ':-0']],
            ['sid' => 'Question', 'effect' => 'allow', 'actions' => ['posts:view'], 'resources' => [$type . ':?']],
            ['sid' => 'Reference', 'effect' => 'deny', 'actions' => ['posts:view'], 'resources' => ['${resource.type}:*']],
            ['sid' => 'Condition', 'effect' => 'deny', 'actions' => ['posts:view'], 'conditions' => ['eq' => ['resource.status' => 'draft']]],
            ['sid' => 'Elsewhere', 'effect' => 'deny', 'actions' => ['posts:edit'], 'resources' => [$type . ':?']],
        ]));

        $refusal = self::refusalOf(static fn (): string => self::authorizer()->compile($subject, new ScopedPost, 'posts:view'));
        $reasons = \array_map(static fn ($refusal): string => $refusal->reason->value . ' ' . $refusal->key, $refusal->refusals);

        self::assertSame(['resource_namespace resource.type', 'resource_namespace resource.status', 'resource_pattern '], $reasons);
        self::assertStringNotContainsString(':?', $refusal->getMessage());
        self::assertStringNotContainsString('draft', $refusal->getMessage());
        self::assertStringContainsString('sid="Question"', $refusal->getMessage());
    }

    /**
     * Compiling reads the authorization tables alone, never the model's table,
     * and the same number of times however many rows there are, with a tree of
     * subtrees, a platform-wide grant and policies attached to records.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoQueryRunsPerRowNorOnTheModelsTable(): void
    {
        $this->app?->instance(TenantTree::class, new ClosureTenantTree);

        ClosureTenantTree::add(new Reference('teams', '5'));
        ClosureTenantTree::add(new Reference('teams', '7'), new Reference('teams', '5'));

        $user    = StubIdentity::create(['id' => 'u1']);
        $manager = $this->resolveRequest($user, new Reference('teams', '5'));
        $counts  = [];

        $user->givePermission(Permission::create(['name' => 'posts:view']));

        foreach ([2, 20] as $rows) {
            for ($index = TenantScopedPost::query()->count(); $index < $rows; $index++) {
                $post = TenantScopedPost::query()->create(['title' => 'post', 'tenant_type' => 'teams', 'tenant_id' => (string) [5, 7, 9][$index % 3]]);

                $id = $post->getKey();

                self::attachToResource([TenantScopedPost::class, \is_scalar($id) ? (string) $id : ''], [['effect' => 'deny', 'actions' => ['posts:edit']]]);
            }

            $this->app?->forgetInstance(ResolutionCache::class);
            $this->app?->forgetInstance(SchemaInspector::class);

            /** @var \ArrayObject<int, string> $queries */
            $queries = new \ArrayObject;

            DB::listen(static function (QueryExecuted $query) use ($queries): void {
                $queries[] = $query->sql;
            });

            self::authorizer()->compile($manager->currentSubject(), new TenantScopedPost, 'posts:view');

            DB::getEventDispatcher()?->forget(QueryExecuted::class);

            // The table's columns are described, never its rows read.
            $reads = \array_filter($queries->getArrayCopy(), static fn (string $sql): bool => \preg_match('/\b(?:from|join)\s+[`"]?scoped_posts\b/i', $sql) === 1);

            self::assertSame([], \array_values($reads));

            $counts[] = \count($queries);
        }

        self::assertSame($counts[0], $counts[1]);
    }

    /**
     * A key holding a glob's special characters is named as `check()` names it:
     * a substituted `*` or `x:*` only as itself, never every record nor the
     * type, a document's backslash as itself, and an escaped `\${` as text.
     *
     * @return void
     */
    public function testSpecialKeysAreNamedAsCheckNamesThem(): void
    {
        $user    = StubIdentity::create(['id' => 'u1']);
        $manager = $this->resolveRequest($user);
        $type    = (new ScopedDocument)->getMorphClass();

        foreach (['*', 'x:*', 'a\b', 'ab', '${input.k}', 'x:a'] as $code) {
            ScopedDocument::query()->create(['code' => $code]);
        }

        $user->attachPolicy(self::storedPolicy('special', [
            ['effect' => 'allow', 'actions' => ['posts:view'], 'resources' => [$type . ':${input.k}', $type . ':a\b', $type . ':\${input.k}']],
            ['effect' => 'allow', 'actions' => ['posts:edit'], 'resources' => [$type . ':${input.k}*']],
        ]));

        foreach ([['k' => '*'], ['k' => 'x:*'], ['k' => 'x:'], []] as $context) {
            foreach (['posts:view', 'posts:edit'] as $action) {
                $isAllowed = static fn (mixed $code): bool => $manager->can($action, ScopedDocument::query()->where('code', $code)->first(), $context);
                $allowed   = \array_values(\array_filter(ScopedDocument::query()->orderBy('row_id')->pluck('code')->all(), $isAllowed));
                $kept      = ScopedDocument::query()->whereAuthorized($action, $context, $manager)->orderBy('row_id')->pluck('code')->all(); // @phpstan-ignore method.notFound

                self::assertSame($allowed, $kept, $action . ' ' . \json_encode($context));
            }
        }
    }

    /**
     * A boundary limited to one record caps every other: only that record is
     * kept, as `check()` keeps it, whatever the subject holds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABoundaryLimitedToOneRecordKeepsItAlone(): void
    {
        $user    = StubIdentity::create(['id' => 'u1']);
        $manager = $this->resolveRequest($user);

        foreach ([4, 5, 6] as $id) {
            ScopedPost::query()->create(['id' => $id, 'title' => 'post']);
        }

        $user->givePermission(Permission::create(['name' => 'posts:view']));

        $boundary = self::storedPolicy('only-five', [['effect' => 'allow', 'actions' => ['posts:*'], 'resources' => [(new ScopedPost)->getMorphClass() . ':5']]]);

        app(BoundaryService::class)->set($user, $boundary);

        self::assertSame([5], ScopedPost::query()->whereAuthorized('posts:view', [], $manager)->pluck('id')->all()); // @phpstan-ignore method.notFound
        self::assertSame([], ScopedPost::query()->whereAuthorized('posts:view', [], $manager->capped(['posts:edit']))->pluck('id')->all()); // @phpstan-ignore method.notFound
    }

    /**
     * A statement reading a source not marked `ScopeInvariant` is refused: an
     * application's context source, a subject attribute provider, or a
     * requirement checker judging an authentication requirement.
     *
     * @return void
     */
    public function testAStatementReadingAnUnmarkedSourceIsRefused(): void
    {
        $user    = StubIdentity::create(['id' => 'u1']);
        $subject = new Subject($user, $user);
        $config  = $this->app?->make(ConfigRepository::class);

        $user->attachPolicy(self::storedPolicy('plan', [['effect' => 'allow', 'actions' => ['posts:view'], 'conditions' => ['eq' => ['plan.tier' => 'pro']]]]));

        self::assertSame(QueryAuthorizer::NO_ROW, self::authorizer()->compile($subject, new ScopedPost, 'posts:view'));

        $config?->set('authorization.context.sources', [PlanContextSource::class]); // @phpstan-ignore method.notFound
        $this->app?->forgetInstance(CheckContextFactory::class);

        self::assertSame(['plan'], self::refusedKeys($subject, 'posts:view'));

        $config?->set('authorization.context.sources', []); // @phpstan-ignore method.notFound
        $config?->set('authorization.attributes.subjects', [$user->getMorphClass() => RecordingSubjectAttributes::class]); // @phpstan-ignore method.notFound
        $this->app?->forgetInstance(CheckContextFactory::class);
        $user->attachPolicy(self::storedPolicy('own', [['effect' => 'allow', 'actions' => ['posts:edit'], 'conditions' => ['eq' => ['subject.id' => 'u1']]]]));

        self::assertSame(['subject'], self::refusedKeys($subject, 'posts:edit'));

        $config?->set('authorization.attributes.subjects', []); // @phpstan-ignore method.notFound
        $this->app?->instance(AuthenticationRequirementChecker::class, new StubRequirementChecker(RequirementResult::met()));
        $this->app?->forgetInstance(CheckContextFactory::class);
        $requirement = ['authentication_requirement' => ['authentication' => ['multifactor' => []]]];

        $user->attachPolicy(self::storedPolicy('step-up', [['effect' => 'allow', 'actions' => ['posts:delete'], 'conditions' => $requirement]]));

        self::assertSame(['authentication_requirement'], self::refusedKeys($subject, 'posts:delete'));
        self::assertStringEndsWith('IS NOT NULL', self::authorizer()->compile($subject, new ScopedPost, 'posts:edit'));
    }

    /**
     * Forget the morph map a test set.
     *
     * @return void
     */
    #[After]
    protected function forgetMorphMap(): void
    {
        Relation::morphMap([], false);
    }

    /**
     * Return the compiler of the pipeline given, or of one with every source
     * the service provider gives the manager.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\DecisionPipeline|null  $pipeline
     * @return \SineMacula\Laravel\Authorization\Query\QueryAuthorizer
     */
    private static function authorizer(?DecisionPipeline $pipeline = null): QueryAuthorizer
    {
        return ($pipeline ?? self::pipeline())->queryAuthorizer();
    }

    /**
     * Return a pipeline with every source the service provider gives the
     * manager.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\DecisionPipeline
     */
    private static function pipeline(): DecisionPipeline
    {
        /** @var \SineMacula\Laravel\Authorization\Context\CheckContextFactory $contexts */
        $contexts = app(CheckContextFactory::class);

        return new DecisionPipeline(new PolicyEvaluator, new DefaultPolicyResolver, $contexts, new ResourcePolicyResolver, new GuardrailResolver);
    }

    /**
     * Return the refusal compiling the model's scope throws.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $action
     * @return \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    private static function refused(Subject $subject, Model $model, string $action): QueryScopeRefusedException
    {
        return self::refusalOf(static fn (): string => self::authorizer()->compile($subject, $model, $action));
    }

    /**
     * Return the titles of the tenant-scoped posts the manager allows viewing,
     * in order.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $manager
     * @return list<string>
     */
    private static function allowed(AuthorizationManager $manager): array
    {
        $allowed = [];

        foreach (TenantScopedPost::query()->orderBy('id')->get() as $post) {
            $title = $post->getAttribute('title');

            if (!$manager->can('posts:view', $post) || !\is_string($title)) {
                continue;
            }

            $allowed[] = $title;
        }

        return $allowed;
    }

    /**
     * Return the key each refusal compiling a post's scope names.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $action
     * @return list<string|null>
     */
    private static function refusedKeys(Subject $subject, string $action): array
    {
        return \array_map(static fn (Refusal $refusal): ?string => $refusal->key, self::refused($subject, new ScopedPost, $action)->refusals);
    }
}
