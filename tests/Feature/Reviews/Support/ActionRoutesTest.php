<?php

declare(strict_types = 1);

namespace Tests\Feature\Reviews\Support;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Reviews\ApplicationSelector;
use SineMacula\Laravel\Authorization\Reviews\Enums\EvidenceKind;
use SineMacula\Laravel\Authorization\Reviews\Enums\GrantState;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewResult;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Reviews\Support\ActionRoutes;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ReviewsAccess;
use Tests\Fixtures\GrantScope\ListedIdentityDirectory;
use Tests\TestCase;

/**
 * Feature tests for where a subject holds an action: the routes of its holdings
 * whose permission or policy gives the action, kept before the rows are sorted
 * and paged, each with what gives it and its compact reach.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ActionRoutes::class)]
final class ActionRoutesTest extends TestCase
{
    use ReviewsAccess;

    /** @var string The action most cases ask about. */
    private const string ACTION = 'audit:read';

    /**
     * A permission covering the action gives it however it is held: directly,
     * through the identity, through a role granted or one above it; a role is
     * no route by itself, and a permission not covering the action is left out.
     * Each row allows, as a permission.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPermissionGivesTheActionByEveryRoute(): void
    {
        $admin  = self::role('admin');
        $editor = self::role('editor', $admin);
        $person = self::identity('person');
        $ann    = self::identity('ann');
        $read   = self::permission(self::ACTION);

        $admin->givePermissionTo($read);
        $editor->givePermissionTo(self::permission('audit:*'));
        $editor->givePermissionTo(self::permission('audit:write'));

        self::grants()->grantRole($ann, $editor);
        self::grants()->grantPermission($ann, $read);
        self::grants()->grantPermission($ann, self::permission('comments:*'));
        self::grants()->grantPermission($person, $read);

        $result = self::held(new Subject($ann, $person));

        self::assertEqualsCanonicalizing([
            'permission_grant ann audit:read',
            'permission_grant ann via person audit:read',
            'role_permission ann [editor] audit:*',
            'role_permission ann [editor>admin] audit:read',
        ], self::described($result));

        foreach ($result->rows as $row) {
            self::assertSame([self::ACTION, EvidenceKind::PERMISSION, PolicyEffect::ALLOW, null, true], [
                $row->evidence?->action, $row->evidence?->evidence, $row->evidence?->effect, $row->evidence?->guard, $row->evidence?->isComplete,
            ]);
        }

        self::assertTrue($result->isStoredInventoryOnly);
        self::assertSame([], self::described(self::held(new Subject($ann, $person), 'posts:read')));
    }

    /**
     * Matching is case-sensitive and the asked action literal: a held pattern
     * covers it by the wildcard rules, a name differing in case does not, and
     * the guard each permission is scoped to is kept apart.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAHeldNameCoversTheActionCaseSensitively(): void
    {
        $ann = self::identity('ann');

        foreach (['Audit:read', 'aud*', 'a*:read', '*', 'audit:read.all', 'audit:rea'] as $name) {
            self::grants()->grantPermission($ann, self::permission($name));
        }

        // MySQL's unique name index folds case, so each casing is stored under
        // a guard of its own.
        foreach (['audit:READ' => 'web', self::ACTION => 'api'] as $name => $guard) {
            $permission = new Permission;

            $permission->forceFill(['name' => $name, 'guard' => $guard])->save();

            self::grants()->grantPermission($ann, $permission);
        }

        $result = self::held(new Subject($ann, $ann));

        self::assertEqualsCanonicalizing(
            ['permission_grant ann aud*', 'permission_grant ann a*:read', 'permission_grant ann *', 'permission_grant ann audit:read'],
            self::described($result),
        );
        self::assertEqualsCanonicalizing([null, null, null, 'api'], \array_map(static fn (ReviewRow $row): ?string => $row->evidence?->guard, $result->rows));
        self::assertEqualsCanonicalizing(['permission_grant ann Audit:read', 'permission_grant ann *'], self::described(self::held(new Subject($ann, $ann), 'Audit:read')));
    }

    /**
     * A policy gives the action when a statement names it, attached directly or
     * to a role of the chain: an allow allows; a policy that only denies it is
     * kept as deny evidence; conditions, resource patterns and requirements are
     * reported, never evaluated; a policy naming another action is left out.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyGivesTheActionByItsStatements(): void
    {
        $ann     = self::identity('ann');
        $carrier = self::role('carrier');

        $policies = [
            'allowing'    => [['effect' => 'allow', 'actions' => [self::ACTION]]],
            'denying'     => [['effect' => 'deny', 'actions' => ['audit:*']]],
            'conditional' => [['effect' => 'allow', 'actions' => ['audit:*'], 'resources' => ['report:*'], 'conditions' => ['eq' => ['input.tenant' => 'org-1']]]],
            'other'       => [['effect' => 'allow', 'actions' => ['audit:write']]],
        ];

        foreach ($policies as $name => $statements) {
            self::grants()->attachPolicy($ann, self::document($name, $statements));
        }

        self::grants()->attachPolicy($carrier, self::document('through-role', [['effect' => 'deny', 'not_actions' => ['comments:*']], ['effect' => 'allow', 'actions' => ['*']]]));
        self::grants()->grantRole($ann, $carrier);

        $result   = self::held(new Subject($ann, $ann));
        $evidence = [];

        foreach ($result->rows as $row) {
            $shape = $row->evidence?->toArray() ?? [];

            $evidence[self::describe($row)] = [
                $shape['evidence']              ?? null,
                $shape['effect']                ?? null,
                $shape['has_deny']              ?? null,
                $shape['has_conditions']        ?? null,
                $shape['has_resource_patterns'] ?? null,
            ];
        }

        \ksort($evidence);

        self::assertSame([
            'policy_attachment ann allowing'         => ['policy_statement', 'allow', false, false, false],
            'policy_attachment ann conditional'      => ['policy_statement', 'allow', false, true, true],
            'policy_attachment ann denying'          => ['policy_statement', 'deny', true, false, false],
            'role_policy ann [carrier] through-role' => ['policy_statement', 'allow', true, false, false],
        ], $evidence);
    }

    /**
     * A policy whose stored document cannot be read is kept as incomplete
     * evidence, with no effect, never dropped, beside the readable ones.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnreadablePolicyIsKeptIncomplete(): void
    {
        $ann     = self::identity('ann');
        $broken  = self::document('broken', [['effect' => 'allow', 'actions' => [self::ACTION]]]);
        $invalid = self::document('invalid', [['effect' => 'allow', 'actions' => [self::ACTION]]]);

        self::grants()->attachPolicy($ann, $broken);
        self::grants()->attachPolicy($ann, $invalid);
        self::grants()->attachPolicy($ann, self::document('sound', [['effect' => 'allow', 'actions' => [self::ACTION]]]));

        DB::table($broken->getTable())->where('id', $broken->getKey())->update(['document' => '"broken"']);
        DB::table($invalid->getTable())->where('id', $invalid->getKey())->update(['document' => '{"statements":[{"effect":"maybe","actions":["audit:read"]}]}']);

        $kept = [];

        foreach (self::held(new Subject($ann, $ann))->rows as $row) {
            $kept[self::describe($row)] = [$row->evidence?->isComplete, $row->evidence?->effect, $row->evidence?->evidence];
        }

        \ksort($kept);

        self::assertSame([
            'policy_attachment ann broken'  => [false, null, EvidenceKind::POLICY_STATEMENT],
            'policy_attachment ann invalid' => [false, null, EvidenceKind::POLICY_STATEMENT],
            'policy_attachment ann sound'   => [true, PolicyEffect::ALLOW, EvidenceKind::POLICY_STATEMENT],
        ], $kept);
    }

    /**
     * An identity's holdings of the action include every principal's it lists,
     * each row keeping its grantee; a principal's include its identity's but
     * never a sibling's; an incomplete directory stays incomplete on a page
     * with no row.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testIdentityModeIncludesPrincipalsAndAnIncompleteDirectoryStaysIncomplete(): void
    {
        $person = self::identity('person');
        $web    = self::identity('person-web');
        $api    = self::identity('person-api');
        $read   = self::permission(self::ACTION);

        foreach ([$person, $web, $api] as $grantee) {
            self::grants()->grantPermission($grantee, $read);
        }

        self::grants()->grantPermission($api, self::permission('audit:write'));

        $key = ListedIdentityDirectory::key(Reference::of($person));

        $this->app?->instance(IdentityDirectory::class, new ListedIdentityDirectory([$key => [Reference::of($web), Reference::of($api)]]));

        self::assertEqualsCanonicalizing(
            ['permission_grant person audit:read', 'permission_grant person via person-web audit:read', 'permission_grant person via person-api audit:read'],
            self::described(self::held($person)),
        );
        self::assertEqualsCanonicalizing(
            ['permission_grant person-web audit:read', 'permission_grant person-web via person audit:read'],
            self::described(self::held(new Subject($web, $person))),
        );

        $this->app?->instance(IdentityDirectory::class, new ListedIdentityDirectory([$key => [Reference::of($web)]], false));

        $empty = self::held(Reference::of($person), 'audit:delete');
        $page  = self::reviews()->trustedPage(ReviewQuery::holdings($person, ReviewScope::everywhere())->forAction('audit:delete'));

        self::assertSame([[], false, true], [$empty->rows, $empty->isComplete, $empty->isStoredInventoryOnly]);
        self::assertSame([[], false, true, null], [$page->rows, $page->isComplete, $page->isStoredInventoryOnly, $page->nextCursor]);
    }

    /**
     * Each row's reach is compact, read from its origin scope: a tenant node, a
     * subtree root, or an explicit platform record, never expanded; one
     * application's route stays that application's under a review of any, and a
     * review of another application leaves it out.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReachIsCompactAndApplicationsStayApart(): void
    {
        $this->tree();

        $ann  = self::identity('ann');
        $read = self::permission(self::ACTION);

        self::grants()->grantPermission($ann, $read);
        self::grants()->grantPermission($ann, $read, application: 'admin');
        self::grants()->grantPermission($ann, $read, tenant: self::tenant('org1'));
        self::grants()->grantPermission($ann, $read, tenant: self::tenant('acct1'), includeSubtree: false);

        $reaches = static fn (ReviewResult $result): array => \array_map(static fn (ReviewRow $row): mixed => $row->evidence?->toArray()['reach'], $result->rows);

        $platform = ['kind' => 'platform', 'tenant' => null, 'application' => null, 'include_subtree' => true];

        self::assertSame([
            $platform,
            ['kind' => 'platform', 'tenant' => null, 'application' => 'admin', 'include_subtree' => true],
            self::reach('node', 'acct1'),
            self::reach('subtree', 'org1'),
        ], $reaches(self::held(new Subject($ann, $ann))));

        self::assertSame(
            [$platform, self::reach('subtree', 'org1')],
            $reaches(self::held(new Subject($ann, $ann), self::ACTION, ReviewScope::appliesIn(self::tenant('acct2'), ApplicationSelector::named('web')))),
        );
    }

    /**
     * A policy through a role reaches only where the role's grant and the
     * attachment hold together, never the wider of the two, while the row's
     * origin scope stays the grant's as stored; a grant meeting no attachment
     * holds no route.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolesPolicyReachesWhereItsGrantAndAttachmentOverlap(): void
    {
        $this->tree();

        $carrier = self::role('carrier');
        $ann     = self::identity('ann');
        $bob     = self::identity('bob');
        $cat     = self::identity('cat');

        $allowing = self::document('allowing', [['effect' => 'allow', 'actions' => [self::ACTION]]]);

        self::grants()->attachPolicy($carrier, $allowing, tenant: self::tenant('org1'), application: 'admin');
        self::grants()->grantRole($ann, $carrier);
        self::grants()->grantRole($bob, $carrier, tenant: self::tenant('acct1'), includeSubtree: false);
        self::grants()->grantRole($cat, $carrier, tenant: self::tenant('org2'));

        $annRows = self::held(new Subject($ann, $ann))->rows;
        $bobRows = self::held(new Subject($bob, $bob))->rows;

        self::assertCount(1, $annRows);
        self::assertSame(self::reach('subtree', 'org1', 'admin'), $annRows[0]->evidence?->toArray()['reach']);
        self::assertSame(['tenant' => null, 'application' => null, 'include_subtree' => true], $annRows[0]->originScope?->toArray());
        self::assertSame(self::reach('node', 'acct1', 'admin'), $bobRows[0]->evidence?->toArray()['reach']);
        self::assertSame([], self::held(new Subject($cat, $cat))->rows);

        $applying = self::held(new Subject($ann, $ann), self::ACTION, ReviewScope::appliesIn(self::tenant('team1'), ApplicationSelector::named('admin')))->rows;

        self::assertSame(self::reach('subtree', 'org1', 'admin'), $applying[0]->evidence?->toArray()['reach']);
    }

    /**
     * A route resting on a row naming half a tenant keeps its `malformed`
     * state, its reach the half-named row's tenant columns as stored: the
     * grant's, or a role's attachment's; a role's route still reaches only the
     * application its grant or its attachment names, whichever row is
     * half-named.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARouteNamingHalfATenantKeepsItsState(): void
    {
        $this->tree();

        $carrier  = self::role('carrier');
        $platform = self::role('platform-carrier');
        $ann      = self::identity('ann');
        $attached = self::document('attached', [['effect' => 'deny', 'actions' => [self::ACTION]]]);
        $global   = self::document('global', [['effect' => 'allow', 'actions' => [self::ACTION]]]);

        self::grants()->grantPermission($ann, self::permission(self::ACTION), tenant: self::tenant('acct1'));
        self::grants()->attachPolicy($carrier, $attached, tenant: self::tenant('acct1'), includeSubtree: false);
        self::grants()->grantRole($ann, $carrier, application: 'admin');
        self::grants()->attachPolicy($platform, $global, application: 'admin');
        self::grants()->grantRole($ann, $platform, tenant: self::tenant('acct2'));

        DB::table('authorizable_permissions')->where('tenant_id', 'acct1')->update(['tenant_type' => null]);
        DB::table('authorizable_policies')->where('policy_id', $attached->getKey())->update(['tenant_type' => null]);
        DB::table('authorizable_roles')->where('tenant_id', 'acct2')->update(['tenant_id' => null]);

        $shown = [];

        foreach (self::held(new Subject($ann, $ann))->rows as $row) {
            $reach = $row->evidence?->toArray()['reach'];

            $shown[self::describe($row)] = [$row->grantState, $reach['tenant'] ?? null, $reach['application'] ?? null];
        }

        \ksort($shown);

        self::assertSame([
            'permission_grant ann audit:read'           => [GrantState::MALFORMED, ['type' => null, 'id' => 'acct1'], null],
            'role_policy ann [carrier] attached'        => [GrantState::MALFORMED, ['type' => null, 'id' => 'acct1'], 'admin'],
            'role_policy ann [platform-carrier] global' => [GrantState::MALFORMED, ['type' => 'tenant', 'id' => null], 'admin'],
        ], $shown);
    }

    /**
     * The routes are kept before the rows are paged, so each page holds its
     * limit of matching rows however many routes do not match, in the same
     * order as one review of them all, the rows of one target in several scopes
     * split across pages exactly once; the page's queries do not grow with the
     * routes read, and nothing is decided or dispatched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPageHoldsItsLimitOfMatchingRows(): void
    {
        $this->tree();
        self::keyCursors();

        $ann  = self::identity('ann');
        $read = self::permission(self::ACTION);

        for ($index = 0; $index < 30; $index++) {
            self::grants()->grantPermission($ann, self::permission(\sprintf('other:%02d', $index)));
        }

        foreach (['a*', 'au*', 'aud*', 'audi*'] as $name) {
            self::grants()->grantPermission($ann, self::permission($name));
        }

        self::grants()->attachPolicy($ann, self::document('other', [['effect' => 'allow', 'actions' => ['other:*']]]));

        foreach ([null, self::tenant('org1'), self::tenant('acct1'), self::tenant('team1')] as $tenant) {
            self::grants()->grantPermission($ann, $read, tenant: $tenant);
        }

        $query = ReviewQuery::holdings(new Subject($ann, $ann), ReviewScope::everywhere())->forAction(self::ACTION);
        $whole = self::trusted($query);
        $paged = self::pagedThrough($query, 3);

        self::assertCount(8, $whole->rows);
        self::assertCount(3, $paged['queries']);
        $keys = static fn (array $rows): array => \array_map(static fn (ReviewRow $row): string => $row->rowKey, $rows);

        self::assertSame($keys($whole->rows), $keys($paged['rows']));

        $sizes = [];
        $page  = null;

        do {
            $page    = self::reviews()->trustedPage($query, $page?->nextCursor, 3);
            $sizes[] = \count($page->rows);
        } while ($page->nextCursor !== null);

        self::assertSame([3, 3, 2], $sizes);

        $few = self::queriesOf(ReviewQuery::holdings(new Subject($ann, $ann), ReviewScope::everywhere())->forAction(self::ACTION)->withLimit(3));

        for ($index = 30; $index < 60; $index++) {
            self::grants()->grantPermission($ann, self::permission(\sprintf('other:%02d', $index)));
            self::grants()->attachPolicy($ann, self::document(\sprintf('other-%02d', $index), [['effect' => 'allow', 'actions' => ['other:*']]]));
        }

        Event::fake([AuthorizationFailed::class, DecisionEvaluated::class]);

        self::assertSame($few, self::queriesOf(ReviewQuery::holdings(new Subject($ann, $ann), ReviewScope::everywhere())->forAction(self::ACTION)->withLimit(3)));

        Event::assertNotDispatched(AuthorizationFailed::class);
        Event::assertNotDispatched(DecisionEvaluated::class);
        self::assertNull(Authorization::lastDecision());
    }

    /**
     * Return the review of what the subject holds giving the action, in the
     * scope, as trusted work.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Subject|\SineMacula\Laravel\Authorization\Support\Reference  $subject
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewScope|null  $scope
     * @return \SineMacula\Laravel\Authorization\Reviews\ReviewResult
     */
    private static function held(Model|Reference|Subject $subject, string $action = self::ACTION, ?ReviewScope $scope = null): ReviewResult
    {
        return self::trusted(ReviewQuery::holdings($subject, $scope ?? ReviewScope::everywhere())->forAction($action));
    }

    /**
     * Return the shape of a reach of the kind, in the tenant, for the
     * application.
     *
     * @param  string  $kind
     * @param  string  $tenant
     * @param  string|null  $application
     * @return array<string, mixed>
     */
    private static function reach(string $kind, string $tenant, ?string $application = null): array
    {
        return ['kind' => $kind, 'tenant' => ['type' => 'tenant', 'id' => $tenant], 'application' => $application, 'include_subtree' => $kind === 'subtree'];
    }

    /**
     * Return a new policy with the name and the statements.
     *
     * @param  string  $name
     * @param  list<array<string, mixed>>  $statements
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function document(string $name, array $statements): Policy
    {
        /** @var \SineMacula\Laravel\Authorization\Models\Policy */
        return Policy::query()->create(['name' => $name, 'document' => ['statements' => $statements]]);
    }

    /**
     * Return how many queries the first page of the review runs.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @return int
     */
    private static function queriesOf(ReviewQuery $query): int
    {
        $count = 0;

        DB::listen(static function (QueryExecuted $executed) use (&$count): void {
            $count++;
        });

        self::reviews()->trustedPage($query);

        app('events')->forget(QueryExecuted::class);

        return $count;
    }
}
