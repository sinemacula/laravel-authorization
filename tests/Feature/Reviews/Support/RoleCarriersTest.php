<?php

declare(strict_types = 1);

namespace Tests\Feature\Reviews\Support;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Reviews\ApplicationSelector;
use SineMacula\Laravel\Authorization\Reviews\Enums\GrantState;
use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Reviews\Support\GrantRow;
use SineMacula\Laravel\Authorization\Reviews\Support\GrantRows;
use SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun;
use SineMacula\Laravel\Authorization\Reviews\Support\RoleCarriers;
use SineMacula\Laravel\Authorization\Reviews\Support\RowCollector;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ReviewsAccess;
use Tests\TestCase;

/**
 * Feature tests for what roles carry, as a review reads it: live permission
 * edges and policy attachments, an unseen permission and a stray inline policy
 * left out, and the routes a role grant takes to them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(RoleCarriers::class)]
final class RoleCarriersTest extends TestCase
{
    use ReviewsAccess;

    /**
     * A role's live permission edges are read by role, for the roles given or
     * for every role carrying the permission given, an expired edge and, in a
     * tenant, an unseen permission left out.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEdgesAreReadByRole(): void
    {
        $this->tree();

        $one     = self::role('one');
        $two     = self::role('two');
        $shared  = self::permission('shared:read');
        $unseen  = self::permission('unseen:read');
        $expired = self::permission('expired:read');

        self::roles()->grantPermission($one, $shared);
        self::roles()->grantPermission($two, $shared);
        self::roles()->grantPermission($one, $unseen);
        self::roles()->grantPermission($one, $expired, Carbon::now('UTC')->addMinute());

        // Its owner moved since the edge was written.
        DB::table('permissions')->where('id', $unseen->getKey())->update(['tenant_type' => 'tenant', 'tenant_id' => 'org2']);
        DB::table('role_permissions')->where('permission_id', $expired->getKey())->update(['expires_at' => Carbon::now('UTC')->subMinute()->format('Y-m-d H:i:s')]);

        $everywhere = ReviewRun::of(ReviewScope::everywhere());
        $tenant     = ReviewRun::of(ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::none()));

        self::assertEqualsCanonicalizing(
            [Reference::of($shared)->id, Reference::of($unseen)->id],
            self::targets(RoleCarriers::edges($everywhere, [Reference::of($one)->id])[Reference::of($one)->id]),
        );
        self::assertSame([Reference::of($shared)->id], self::targets(RoleCarriers::edges($tenant, [Reference::of($one)->id])[Reference::of($one)->id]));
        self::assertEqualsCanonicalizing(
            [Reference::of($one)->id, Reference::of($two)->id],
            \array_map(strval(...), \array_keys(RoleCarriers::edges($everywhere, null, Reference::of($shared)->id))),
        );
        self::assertSame([], RoleCarriers::edges($everywhere, []));
        self::assertSame([Reference::of($two)->id], \array_map(strval(...), \array_keys(RoleCarriers::edges($everywhere, [Reference::of($two)->id], Reference::of($shared)->id))));
    }

    /**
     * A role's live policy attachments are read by role, in a tenant those that
     * apply there, else those holding in the application selected, an
     * attachment to a grantee and a stray inline policy left out.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttachmentsAreReadByRole(): void
    {
        $this->tree();

        $role   = self::role('role');
        $policy = self::policy('deny');

        self::grants()->attachPolicy($role, $policy, tenant: self::tenant('acct1'));
        self::grants()->attachPolicy($role, $other = self::policy('other'), application: 'web');
        self::grants()->attachPolicy($role, $offchain = self::policy('offchain'), tenant: self::tenant('acct2'));
        self::grants()->attachPolicy($role, $halved = self::policy('halved'), tenant: self::tenant('acct2'));
        self::grants()->attachPolicy(self::identity('ann'), $policy);

        // An attachment naming a type without a key is read wherever what
        // applies is not, for its routes to weigh, and never where it is.
        DB::table('authorizable_policies')->where('policy_id', $halved->getKey())->update(['tenant_id' => null]);

        $inline = Policy::query()->create(
            ['name' => 'inline', 'owner_type' => 'u', 'owner_id' => 'someone', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['x:y']]]]],
        );

        DB::table('authorizable_policies')->insert(
            ['policy_id' => $inline->getKey(), 'authorizable_type' => $role->getMorphClass(), 'authorizable_id' => $role->getKey(), 'include_subtree' => true],
        );

        $key = Reference::of($role)->id;
        $all = RoleCarriers::attachments(ReviewRun::of(ReviewScope::everywhere()), [$key]);

        self::assertEqualsCanonicalizing(
            [Reference::of($policy)->id, Reference::of($other)->id, Reference::of($offchain)->id, Reference::of($halved)->id],
            self::targets($all[$key]),
        );
        self::assertSame(
            [Reference::of($policy)->id],
            self::targets(RoleCarriers::attachments(ReviewRun::of(ReviewScope::appliesIn(self::tenant('team1'), ApplicationSelector::none())), [$key])[$key]),
        );
        self::assertEqualsCanonicalizing(
            [Reference::of($policy)->id, Reference::of($offchain)->id, Reference::of($halved)->id],
            self::targets(RoleCarriers::attachments(ReviewRun::of(ReviewScope::everywhere(ApplicationSelector::none())), [$key])[$key]),
        );

        // Outside a review of what applies in a tenant, an attachment is read
        // whatever its tenant, for the routes to weigh where it holds.
        self::assertEqualsCanonicalizing(
            [Reference::of($policy)->id, Reference::of($other)->id, Reference::of($offchain)->id, Reference::of($halved)->id],
            self::targets(RoleCarriers::attachments(ReviewRun::of(ReviewScope::rootedWithin(self::tenant('acct1'))), [$key])[$key]),
        );
        self::assertSame([Reference::of($other)->id], self::targets(RoleCarriers::attachments(ReviewRun::of(ReviewScope::everywhere()), null, Reference::of($other)->id)[$key]));
        self::assertSame([], RoleCarriers::attachments(ReviewRun::of(ReviewScope::everywhere()), []));
    }

    /**
     * A role grant reaches what each role of its chain carries, one route for
     * each, through the chain up to that role, in the order of their routes; a
     * policy only where the grant and the attachment hold together.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantReachesWhatItsChainCarries(): void
    {
        $this->tree();

        $run   = ReviewRun::of(ReviewScope::everywhere());
        $rows  = new RowCollector($run, 10);
        $grant = self::grant('held', 'acct1');
        $edges = ['held' => [self::edge('held', 'p1')], 'parent' => [self::edge('parent', 'p3'), self::edge('parent', 'p2')]];

        RoleCarriers::throughEdges($rows, new Reference('u', 'ann'), $grant, ['held', 'parent'], $edges, new Reference('person', 'p'));

        self::assertSame([
            'role_permission p1 held',
            'role_permission p2 held>parent',
            'role_permission p3 held>parent',
        ], self::routes($rows));

        self::assertSame('p', $rows->rows()[0]->viaIdentity?->id);

        $attachments = [
            'held'   => [self::attachment('held', 'y1', 'acct2')],
            'parent' => [self::attachment('parent', 'y3', 'team1'), self::attachment('parent', 'y2', null)],
        ];

        $policies = new RowCollector($run, 10);

        RoleCarriers::throughAttachments($run, $policies, new Reference('u', 'ann'), $grant, ['held', 'parent'], $attachments);

        self::assertSame(['role_policy y2 held>parent', 'role_policy y3 held>parent'], self::routes($policies));
        self::assertSame([SourceKind::ROLE_POLICY, null], [$policies->rows()[0]->sourceKind, $policies->rows()[0]->viaIdentity]);

        // An attachment no check places reaches a grant held everywhere alone,
        // and the route through it is malformed.
        $nowhere  = ['held' => [self::attachment('held', 'y4', null, 'tenant')]];
        $inTenant = new RowCollector($run, 10);
        $platform = new RowCollector($run, 10);

        RoleCarriers::throughAttachments($run, $inTenant, new Reference('u', 'ann'), $grant, ['held'], $nowhere);
        RoleCarriers::throughAttachments($run, $platform, new Reference('u', 'ann'), self::grant('held', null), ['held'], $nowhere);

        self::assertSame([], self::routes($inTenant));
        self::assertSame(['role_policy y4 held'], self::routes($platform));
        self::assertSame(GrantState::MALFORMED, $platform->rows()[0]->grantState);

        // The routes come in their own order: by how far up the chain the role
        // carrying each is, nearest first, whatever the roles' keys, then by
        // the row each rests on.
        $sorted  = new RowCollector($run, 10);
        $carried = ['held' => [self::edge('held', 'p9')], '01parent' => [self::edge('01parent', 'p2')], '00top' => [self::edge('00top', 'p1')]];

        RoleCarriers::throughEdges($sorted, new Reference('u', 'ann'), $grant, ['held', '01parent', '00top'], $carried);

        self::assertSame(['role_permission p9 held', 'role_permission p2 held>01parent', 'role_permission p1 held>01parent>00top'], self::routes($sorted));
    }

    /**
     * A query of role grants is limited to those that reach one of the
     * attachments: of a role whose chain reaches the attachment's role, in an
     * application and a tenant where both hold; a role reaching no attachment
     * adds nothing, and no attachment leaves no grant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRoleGrantsAreLimitedToThoseReachingAnAttachment(): void
    {
        $this->tree();

        $parent = self::role('parent');
        $child  = self::role('child', $parent);
        $other  = self::role('other');
        $policy = self::policy('deny');

        self::grants()->attachPolicy($parent, $policy, tenant: self::tenant('acct1'), includeSubtree: false, application: 'web');

        self::grants()->grantRole(self::identity('platform'), $child);
        self::grants()->grantRole(self::identity('here'), $child, tenant: self::tenant('acct1'));
        self::grants()->grantRole(self::identity('below'), $child, tenant: self::tenant('team1'));
        self::grants()->grantRole(self::identity('sibling'), $child, tenant: self::tenant('acct2'));
        self::grants()->grantRole(self::identity('api'), $child, tenant: self::tenant('acct1'), application: 'api');
        self::grants()->grantRole(self::identity('unrelated'), $other, tenant: self::tenant('acct1'));

        $run         = ReviewRun::of(ReviewScope::everywhere());
        $table       = 'authorizable_roles';
        $attachments = RoleCarriers::attachments($run, null, Reference::of($policy)->id);
        $chains      = [Reference::of($child)->id => [Reference::of($child)->id, Reference::of($parent)->id], Reference::of($other)->id => [Reference::of($other)->id]];
        $reaching    = static fn (array $attachments): array => \array_map(
            static fn (GrantRow $row): string => $row->grantee->id,
            GrantRows::all(RoleCarriers::reaching($run, GrantRows::of(GrantTarget::ROLE), $table, $chains, $attachments), 'role'),
        );

        self::assertEqualsCanonicalizing(['platform', 'here'], $reaching($attachments));
        self::assertSame([], $reaching([]));

        // An attachment naming a type without a key, which no check reads in a
        // tenant, is reached only by a grant held everywhere.
        $nowhere = self::policy('nowhere');

        self::grants()->attachPolicy($parent, $nowhere, tenant: self::tenant('acct1'));

        DB::table('authorizable_policies')->where('policy_id', $nowhere->getKey())->update(['tenant_id' => null]);

        self::assertSame(['platform'], $reaching(RoleCarriers::attachments($run, null, Reference::of($nowhere)->id)));
        self::assertSame([], $reaching([Reference::of($other)->id . '-none' => $attachments[Reference::of($parent)->id]]));
    }

    /**
     * Return the keys of the targets of the rows.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>  $rows
     * @return list<string>
     */
    private static function targets(array $rows): array
    {
        return \array_map(static fn (GrantRow $row): string => $row->targetId, $rows);
    }

    /**
     * Describe the rows collected as their kind, target and path.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\RowCollector  $rows
     * @return list<string>
     */
    private static function routes(RowCollector $rows): array
    {
        return \array_map(
            static fn (ReviewRow $row): string => $row->sourceKind->value . ' ' . $row->target->id . ' ' . \implode(
                '>',
                \array_map(static fn (Reference $role): string => $role->id, $row->rolePath),
            ),
            $rows->rows(),
        );
    }

    /**
     * Return a grant of the role in the tenant, or platform-wide for none,
     * reaching below it.
     *
     * @param  string  $role
     * @param  string|null  $tenant
     * @return \SineMacula\Laravel\Authorization\Reviews\Support\GrantRow
     */
    private static function grant(string $role, ?string $tenant): GrantRow
    {
        return GrantRow::from(
            (object) [
                'target_id'       => $role,
                'grantee_type'    => 'u',
                'grantee_id'      => 'ann',
                'tenant_type'     => $tenant === null ? null : 'tenant',
                'tenant_id'       => $tenant,
                'include_subtree' => true,
            ],
            'role',
        );
    }

    /**
     * Return the role's edge to the permission.
     *
     * @param  string  $role
     * @param  string  $permission
     * @return \SineMacula\Laravel\Authorization\Reviews\Support\GrantRow
     */
    private static function edge(string $role, string $permission): GrantRow
    {
        return GrantRow::from((object) ['target_id' => $permission, 'grantee_id' => $role], GrantRow::EDGE, 'role');
    }

    /**
     * Return the attachment of the policy to the role in the tenant, or
     * platform-wide for none, stored with the tenant type given, the tenant's
     * own by default.
     *
     * @param  string  $role
     * @param  string  $policy
     * @param  string|null  $tenant
     * @param  string|null  $type
     * @return \SineMacula\Laravel\Authorization\Reviews\Support\GrantRow
     */
    private static function attachment(string $role, string $policy, ?string $tenant, ?string $type = null): GrantRow
    {
        return GrantRow::from(
            (object) [
                'target_id'       => $policy,
                'grantee_type'    => 'role',
                'grantee_id'      => $role,
                'tenant_type'     => $type ?? ($tenant === null ? null : 'tenant'),
                'tenant_id'       => $tenant,
                'include_subtree' => true,
            ],
            'policy',
        );
    }
}
