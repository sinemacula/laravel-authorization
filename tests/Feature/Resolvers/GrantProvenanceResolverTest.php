<?php

declare(strict_types = 1);

namespace Tests\Feature\Resolvers;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\GrantSource;
use SineMacula\Laravel\Authorization\Evaluation\EvidenceRecorder;
use SineMacula\Laravel\Authorization\Evaluation\GrantProvenance;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Resolvers\GrantProvenanceResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\CustomGrantsIdentity;
use Tests\Feature\Stubs\HiddenPolicy;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubMachine;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\SuspendableIdentity;
use Tests\Feature\Stubs\UndeclaredRolesGrantee;
use Tests\TestCase;

/**
 * Feature tests for the grant provenance resolver: an explained check's
 * permissions and policies, the ones the grant resolution gives, each with the
 * grant row it came from, the roles it came through and the scope it was
 * granted in, read in no more queries than the resolution of the names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(GrantProvenanceResolver::class)]
final class GrantProvenanceResolverTest extends TestCase
{
    /**
     * A permission granted directly, in a tenant and an application, is held
     * with its grant row; the exact name wins over a pattern, as it does
     * without explain mode.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADirectGrantIsHeldWithItsRow(): void
    {
        $tenant = StubTenant::query()->create(['id' => 'tenant-1', 'name' => 'tenant-1']);
        $user   = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:*']));
        $user->givePermission(Permission::create(['name' => 'posts:read']), null, $tenant, true, 'web');

        $subject = new Subject($user, $user);
        $resolve = static fn (string $action): array => TenantScope::within(
            Reference::of($tenant),
            'web',
            static fn (): array => GrantProvenanceResolver::permissionFor($subject, $action),
        );

        [$held, $grants] = $resolve('posts:read');
        [$pattern]       = $resolve('posts:edit');

        self::assertSame('posts:read', $held);
        self::assertEquals([new GrantProvenance(GrantSource::PERMISSION, 'posts:read', Reference::of($user), false, [], true, Reference::of($tenant), 'web')], $grants);
        self::assertSame('posts:*', $pattern);
        self::assertSame([null, []], GrantProvenanceResolver::permissionFor(new Subject($user, $user), 'comments:read'));
    }

    /**
     * A permission held through a role and again through an ancestor of another
     * role names each path; with the hierarchy disabled, only the roles held
     * count.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolePermissionNamesEachPath(): void
    {
        $author = Role::create(['name' => 'author']);
        $editor = Role::create(['name' => 'editor', 'parent_id' => $author->id]);
        $writer = Role::create(['name' => 'writer']);
        $user   = StubIdentity::create(['id' => 'user-1']);
        $read   = Permission::create(['name' => 'posts:read']);

        $author->givePermissionTo($read);
        $writer->givePermissionTo($read);
        $user->assignRole($editor);
        $user->assignRole($writer, null, null, true, 'web');

        [$held, $grants] = TenantScope::within(null, 'web', static fn (): array => GrantProvenanceResolver::permissionFor(new Subject($user, $user), 'posts:read'));

        self::assertSame('posts:read', $held);
        self::assertEqualsCanonicalizing([
            new GrantProvenance(GrantSource::ROLE_PERMISSION, 'posts:read', Reference::of($user), false, ['editor', 'author'], true),
            new GrantProvenance(GrantSource::ROLE_PERMISSION, 'posts:read', Reference::of($user), false, ['writer'], true, null, 'web'),
        ], $grants);

        $this->app?->make(ConfigRepository::class)->set('authorization.hierarchy.enabled', false);

        self::assertSame([null, []], GrantProvenanceResolver::permissionFor(new Subject($user, $user), 'posts:read'));
    }

    /**
     * The identity's permission is held when the subject's own do not match,
     * named as the identity's; an identity of the other kind grants nothing,
     * and an inactive subject holds nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheIdentityGrantsOnlyWhenItGrantsToTheSubject(): void
    {
        $principal = StubIdentity::create(['id' => 'principal-1']);
        $identity  = StubSecondIdentity::create(['id' => 'person-1']);
        $machine   = StubMachine::create(['id' => 'machine-1']);
        $read      = Permission::create(['name' => 'posts:read']);

        $identity->givePermission($read);
        $machine->givePermission($read);

        [, $grants] = GrantProvenanceResolver::permissionFor(new Subject($principal, $identity), 'posts:read');

        self::assertEquals([new GrantProvenance(GrantSource::PERMISSION, 'posts:read', Reference::of($identity), true, [], true)], $grants);
        self::assertSame([null, []], GrantProvenanceResolver::permissionFor(new Subject($principal, $machine), 'posts:read'));

        $suspended = SuspendableIdentity::create(['id' => 'person-2']);

        $suspended->givePermission($read);
        $suspended->suspended = true;

        self::assertSame([null, []], GrantProvenanceResolver::permissionFor(new Subject($principal, $suspended), 'posts:read'));
    }

    /**
     * A grantee whose own code gives its permissions holds what that code
     * gives, its provenance unavailable.
     *
     * @return void
     */
    public function testACustomGranteeIsUnavailable(): void
    {
        $user = CustomGrantsIdentity::create(['id' => 'custom-1']);

        $own = GrantProvenanceResolver::permissionFor(new Subject($user, $user), 'reports:read');

        self::assertEquals(['reports:read', [GrantProvenance::unavailable('reports:read', Reference::of($user))]], $own);
        self::assertSame([null, []], GrantProvenanceResolver::permissionFor(new Subject($user, $user), 'reports:write'));
        self::assertEquals(
            ['reports:read', [GrantProvenance::unavailable('reports:read', null, true)]],
            GrantProvenanceResolver::permissionFor(new Subject(StubIdentity::create(['id' => 'principal-1']), new CustomGrantsIdentity(['id' => 'unsaved'])), 'reports:read'),
        );
    }

    /**
     * The policies are those `getPolicies()` resolves, each with where it came
     * from: its own attachment with its scope, or a role held, through each
     * ancestor up to the role it is attached to.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePoliciesAreTheResolvedOnesWithTheirProvenance(): void
    {
        $tenant = StubTenant::query()->create(['id' => 'tenant-1', 'name' => 'tenant-1']);
        $author = Role::create(['name' => 'author']);
        $editor = Role::create(['name' => 'editor', 'parent_id' => $author->id]);
        $user   = StubIdentity::create(['id' => 'user-1']);
        $own    = self::policy('own');
        $shared = self::policy('shared');

        $user->attachPolicy($own, null, $tenant, true, 'web');
        $author->attachPolicy($shared);
        $user->assignRole($editor);

        [$policies, $recorder] = TenantScope::within(Reference::of($tenant), 'web', static function () use ($user): array {
            $recorder = new EvidenceRecorder;

            return [GrantProvenanceResolver::policiesOf($user, $recorder), $recorder];
        });

        $this->app?->forgetInstance(ResolutionCache::class);

        $expected = TenantScope::within(Reference::of($tenant), 'web', static fn (): array => $user->getPolicies());

        self::assertEqualsCanonicalizing(self::names($expected), self::names($policies));
        self::assertEquals(
            [
                new GrantProvenance(GrantSource::POLICY, "own[{$own->id}]", Reference::of($user), false, [], true, Reference::of($tenant), 'web'),
                new GrantProvenance(GrantSource::ROLE_POLICY, "shared[{$shared->id}]", Reference::of($user), false, ['editor', 'author'], true),
            ],
            $recorder->evidenceFor(Decision::allow(DecisionStage::ALLOW, [new StatementReference('own', 0, $own->id), new StatementReference('shared', 0, $shared->id)]))->grants,
        );
    }

    /**
     * An explained check reads the policies as an everyday check does: an
     * attachment naming half a tenant, and any attachment of a policy naming
     * half a tenant, counts in every scope for its denies alone, the grantee's
     * own and a role's alike, unless an attachment that holds, of a policy
     * naming no half tenant, reaches the policy too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAttachmentNamingHalfATenantIsExplainedForItsDeniesAlone(): void
    {
        $user  = StubIdentity::create(['id' => 'user-1']);
        $role  = Role::create(['name' => 'editor']);
        $names = ['whole', 'keyless', 'mixed', 'owned', 'role half', 'role owned', 'role both', 'own and role half'];
        $made  = [];

        $statements = [['effect' => 'allow', 'actions' => ['posts:read']], ['effect' => 'deny', 'actions' => ['posts:write']]];

        foreach ($names as $name) {
            $made[$name] = Policy::create(['name' => $name, 'document' => ['statements' => $statements]]);
        }

        $user->assignRole($role);
        $user->attachPolicy($made['whole']);
        $user->attachPolicy($made['mixed']);
        $role->attachPolicy($made['role owned']);
        $role->attachPolicy($made['role both']);
        $user->attachPolicy($made['own and role half']);

        $own  = ['authorizable_type' => $user->getMorphClass(), 'authorizable_id' => 'user-1', 'include_subtree' => true];
        $held = ['authorizable_type' => $role->getMorphClass(), 'authorizable_id' => $role->id, 'include_subtree' => true];

        DB::table('authorizable_policies')->insert([
            ['policy_id' => $made['keyless']->id, ...$own, 'tenant_type' => 'tenant', 'tenant_id' => null],
            ['policy_id' => $made['mixed']->id, ...$own, 'tenant_type' => null, 'tenant_id' => 't-1'],
            ['policy_id' => $made['owned']->id, ...$own, 'tenant_type' => 'tenant', 'tenant_id' => 't-2'],
            ['policy_id' => $made['role half']->id, ...$held, 'tenant_type' => null, 'tenant_id' => 't-1'],
            ['policy_id' => $made['own and role half']->id, ...$held, 'tenant_type' => null, 'tenant_id' => 't-1'],
        ]);

        // Read after the role's whole row, a half row of the same policy never
        // takes away what the whole one gives.
        DB::table('authorizable_policies')->insert(['policy_id' => $made['role both']->id, ...$held, 'tenant_type' => null, 'tenant_id' => 't-1']);
        DB::table('policies')->whereIn('id', [$made['owned']->id, $made['role owned']->id])->update(['tenant_type' => 'tenant', 'tenant_id' => null]);

        $this->app?->forgetInstance(ResolutionCache::class);

        $effects = [];

        foreach (GrantProvenanceResolver::policiesOf($user, new EvidenceRecorder) as $policy) {
            $effects[$policy->name] = \array_values(\array_map(static fn (Statement $statement): string => $statement->effect->value, $policy->statements));
        }

        \ksort($effects);

        $denies = ['deny'];

        $both = ['allow', 'deny'];

        self::assertSame([
            'keyless'           => $denies,
            'mixed'             => $both,
            'own and role half' => $both,
            'owned'             => $denies,
            'role both'         => $both,
            'role half'         => $denies,
            'role owned'        => $denies,
            'whole'             => $both,
        ], $effects);
    }

    /**
     * An attachment naming half a tenant only denies, so it is never where an
     * allow came from: the evidence of an allow lists the grantee's whole
     * attachment and the route through the role attaching the policy whole,
     * never the grantee's half row, which would read as the platform's, nor the
     * role attaching it by a half row.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAttachmentNamingHalfATenantIsNeverWhereAnAllowCameFrom(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $whole  = Role::create(['name' => 'whole']);
        $half   = Role::create(['name' => 'half']);
        $policy = Policy::create(['name' => 'p', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]]);

        $tenant = StubTenant::query()->create(['id' => 'tenant-1', 'name' => 'tenant-1']);

        $user->attachPolicy($policy, tenant: $tenant);
        $user->assignRole($whole);
        $user->assignRole($half);
        $whole->attachPolicy($policy);

        $own  = ['policy_id' => $policy->id, 'authorizable_type' => $user->getMorphClass(), 'authorizable_id' => 'user-1'];
        $held = ['policy_id' => $policy->id, 'authorizable_type' => $half->getMorphClass(), 'authorizable_id' => $half->id];

        DB::table('authorizable_policies')->insert([
            [...$own, 'include_subtree' => true, 'tenant_type' => null, 'tenant_id' => 'zzz'],
            [...$held, 'include_subtree' => true, 'tenant_type' => 'tenant', 'tenant_id' => null],
        ]);

        $this->app?->forgetInstance(ResolutionCache::class);

        $recorder = new EvidenceRecorder;

        TenantScope::within($tenant, null, static fn (): array => GrantProvenanceResolver::policiesOf($user, $recorder));

        $grants = $recorder->evidenceFor(Decision::allow(DecisionStage::ALLOW, [new StatementReference('p', 0, $policy->id)]))->grants;
        $shown  = \array_map(static fn (GrantProvenance $grant): array => [$grant->source, $grant->roles, $grant->tenant?->id], $grants);

        self::assertEqualsCanonicalizing([[GrantSource::POLICY, [], 'tenant-1'], [GrantSource::ROLE_POLICY, ['whole'], null]], $shown);
    }

    /**
     * Without a role holding a policy in scope, the roles are never read, and a
     * grantee without policies has none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRolesAreReadOnlyWhenOneHoldsAPolicy(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $user->assignRole(Role::create(['name' => 'editor']));

        DB::enableQueryLog();
        DB::flushQueryLog();

        $policies = GrantProvenanceResolver::policiesOf($user, new EvidenceRecorder);
        $queries  = \count(DB::getQueryLog());

        DB::disableQueryLog();

        self::assertSame([], $policies);
        self::assertSame(1, $queries);
    }

    /**
     * The resolution reads no more than the resolution of the names does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testItReadsNoMoreThanTheNamesResolution(): void
    {
        $author = Role::create(['name' => 'author']);
        $editor = Role::create(['name' => 'editor', 'parent_id' => $author->id]);
        $user   = StubIdentity::create(['id' => 'user-1']);

        $author->givePermissionTo(Permission::create(['name' => 'posts:read']));
        $author->attachPolicy(self::policy('shared'));
        $user->givePermission(Permission::create(['name' => 'posts:edit']));
        $user->attachPolicy(self::policy('own'));
        $user->assignRole($editor);

        $count = static function (\Closure $read): int {
            DB::enableQueryLog();
            DB::flushQueryLog();

            $read();

            $queries = \count(DB::getQueryLog());

            DB::disableQueryLog();

            return $queries;
        };

        $this->app?->forgetInstance(ResolutionCache::class);
        $names = $count(static fn (): array => [$user->getPermissions(), $user->getPolicies()]);

        $provenance = $count(static fn (): array => [
            GrantProvenanceResolver::permissionFor(new Subject($user, $user), 'posts:read'),
            GrantProvenanceResolver::policiesOf($user, new EvidenceRecorder),
        ]);

        self::assertLessThanOrEqual($names, $provenance);
    }

    /**
     * The identity's policies are noted as the identity's, whole when it grants
     * to the subject and as their denies alone otherwise; a subject that is its
     * own identity has none, and a grantee whose own code gives its policies is
     * noted as unavailable.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheIdentityPolicies(): void
    {
        $principal = StubIdentity::create(['id' => 'principal-1']);
        $identity  = StubSecondIdentity::create(['id' => 'person-1']);
        $machine   = StubMachine::create(['id' => 'machine-1']);
        $mixed     = Policy::create(['name' => 'mixed', 'document' => ['statements' => [
            ['effect' => 'allow', 'actions' => ['posts:read']],
            ['effect' => 'deny', 'actions' => ['posts:delete']],
        ]]]);

        $identity->attachPolicy($mixed);
        $machine->attachPolicy($mixed);

        $recorder = new EvidenceRecorder;
        $whole    = GrantProvenanceResolver::identityPolicies(new Subject($principal, $identity), $recorder);
        $denials  = GrantProvenanceResolver::identityPolicies(new Subject($principal, $machine), new EvidenceRecorder);
        $custom   = new EvidenceRecorder;

        self::assertCount(2, $whole[0]->statements ?? []);
        self::assertSame([1], \array_keys($denials[0]->statements ?? []));
        self::assertSame([], GrantProvenanceResolver::identityPolicies(new Subject($principal, $principal), new EvidenceRecorder));
        self::assertSame([], GrantProvenanceResolver::identityPolicies(new Subject($principal, new \stdClass), new EvidenceRecorder));
        self::assertEquals(
            [new GrantProvenance(GrantSource::POLICY, "mixed[{$mixed->id}]", Reference::of($identity), true, [], true)],
            $recorder->evidenceFor(Decision::allow(DecisionStage::ALLOW, [new StatementReference('mixed', 0, $mixed->id)]))->grants,
        );

        $coded = GrantProvenanceResolver::policiesOf($user = CustomGrantsIdentity::create(['id' => 'custom-1']), $custom, true);

        self::assertSame(['coded'], self::names($coded));
        self::assertEquals(
            [GrantProvenance::unavailable('coded', Reference::of($user), true)],
            $custom->evidenceFor(Decision::allow(DecisionStage::ALLOW, [new StatementReference('coded', 0)]))->grants,
        );
    }

    /**
     * A grantee whose roles are not declared through `SupportsRoles` holds its
     * policies by its own attachments alone, the roles never read, as its
     * `getPolicies()` reads them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGranteeWithUndeclaredRoles(): void
    {
        $grantee = UndeclaredRolesGrantee::create(['id' => 'grantee-1']);
        $own     = self::policy('own');

        $grantee->attachPolicy($own);

        DB::enableQueryLog();
        DB::flushQueryLog();

        $recorder = new EvidenceRecorder;
        $policies = GrantProvenanceResolver::policiesOf($grantee, $recorder);
        $queries  = \count(DB::getQueryLog());

        DB::disableQueryLog();

        self::assertSame(['own'], self::names($policies));
        self::assertSame(2, $queries);
        self::assertEquals(
            [new GrantProvenance(GrantSource::POLICY, "own[{$own->id}]", Reference::of($grantee), false, [], true)],
            $recorder->evidenceFor(Decision::allow(DecisionStage::ALLOW, [new StatementReference('own', 0, $own->id)]))->grants,
        );
    }

    /**
     * A policy reached through a role that the policy model's scope hides is
     * left out, and the policies after it are still resolved, as the resolution
     * of the names resolves them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyTheModelHidesIsLeftOut(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $role   = Role::create(['name' => 'editor']);
        $hidden = self::policy('hidden');
        $shown  = self::policy('shown');

        $role->attachPolicy($hidden);
        $role->attachPolicy($shown);
        $user->assignRole($role);

        $this->app?->make(ConfigRepository::class)->set('authorization.models.policy', HiddenPolicy::class);

        $recorder = new EvidenceRecorder;
        $policies = GrantProvenanceResolver::policiesOf($user, $recorder);

        $this->app?->forgetInstance(ResolutionCache::class);

        self::assertSame(['shown'], self::names($policies));
        self::assertSame(self::names($user->getPolicies()), self::names($policies));
    }

    /**
     * On a warm cache, what decided is what the cache holds, as an everyday
     * check decides from it: the grant rows are read afresh only for where a
     * grant that decided came from, never when no permission is held or the
     * grantee has no policy, and a grant the cache still holds that the rows no
     * longer give is `unavailable`, never guessed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWarmCacheDecidesAndAStaleGrantIsUnavailable(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $bare = StubIdentity::create(['id' => 'user-2']);
        $own  = self::policy('own');
        $read = Permission::create(['name' => 'posts:read']);

        $user->givePermission($read);
        $user->attachPolicy($own);
        $user->getPermissions();
        $user->getPolicies();
        $bare->getPolicies();

        $subject = new Subject($user, $user);
        $count   = static function (\Closure $read): int {
            DB::enableQueryLog();
            DB::flushQueryLog();

            $read();

            $queries = \count(DB::getQueryLog());

            DB::disableQueryLog();

            return $queries;
        };

        self::assertSame(0, $count(static fn (): array => GrantProvenanceResolver::permissionFor($subject, 'comments:read')));
        self::assertSame(0, $count(static fn (): array => GrantProvenanceResolver::policiesOf($bare, new EvidenceRecorder)));

        $fresh = new EvidenceRecorder;

        self::assertEquals(
            ['posts:read', [new GrantProvenance(GrantSource::PERMISSION, 'posts:read', Reference::of($user), false, [], true)]],
            GrantProvenanceResolver::permissionFor($subject, 'posts:read'),
        );
        self::assertSame(['own'], self::names(GrantProvenanceResolver::policiesOf($user, $fresh)));
        self::assertEquals(
            [new GrantProvenance(GrantSource::POLICY, "own[{$own->id}]", Reference::of($user), false, [], true)],
            $fresh->evidenceFor(Decision::allow(DecisionStage::ALLOW, [new StatementReference('own', 0, $own->id)]))->grants,
        );

        DB::table('authorizable_permissions')->delete();
        DB::table('authorizable_policies')->delete();

        $recorder = new EvidenceRecorder;

        self::assertEquals(['posts:read', [GrantProvenance::unavailable('posts:read', Reference::of($user))]], GrantProvenanceResolver::permissionFor($subject, 'posts:read'));
        self::assertSame(['own'], self::names(GrantProvenanceResolver::policiesOf($user, $recorder)));
        self::assertEquals(
            [GrantProvenance::unavailable("own[{$own->id}]", Reference::of($user))],
            $recorder->evidenceFor(Decision::allow(DecisionStage::ALLOW, [new StatementReference('own', 0, $own->id)]))->grants,
        );
    }

    /**
     * Without a resolution cache, the check decides from the rows read for
     * where each grant came from.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutACacheTheRowsDecide(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $own  = self::policy('own');

        $user->givePermission(Permission::create(['name' => 'posts:read']));
        $user->attachPolicy($own);

        $this->app?->offsetUnset(ResolutionCache::class);

        $recorder = new EvidenceRecorder;

        self::assertNull(ResolutionCache::instance());
        self::assertEquals(
            ['posts:read', [new GrantProvenance(GrantSource::PERMISSION, 'posts:read', Reference::of($user), false, [], true)]],
            GrantProvenanceResolver::permissionFor(new Subject($user, $user), 'posts:read'),
        );
        self::assertSame(['own'], self::names(GrantProvenanceResolver::policiesOf($user, $recorder)));
        self::assertEquals(
            [new GrantProvenance(GrantSource::POLICY, "own[{$own->id}]", Reference::of($user), false, [], true)],
            $recorder->evidenceFor(Decision::allow(DecisionStage::ALLOW, [new StatementReference('own', 0, $own->id)]))->grants,
        );
    }

    /**
     * On a cold cache, the check decides from the rows read for provenance, and
     * keeps nothing in the cache, so a later everyday check resolves its grants
     * itself.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAColdCacheKeepsNothing(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:read']));
        $user->attachPolicy(self::policy('own'));

        GrantProvenanceResolver::permissionFor(new Subject($user, $user), 'posts:read');
        GrantProvenanceResolver::policiesOf($user, new EvidenceRecorder);

        DB::enableQueryLog();
        DB::flushQueryLog();

        $user->getPermissions();
        $user->getPolicies();

        $queries = \count(DB::getQueryLog());

        DB::disableQueryLog();

        self::assertGreaterThan(0, $queries);
    }

    /**
     * A policy whose document cannot be read throws, as the resolution of the
     * names does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnreadablePolicyThrows(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $broken = self::policy('broken');

        $user->attachPolicy($broken);
        DB::table('policies')->where('id', $broken->id)->update(['document' => '{"statements": "nonsense"}']);

        $this->expectException(InvalidPolicyDocumentException::class);

        GrantProvenanceResolver::policiesOf($user, new EvidenceRecorder);
    }

    /**
     * Create a stored policy allowing an action.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function policy(string $name): Policy
    {
        return Policy::create(['name' => $name, 'document' => ['statements' => [['effect' => 'allow', 'actions' => ["{$name}:read"]]]]]);
    }

    /**
     * Return the names of the policies.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @return list<string>
     */
    private static function names(array $policies): array
    {
        return \array_values(\array_map(static fn (EvaluationPolicy $policy): string => $policy->name, $policies));
    }
}
