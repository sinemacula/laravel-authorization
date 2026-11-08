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
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Resolvers\GrantProvenanceResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\CustomGrantsIdentity;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubMachine;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Feature\Stubs\StubTenant;
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
