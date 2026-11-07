<?php

declare(strict_types = 1);

namespace Tests\Feature\Query;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Query\ResourceShape;
use SineMacula\Laravel\Authorization\Query\SchemaInspector;
use SineMacula\Laravel\Authorization\Query\TenantMembership;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\Fixtures\QueryScoping\ScopedTicket;
use Tests\Fixtures\QueryScoping\TenantScopedPost;
use Tests\TestCase;

/**
 * Feature tests for the conditions a row meets for its tenant: none, one the
 * resolver can read, exactly a tenant, or within a tenant's subtree.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(TenantMembership::class)]
final class TenantMembershipTest extends TestCase
{
    /**
     * A row of no tenant has either column null; one with a tenant has neither,
     * each at most 191 bytes; one exactly a tenant matches its bytes.
     *
     * @return void
     */
    public function testTheRowsOfNoTenantOfOneAndOfExactlyOne(): void
    {
        $rows = ['none' => [null, null], 'partial' => ['teams', null], 'team' => ['teams', '5'], 'case' => ['Teams', '5'], 'long' => ['teams', \str_repeat('5', 192)]];

        foreach ($rows as $title => [$type, $id]) {
            TenantScopedPost::query()->create(['title' => $title, 'tenant_type' => $type, 'tenant_id' => $id]);
        }

        $membership = self::membership(new TenantScopedPost);

        self::assertSame(['none', 'partial'], self::titles($membership->ofNone()));
        self::assertSame(['team', 'case'], self::titles($membership->present()));
        self::assertSame(['team'], self::titles($membership->equalTo(new Reference('teams', '5'))));
        self::assertSame(['team'], self::titles($membership->within(new Reference('teams', '5'))));
    }

    /**
     * A row within a tenant's subtree is one the tree's subtree query selects,
     * compared byte for byte, the tenant itself included; a fixed tenant type
     * is compared as its bytes.
     *
     * @return void
     */
    public function testARowWithinASubtreeIsOneTheTreeSelects(): void
    {
        $this->app?->instance(TenantTree::class, new ClosureTenantTree);

        ClosureTenantTree::add(new Reference('teams', '5'));
        ClosureTenantTree::add(new Reference('teams', '7'), new Reference('teams', '5'));
        ClosureTenantTree::add(new Reference('teams', '9'));

        foreach (['five' => '5', 'seven' => '7', 'nine' => '9', 'padded' => '7 '] as $title => $id) {
            TenantScopedPost::query()->create(['title' => $title, 'tenant_type' => 'teams', 'tenant_id' => $id]);
            ScopedTicket::query()->create(['title' => $title, 'team_id' => (int) $id]);
        }

        $within = self::membership(new TenantScopedPost)->within(new Reference('teams', '5'));

        self::assertStringStartsWith('EXISTS (SELECT 1 FROM (', $within);
        self::assertSame(['five', 'seven'], self::titles($within));
        $tickets = self::membership(new ScopedTicket)->within(new Reference('teams', '5'));

        self::assertSame(['five', 'seven', 'padded'], ScopedTicket::query()->whereRaw($tickets)->orderBy('id')->pluck('title')->all());
    }

    /**
     * A subtree query run on another connection than the model's cannot be
     * nested, so it is refused naming the tree.
     *
     * @return void
     */
    public function testASubtreeOnAnotherConnectionIsRefused(): void
    {
        $tree = new class implements TenantTree {
            /**
             * Return no ancestors.
             *
             * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
             * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
             */
            #[\Override]
            public function ancestors(Reference $tenant): array
            {
                return [];
            }

            /**
             * Determine whether the tenant is the ancestor.
             *
             * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
             * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
             * @return bool
             */
            #[\Override]
            public function isWithin(Reference $tenant, Reference $ancestor): bool
            {
                return (new FlatTenantTree)->isWithin($tenant, $ancestor);
            }

            /**
             * Return the subtree on a connection of its own.
             *
             * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
             * @return \Illuminate\Contracts\Database\Query\Builder
             */
            #[\Override]
            public function subtree(Reference $tenant): Builder
            {
                config()->set('database.connections.tenants', config('database.connections.' . DB::getDefaultConnection()));

                return DB::connection('tenants')->query()->selectRaw('? as tenant_type, ? as tenant_id', [$tenant->type, $tenant->id]);
            }
        };

        $this->app?->instance(TenantTree::class, $tree);

        try {
            self::membership(new TenantScopedPost)->within(new Reference('teams', '5'));

            self::fail('The subtree was nested.');
        } catch (QueryScopeRefusedException $exception) {
            self::assertSame([RefusalReason::SUBTREE_CONNECTION], $exception->reasons());
            self::assertSame($tree::class, $exception->refusals[0]->key);
        }

        self::assertSame(AuthorizationConnection::resolve(), DB::getDefaultConnection());
    }

    /**
     * Return the writer of the model's tenant conditions.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return \SineMacula\Laravel\Authorization\Query\TenantMembership
     */
    private static function membership(Model $model): TenantMembership
    {
        return new TenantMembership(ResourceShape::of($model, 'posts:view', new SchemaInspector), 'posts:view');
    }

    /**
     * Return the titles of the posts meeting the condition, in order.
     *
     * @param  string  $condition
     * @return list<string>
     */
    private static function titles(string $condition): array
    {
        /** @var list<string> */
        return TenantScopedPost::query()->whereRaw($condition)->orderBy('id')->pluck('title')->all();
    }
}
