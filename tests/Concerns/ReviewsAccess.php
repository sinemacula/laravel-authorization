<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Reviews\AccessReview;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewResult;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Fixtures\GrantScope\ListedIdentityDirectory;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;

/**
 * Sets up what access reviews read: identities, roles in a hierarchy, the
 * permissions and policies they carry, grants of each in a tree of tenants, and
 * the review service, with a compact description of each row a review returns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait ReviewsAccess
{
    /**
     * Bind a closure-table tree of two organisations, the first with two
     * accounts and a team below the first account, and an empty, complete
     * identity directory.
     *
     * @return void
     */
    protected function tree(): void
    {
        $this->app?->instance(TenantTree::class, new ClosureTenantTree);
        $this->app?->instance(IdentityDirectory::class, new ListedIdentityDirectory);

        ClosureTenantTree::add(self::tenant('org1'));
        ClosureTenantTree::add(self::tenant('acct1'), self::tenant('org1'));
        ClosureTenantTree::add(self::tenant('acct2'), self::tenant('org1'));
        ClosureTenantTree::add(self::tenant('team1'), self::tenant('acct1'));
        ClosureTenantTree::add(self::tenant('org2'));
    }

    /**
     * Give the application a key, so paged reviews can sign their cursors.
     *
     * @return void
     */
    protected static function keyCursors(): void
    {
        config(['app.key' => 'base64:' . \base64_encode(\str_repeat('k', 32))]);
    }

    /**
     * Return the reference to the tenant with the id.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    protected static function tenant(string $id): Reference
    {
        return new Reference('tenant', $id);
    }

    /**
     * Return a new identity with the id.
     *
     * @param  string  $id
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    protected static function identity(string $id): StubIdentity
    {
        /** @var \Tests\Feature\Stubs\StubIdentity */
        return StubIdentity::query()->create(['id' => $id]);
    }

    /**
     * Return a new role with the name, below the parent when one is given,
     * owned by the tenant when one is given.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authorization\Models\Role|null  $parent
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $owner
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    protected static function role(string $name, ?Role $parent = null, ?Reference $owner = null): Role
    {
        $role = new Role;

        $role->forceFill(['name' => $name, 'parent_id' => $parent?->getKey(), 'tenant_type' => $owner?->type, 'tenant_id' => $owner?->id])->save();

        return $role;
    }

    /**
     * Return a new permission with the name, owned by the tenant when one is
     * given.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $owner
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     */
    protected static function permission(string $name, ?Reference $owner = null): Permission
    {
        $permission = new Permission;

        $permission->forceFill(['name' => $name, 'tenant_type' => $owner?->type, 'tenant_id' => $owner?->id])->save();

        return $permission;
    }

    /**
     * Return a new policy with the name, one that only denies unless told to
     * allow.
     *
     * @param  string  $name
     * @param  bool  $isAllowing
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    protected static function policy(string $name, bool $isAllowing = false): Policy
    {
        /** @var \SineMacula\Laravel\Authorization\Models\Policy */
        return Policy::query()->create(['name' => $name, 'document' => ['statements' => [['effect' => $isAllowing ? 'allow' : 'deny', 'actions' => ['posts:delete']]]]]);
    }

    /**
     * Return the grant service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService
     */
    protected static function grants(): GrantService
    {
        $service = GrantService::instance();

        self::assertInstanceOf(GrantService::class, $service);

        return $service;
    }

    /**
     * Return the role service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\RoleService
     */
    protected static function roles(): RoleService
    {
        /** @var \SineMacula\Laravel\Authorization\Services\RoleService */
        return app(RoleService::class);
    }

    /**
     * Return the access review service.
     *
     * @return \SineMacula\Laravel\Authorization\Reviews\AccessReview
     */
    protected static function reviews(): AccessReview
    {
        /** @var \SineMacula\Laravel\Authorization\Reviews\AccessReview */
        return app(AccessReview::class);
    }

    /**
     * Run the review as trusted system work.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @return \SineMacula\Laravel\Authorization\Reviews\ReviewResult
     */
    protected static function trusted(ReviewQuery $query): ReviewResult
    {
        return self::reviews()->trusted($query);
    }

    /**
     * Read every page of the review as trusted work, at most the size of rows a
     * page, from the first to the last, and return the rows of all of them and
     * the SQL each page ran.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  int  $size
     * @return array{rows: list<\SineMacula\Laravel\Authorization\Reviews\ReviewRow>, queries: list<list<string>>}
     *
     * @throws \Throwable
     */
    protected static function pagedThrough(ReviewQuery $query, int $size): array
    {
        $sql = [];

        DB::listen(static function (QueryExecuted $executed) use (&$sql): void {
            $sql[] = $executed->sql;
        });

        $rows    = [];
        $queries = [];
        $cursor  = null;

        do {
            $sql    = [];
            $page   = self::reviews()->trustedPage($query, $cursor, $size);
            $cursor = $page->nextCursor;

            \array_push($rows, ...$page->rows);

            $queries[] = $sql;
        } while ($cursor !== null && \count($queries) < 10000);

        return ['rows' => $rows, 'queries' => $queries];
    }

    /**
     * Describe each row of the result as its kind, its subject's key, its
     * grantee's key when another, the roles of its path by name, and its target
     * by name, in the result's order.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewResult  $result
     * @return list<string>
     */
    protected static function described(ReviewResult $result): array
    {
        return \array_map(static fn (ReviewRow $row): string => self::describe($row), $result->rows);
    }

    /**
     * Describe the row as its kind, its subject's key, its grantee's key when
     * another, the roles of its path by name, and its target by name.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewRow  $row
     * @return string
     */
    protected static function describe(ReviewRow $row): string
    {
        $grantee = $row->grantee->id === $row->subject->id ? '' : ' via ' . $row->grantee->id;
        $path    = \array_map(static fn (Reference $role): string => self::nameOf($role), $row->rolePath);
        $target  = self::nameOf($row->target);

        return $row->sourceKind->value . ' ' . $row->subject->id . $grantee . ($path === [] ? '' : ' [' . \implode('>', $path) . ']') . ' ' . $target;
    }

    /**
     * Return the name of the definition the reference names, read outside every
     * global scope through its morph type, which is its class with no morph
     * map, or its key when there is none.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $definition
     * @return string
     */
    private static function nameOf(Reference $definition): string
    {
        $class = $definition->type;
        $name  = \is_a($class, Model::class, true) ? $class::query()->withoutGlobalScopes()->whereKey($definition->id)->value('name') : null;

        return \is_string($name) ? $name : $definition->id;
    }
}
