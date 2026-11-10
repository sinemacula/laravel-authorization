<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Concerns\HasRoleHierarchy;
use SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Feature\Stubs\CustomRole;
use Tests\TestCase;

/**
 * Feature tests pinning the role class the hierarchy relations and lookups
 * resolve.
 *
 * With `authorization.models.role` pointed at an application subclass, the
 * `parent()` and `children()` relations and the `ancestors()` cycle lookup
 * hydrate that subclass, never the shipped `Role`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(RoleHierarchyCycleException::class)]
#[CoversTrait(HasRoleHierarchy::class)]
final class HasRoleHierarchyTest extends TestCase
{
    /**
     * Point `authorization.models.role` at the subclass stub.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.models.role', CustomRole::class);
    }

    /**
     * `parent()` returns the configured subclass.
     *
     * @return void
     */
    public function testParentReturnsConfiguredRoleClass(): void
    {
        $parent = $this->makeRole('admin');
        $child  = $this->makeRole('editor', $parent->id);

        $resolved = $child->parent()->getResults();

        self::assertSame(CustomRole::class, $child->parent()->getRelated()::class);
        self::assertInstanceOf(CustomRole::class, $resolved);
        self::assertSame($parent->id, $resolved->id);
    }

    /**
     * `children()` returns the configured subclass.
     *
     * @return void
     */
    public function testChildrenReturnsConfiguredRoleClass(): void
    {
        $parent = $this->makeRole('admin');
        $child  = $this->makeRole('editor', $parent->id);

        $children = $parent->children()->get();

        self::assertSame(CustomRole::class, $parent->children()->getRelated()::class);
        self::assertCount(1, $children);
        self::assertSame([CustomRole::class], $children->map(static fn (Role $role): string => $role::class)->all());
        self::assertSame($child->id, $children->first()?->id);
    }

    /**
     * The `ancestors()` cycle lookup hydrates the configured subclass, and no
     * row is read back as the shipped `Role` along the way.
     *
     * @return void
     */
    public function testAncestorsCycleLookupUsesConfiguredRoleClass(): void
    {
        $root  = $this->makeRole('admin');
        $child = $this->makeRole('editor', $root->id);

        DB::table('roles')->where('id', $root->id)->update(['parent_id' => $child->id]);

        $hydrated = $this->recordHydratedRoleClasses();

        try {
            $child->ancestors();
            self::fail('RoleHierarchyCycleException was not thrown.');
        } catch (RoleHierarchyCycleException $exception) {
            self::assertSame('editor', $exception->getRoleName());
            self::assertSame('admin', $exception->getProposedParentName());
        }

        self::assertSame([CustomRole::class], \array_values(\array_unique($hydrated->getArrayCopy())));
    }

    /**
     * The `ancestors()` cycle lookup hydrates the configured subclass even when
     * the walk starts from a shipped `Role` instance, so the lookup reads the
     * configured class rather than the class it is called on.
     *
     * @return void
     */
    public function testAncestorsCycleLookupFromBaseRoleUsesConfiguredRoleClass(): void
    {
        $root  = $this->makeRole('admin');
        $child = $this->makeRole('editor', $root->id);

        DB::table('roles')->where('id', $root->id)->update(['parent_id' => $child->id]);

        $start = Role::query()->findOrFail($child->id);

        self::assertSame(Role::class, $start::class);

        $hydrated = $this->recordHydratedRoleClasses();

        try {
            $start->ancestors();
            self::fail('RoleHierarchyCycleException was not thrown.');
        } catch (RoleHierarchyCycleException $exception) {
            self::assertSame('editor', $exception->getRoleName());
            self::assertSame('admin', $exception->getProposedParentName());
        }

        // The chain is loaded once: the two roles in the cycle, each as the
        // configured class.
        self::assertSame([CustomRole::class, CustomRole::class], $hydrated->getArrayCopy());
    }

    /**
     * Record the class of every role model hydrated from here on.
     *
     * @return \ArrayObject<int, string>
     */
    private function recordHydratedRoleClasses(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $hydrated */
        $hydrated = new \ArrayObject;

        Event::listen('eloquent.retrieved: *', static function (string $event, array $payload) use ($hydrated): void {
            if (!$payload[0] instanceof Role) {
                return;
            }

            $hydrated->append($payload[0]::class);
        });

        return $hydrated;
    }

    /**
     * Create a role through the configured subclass.
     *
     * @param  string  $name
     * @param  string|null  $parentId
     * @return \Tests\Feature\Stubs\CustomRole
     */
    private function makeRole(string $name, ?string $parentId = null): CustomRole
    {
        return CustomRole::query()->create([
            'name'      => $name,
            'guard'     => 'web',
            'parent_id' => $parentId,
        ]);
    }
}
