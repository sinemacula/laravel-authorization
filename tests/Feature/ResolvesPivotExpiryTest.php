<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Concerns\ResolvesPivotExpiry;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the read of an existing grant that the grant methods use to
 * tell whether a re-grant changes the expiry.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversTrait(ResolvesPivotExpiry::class)]
final class ResolvesPivotExpiryTest extends TestCase
{
    /** @var string The identity whose grants are read. */
    private const string IDENTITY = '5b0c2e1a-7f3d-4a9b-8c6e-1d2f3a4b5c6d';

    /** @var string Another identity, whose grants must not be read. */
    private const string OTHER_IDENTITY = '9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b';

    /**
     * No row for the identity and target reads as no grant.
     *
     * @return void
     */
    public function testMissingGrantReadsAsAbsent(): void
    {
        $role = Role::query()->create(['name' => 'editor']);

        self::assertSame(['exists' => false, 'expires_at' => null], $this->read(self::identity(self::IDENTITY), $role));
    }

    /**
     * A stored grant reads back with its expiry.
     *
     * @return void
     */
    public function testExistingGrantReadsBackWithItsExpiry(): void
    {
        $identity = self::identity(self::IDENTITY);
        $role     = Role::query()->create(['name' => 'editor']);

        $this->grant($identity, $role, '2030-01-02 03:04:05');

        $read = $this->read($identity, $role);

        self::assertTrue($read['exists']);
        self::assertSame('2030-01-02 03:04:05', $read['expires_at']?->format('Y-m-d H:i:s'));
    }

    /**
     * A stored grant without an expiry reads back as existing and forever.
     *
     * @return void
     */
    public function testExistingGrantWithoutExpiryReadsBackAsForever(): void
    {
        $identity = self::identity(self::IDENTITY);
        $role     = Role::query()->create(['name' => 'editor']);

        $this->grant($identity, $role, null);

        self::assertSame(['exists' => true, 'expires_at' => null], $this->read($identity, $role));
    }

    /**
     * Only the identity's own grant of the named target is read: another
     * identity's grant of it, another target's grant and a grant to another
     * grantee type with the same id are not.
     *
     * @return void
     */
    public function testOnlyTheIdentitysGrantOfTheTargetIsRead(): void
    {
        $identity = self::identity(self::IDENTITY);
        $role     = Role::query()->create(['name' => 'editor']);
        $other    = Role::query()->create(['name' => 'author']);

        $this->grant(self::identity(self::OTHER_IDENTITY), $role, null);
        $this->grant($identity, $other, null);

        DB::table('authorizable_roles')->insert([
            'role_id'           => $role->id,
            'authorizable_type' => 'another_type',
            'authorizable_id'   => self::IDENTITY,
        ]);

        self::assertSame(['exists' => false, 'expires_at' => null], $this->read($identity, $role));
    }

    /**
     * Create a stub identity with the given id.
     *
     * @param  string  $id
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private static function identity(string $id): StubIdentity
    {
        return StubIdentity::query()->create(['id' => $id]);
    }

    /**
     * Write a grant of the role to the identity with the given expiry.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  string|null  $expiresAt
     * @return void
     */
    private function grant(StubIdentity $identity, Role $role, ?string $expiresAt): void
    {
        DB::table('authorizable_roles')->insert([
            'role_id'           => $role->id,
            'authorizable_type' => $identity->getMorphClass(),
            'authorizable_id'   => $identity->id,
            'expires_at'        => $expiresAt,
        ]);
    }

    /**
     * Read the identity's grant of the role through the trait.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return array{exists: bool, expires_at: \DateTimeInterface|null}
     */
    private function read(StubIdentity $identity, Role $role): array
    {
        /** @phpstan-ignore-next-line class.missingExtends */
        $probe = new class {
            use ResolvesPivotExpiry;

            /**
             * Read the grant.
             *
             * @param  \Illuminate\Database\Eloquent\Model&\Tests\Feature\Stubs\StubIdentity  $identity
             * @param  string  $roleId
             * @return array{exists: bool, expires_at: \DateTimeInterface|null}
             */
            public function read(Model $identity, string $roleId): array
            {
                return self::authorizationReadGrantPivot($identity, $identity->roles()->newPivotStatement(), 'role_id', $roleId);
            }
        };

        return $probe->read($identity, $role->id);
    }
}
