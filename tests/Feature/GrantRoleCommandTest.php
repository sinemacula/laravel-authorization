<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Console\GrantRoleCommand;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the `authorization:grant` Artisan command.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantRoleCommand::class)]
final class GrantRoleCommandTest extends TestCase
{
    /**
     * Successfully grants a role to an identity via morph alias.
     *
     * @return void
     */
    public function testGrantsRoleViaMorphAlias(): void
    {
        Relation::morphMap(['stub_identity' => StubIdentity::class]);

        Role::create(['id' => '42008342-6351-490d-8a02-9615371eeb8d', 'name' => 'editor', 'guard_name' => 'web']);
        $user = StubIdentity::create(['id' => 'af0f3486-876c-46ac-85fe-a5b7335b394a']);

        $exitCode = Artisan::call('authorization:grant', [
            'identity' => 'stub_identity:af0f3486-876c-46ac-85fe-a5b7335b394a',
            'role'     => 'editor',
        ]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('granted', Artisan::output());
        /** @var \Tests\Feature\Stubs\StubIdentity $freshUser */
        $freshUser = $user->fresh();
        self::assertTrue($freshUser->hasRole('editor'));

        // Reset the shared morph map — `morphMap([])` merges rather
        // than replaces, so without the `false` second arg the
        // `stub_identity` alias leaks into later tests in the run.
        Relation::morphMap([], false);
    }

    /**
     * Successfully grants a role via raw class-string.
     *
     * @return void
     */
    public function testGrantsRoleViaClassName(): void
    {
        Role::create(['id' => 'cbe9505c-00d8-4985-89ed-9bae2eb5e5b4', 'name' => 'admin', 'guard_name' => 'web']);
        StubIdentity::create(['id' => 'abca5c3d-111a-4cdb-8a40-0916dbac1d93']);

        $exitCode = Artisan::call('authorization:grant', [
            'identity' => StubIdentity::class . ':abca5c3d-111a-4cdb-8a40-0916dbac1d93',
            'role'     => 'admin',
        ]);

        self::assertSame(0, $exitCode);
        /** @var \Tests\Feature\Stubs\StubIdentity $found */
        $found = StubIdentity::find('abca5c3d-111a-4cdb-8a40-0916dbac1d93');
        self::assertTrue($found->hasRole('admin'));
    }

    /**
     * Fails on invalid identity format.
     *
     * @return void
     */
    public function testFailsOnInvalidIdentityFormat(): void
    {
        $exitCode = Artisan::call('authorization:grant', [
            'identity' => 'no-colon',
            'role'     => 'editor',
        ]);

        self::assertSame(1, $exitCode);
    }

    /**
     * Fails when class cannot be resolved.
     *
     * @return void
     */
    public function testFailsOnUnresolvableClass(): void
    {
        $exitCode = Artisan::call('authorization:grant', [
            'identity' => 'NonExistentClass:1',
            'role'     => 'editor',
        ]);

        self::assertSame(1, $exitCode);
    }

    /**
     * Fails when model does not exist in the database.
     *
     * @return void
     */
    public function testFailsWhenModelNotFound(): void
    {
        $exitCode = Artisan::call('authorization:grant', [
            'identity' => StubIdentity::class . ':missing',
            'role'     => 'editor',
        ]);

        self::assertSame(1, $exitCode);
    }

    /**
     * Fails when role does not exist.
     *
     * @return void
     */
    public function testFailsWhenRoleDoesNotExist(): void
    {
        StubIdentity::create(['id' => '538d1787-6f8a-44cc-81ad-19f2980fc83b']);

        $exitCode = Artisan::call('authorization:grant', [
            'identity' => StubIdentity::class . ':538d1787-6f8a-44cc-81ad-19f2980fc83b',
            'role'     => 'nonexistent',
        ]);

        self::assertSame(1, $exitCode);
    }

    /**
     * A failed grant outputs the exception message. Pins the
     * MethodCallRemoval mutant on line 65 of GrantRoleCommand.
     *
     * @return void
     */
    public function testFailedGrantOutputsErrorMessage(): void
    {
        StubIdentity::create(['id' => 'a1a1a1a1-0000-0000-0000-000000000001']);

        $exitCode = Artisan::call('authorization:grant', [
            'identity' => StubIdentity::class . ':a1a1a1a1-0000-0000-0000-000000000001',
            'role'     => 'does-not-exist',
        ]);
        $output = Artisan::output();

        self::assertSame(1, $exitCode);
        self::assertNotEmpty(\trim($output), 'Error message must be printed on failure.');
    }

    /**
     * Success message includes both the role name and identity arg.
     * Pins the ReturnRemoval on line 59 (FAILURE return prevents
     * reaching the info line).
     *
     * @return void
     */
    public function testSuccessMessageIncludesRoleAndIdentity(): void
    {
        Role::create(['id' => 'a2a2a2a2-0000-0000-0000-000000000001', 'name' => 'msg-role', 'guard_name' => 'web']);
        StubIdentity::create(['id' => 'a3a3a3a3-0000-0000-0000-000000000001']);

        $identity = StubIdentity::class . ':a3a3a3a3-0000-0000-0000-000000000001';
        $exitCode = Artisan::call('authorization:grant', [
            'identity' => $identity,
            'role'     => 'msg-role',
        ]);
        $output = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('msg-role', $output);
        self::assertStringContainsString($identity, $output);
    }

    /**
     * Fails with empty identity key segment. Pins the
     * `$parts[1] === ''` branch in ResolvesIdentity line 36.
     *
     * @return void
     */
    public function testFailsOnEmptyKeySegment(): void
    {
        $exitCode = Artisan::call('authorization:grant', [
            'identity' => 'SomeClass:',
            'role'     => 'editor',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('{morphType}:{key}', Artisan::output());
    }

    /**
     * Fails with empty type segment. Pins the `$parts[0] === ''`
     * branch in ResolvesIdentity line 36.
     *
     * @return void
     */
    public function testFailsOnEmptyTypeSegment(): void
    {
        $exitCode = Artisan::call('authorization:grant', [
            'identity' => ':123',
            'role'     => 'editor',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('{morphType}:{key}', Artisan::output());
    }

    /**
     * Fails when class is not an Eloquent model. Pins the
     * `is_subclass_of(Model)` branch in ResolvesIdentity line 54.
     *
     * @return void
     */
    public function testFailsWhenClassIsNotEloquentModel(): void
    {
        $exitCode = Artisan::call('authorization:grant', [
            'identity' => \stdClass::class . ':1',
            'role'     => 'editor',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('not an Eloquent model', Artisan::output());
    }

    /**
     * Fails when model does not implement AuthorizableIdentity.
     * Pins the `!$model instanceof AuthorizableIdentity` branch
     * in ResolvesIdentity lines 71-73 and the Concat on line 73.
     *
     * @return void
     */
    public function testFailsWhenModelNotAuthorizable(): void
    {
        // Use the Role model which IS an Eloquent model but does
        // NOT implement AuthorizableIdentity.
        $role = Role::create([
            'id'         => 'a4a4a4a4-0000-0000-0000-000000000001',
            'name'       => 'check',
            'guard_name' => 'web',
        ]);

        $exitCode = Artisan::call('authorization:grant', [
            'identity' => Role::class . ':' . $role->getKey(),
            'role'     => 'check',
        ]);
        $output = Artisan::output();

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('AuthorizableIdentity', $output);
    }

    /**
     * Error message for unresolvable class includes the morph type.
     * Pins the Concat/ConcatOperandRemoval on ResolvesIdentity line 49.
     *
     * @return void
     */
    public function testErrorMessageIncludesMorphType(): void
    {
        $exitCode = Artisan::call('authorization:grant', [
            'identity' => 'FakeNonExistentClass:999',
            'role'     => 'editor',
        ]);
        $output = Artisan::output();

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('FakeNonExistentClass', $output);
    }

    /**
     * Error message for missing model includes the key. Pins the
     * MethodCallRemoval on ResolvesIdentity line 66 and
     * Concat on line 73.
     *
     * @return void
     */
    public function testErrorMessageForMissingModelIncludesKey(): void
    {
        $exitCode = Artisan::call('authorization:grant', [
            'identity' => StubIdentity::class . ':missing-key-99',
            'role'     => 'editor',
        ]);
        $output = Artisan::output();

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('missing-key-99', $output);
    }
}
