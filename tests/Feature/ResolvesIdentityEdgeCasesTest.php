<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Console\GrantRoleCommand;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests covering the two `ResolvesIdentity` error paths that
 * are not exercised by the happy-path command suites:
 *
 * - A morph alias resolves to a real, loadable class that is not an
 *   Eloquent `Model` (the `is_subclass_of($class, Model::class)`
 *   guard).
 * - A morph alias resolves to an Eloquent model whose instance does
 *   not implement `AuthorizableIdentity` (the final safety net before
 *   the trait returns the model).
 *
 * Both branches emit a console error and return `null`, which the
 * consuming commands translate to `FAILURE`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(GrantRoleCommand::class)]
final class ResolvesIdentityEdgeCasesTest extends TestCase
{
    /**
     * When the resolved class exists but is not an Eloquent model,
     * the command reports the error and fails.
     *
     * @return void
     */
    public function testFailsWhenResolvedClassIsNotEloquent(): void
    {
        $exitCode = Artisan::call('authorization:grant', [
            'identity' => \stdClass::class . ':1',
            'role'     => 'editor',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('not an Eloquent model', Artisan::output());
    }

    /**
     * When the resolved model is Eloquent but does not implement
     * `AuthorizableIdentity`, the command reports the error and
     * fails before it tries to delegate a role grant to the model.
     *
     * @return void
     */
    public function testFailsWhenModelDoesNotImplementAuthorizableIdentity(): void
    {
        StubTenant::create(['id' => 'cf202d80-1117-4cd7-86bc-757a4bb0c95b']);

        $exitCode = Artisan::call('authorization:grant', [
            'identity' => StubTenant::class . ':cf202d80-1117-4cd7-86bc-757a4bb0c95b',
            'role'     => 'editor',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('does not implement AuthorizableIdentity', Artisan::output());
    }
}
