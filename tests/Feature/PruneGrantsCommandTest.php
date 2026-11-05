<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Console\PruneGrantsCommand;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `authorization:prune`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PruneGrantsCommand::class)]
final class PruneGrantsCommandTest extends TestCase
{
    /**
     * Reset the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * The command removes expired grants and the grants of grantees that are
     * gone, and says how many; pretending says how many it would remove.
     *
     * @return void
     */
    public function testPrunesAndReports(): void
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        StubIdentity::create(['id' => 'user-1'])->assignRole(Role::create(['name' => 'editor']), Carbon::parse('2026-07-01 11:00:00'));
        StubIdentity::create(['id' => 'user-2'])->assignRole(Role::create(['name' => 'viewer']));

        DB::table('stub_identities')->where('id', 'user-2')->delete();

        self::assertSame(0, Artisan::call('authorization:prune', ['--pretend' => true]));
        self::assertSame("Would prune 1 expired grant(s) and 1 grant(s) of grantees that no longer exist.\n", Artisan::output());
        self::assertSame(2, DB::table('authorizable_roles')->count());

        self::assertSame(0, Artisan::call('authorization:prune', ['--chunk' => '1']));
        self::assertSame("Pruned 1 expired grant(s) and 1 grant(s) of grantees that no longer exist.\n", Artisan::output());
        self::assertSame(0, DB::table('authorizable_roles')->count());
    }

    /**
     * A grantee type that names no model class is warned about and its grants
     * are left.
     *
     * @return void
     */
    public function testWarnsAboutAnUnresolvedGranteeType(): void
    {
        DB::table('authorizable_roles')->insert(['role_id' => Role::create(['name' => 'editor'])->id, 'authorizable_type' => 'unmapped_type', 'authorizable_id' => '1']);

        self::assertSame(0, Artisan::call('authorization:prune'));
        self::assertStringContainsString('Grantee type \'unmapped_type\' names no model class; its grants were left.', Artisan::output());
        self::assertSame(1, DB::table('authorizable_roles')->count());
    }

    /**
     * A chunk that is not a whole number of at least one is refused.
     *
     * @return void
     */
    public function testRefusesAnInvalidChunk(): void
    {
        foreach (['0', 'many', '-3'] as $chunk) {
            self::assertSame(2, Artisan::call('authorization:prune', ['--chunk' => $chunk]));
            self::assertSame("The chunk must be a whole number of at least 1.\n", Artisan::output());
        }
    }
}
