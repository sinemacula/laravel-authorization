<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Console\PruneGrantsCommand;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
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
    /** @var string What the command reports it removed, after its verb. */
    private const string SUMMARY = '1 expired grant(s), 1 grant(s) of grantees that no longer exist, 1 inline polic(ies) of grantees that no longer exist'
        . ' and 1 resource polic(ies) attached to records that no longer exist.';

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
     * The command removes expired grants, the grants and inline policies of
     * grantees that are gone, and the resource policies of records that are
     * gone, and says how many; pretending says how many it would remove.
     *
     * @return void
     */
    public function testPrunesAndReports(): void
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        StubIdentity::create(['id' => 'user-1'])->assignRole(Role::create(['name' => 'editor']), Carbon::parse('2026-07-01 11:00:00'));
        $gone = StubIdentity::create(['id' => 'user-2'])->assignRole(Role::create(['name' => 'viewer']));

        $gone->createInlinePolicy('mine', ['version' => 1, 'statements' => []]);
        ResourcePolicyService::instance()?->attach(Policy::create(['name' => 'locked', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['*']]]]]), $gone);

        DB::table('stub_identities')->where('id', 'user-2')->delete();

        self::assertSame(0, Artisan::call('authorization:prune', ['--pretend' => true]));
        self::assertSame('Would prune ' . self::SUMMARY . "\n", Artisan::output());
        self::assertSame(2, DB::table('authorizable_roles')->count());

        self::assertSame(0, Artisan::call('authorization:prune', ['--chunk' => '1']));
        self::assertSame('Pruned ' . self::SUMMARY . "\n", Artisan::output());
        self::assertSame(0, DB::table('authorizable_roles')->count());
        self::assertSame(0, DB::table('resource_policies')->count());
        self::assertSame(['locked'], DB::table('policies')->pluck('name')->all());
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
        self::assertStringContainsString('Grantee type \'unmapped_type\' names no model class; its grants and inline policies were left.', Artisan::output());
        self::assertSame(1, DB::table('authorizable_roles')->count());
    }

    /**
     * A resource type that names no model class is warned about and the
     * policies attached to its records are left; a whole type's attachment
     * raises no warning.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWarnsAboutAnUnresolvedResourceType(): void
    {
        $policy  = Policy::create(['name' => 'locked', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['*']]]]]);
        $service = ResourcePolicyService::instance();

        self::assertInstanceOf(ResourcePolicyService::class, $service);

        $service->attach($policy, ['unmapped_type', 7]);
        $service->attach($policy, 'whole_type');

        self::assertSame(0, Artisan::call('authorization:prune'));

        $output = Artisan::output();

        self::assertStringContainsString('Resource type \'unmapped_type\' names no model class; the policies attached to its records were left.', $output);
        self::assertStringNotContainsString('whole_type', $output);
        self::assertSame(2, DB::table('resource_policies')->count());
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
