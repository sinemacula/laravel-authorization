<?php

declare(strict_types = 1);

namespace Tests\Feature\Support;

use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;
use SineMacula\Laravel\Authorization\Support\TenantColumns;
use Tests\Feature\Stubs\RecordingLogger;
use Tests\TestCase;

/**
 * Feature tests for the pair of tenant columns a stored row holds, read as the
 * package fails closed on a row naming half a tenant (N130): what grants of it
 * applies nowhere, what restricts of it everywhere, and an attachment of it, or
 * of a policy naming half a tenant, counts for its denies alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantColumns::class)]
final class TenantColumnsTest extends TestCase
{
    /** @var array<string, array{string|null, string|null}> The tenant columns each row is stored with, by its grantee's key. */
    private const array ROWS = [
        'platform' => [null, null],
        'o1'       => ['tenant', 'o1'],
        'o2'       => ['tenant', 'o2'],
        'no-type'  => [null, 'o1'],
        'no-key'   => ['tenant', null],
    ];

    /**
     * Tenant columns name half a tenant when exactly one of them is null; an
     * attachment counts for its denies alone when it, or its policy, does.
     *
     * @return void
     */
    public function testHalfATenantIsOneColumnWithoutTheOther(): void
    {
        self::assertFalse(TenantColumns::isHalf(null, null));
        self::assertFalse(TenantColumns::isHalf('tenant', 'o1'));
        self::assertTrue(TenantColumns::isHalf(null, 'o1'));
        self::assertTrue(TenantColumns::isHalf('tenant', null));

        $whole = new Policy(['tenant_type' => 'tenant', 'tenant_id' => 'o1']);
        $half  = new Policy(['tenant_type' => null, 'tenant_id' => 'o1']);

        self::assertFalse(TenantColumns::isDenyOnly(null, null));
        self::assertFalse(TenantColumns::isDenyOnly('tenant', 'o1', $whole));
        self::assertTrue(TenantColumns::isDenyOnly(null, 'o1', $whole));
        self::assertTrue(TenantColumns::isDenyOnly('tenant', null));
        self::assertTrue(TenantColumns::isDenyOnly(null, null, $half));
        self::assertTrue(TenantColumns::isDenyOnly('tenant', 'o1', new Policy(['tenant_type' => 'tenant', 'tenant_id' => null])));
    }

    /**
     * Rows naming half a tenant are kept alone, or added to what the query
     * already keeps.
     *
     * @return void
     */
    public function testRowsNamingHalfATenantAreKeptOrAdded(): void
    {
        self::rows();

        $query = DB::table('authorizable_boundaries');

        self::assertSame($query, TenantColumns::whereHalf($query, 'tenant_type', 'tenant_id'));
        self::assertEqualsCanonicalizing(['no-type', 'no-key'], $query->pluck('authorizable_id')->all());

        $added = TenantColumns::whereHalf(DB::table('authorizable_boundaries')->where('authorizable_id', 'o1'), 'tenant_type', 'tenant_id', 'or');

        self::assertEqualsCanonicalizing(['o1', 'no-type', 'no-key'], $added->pluck('authorizable_id')->all());
    }

    /**
     * What restricts holds where the chain reads it and, naming half a tenant,
     * everywhere: a boundary by its grant; a guardrail by its owner, read as
     * the queries united with the chain's own, each half on its own, or the two
     * halves alone.
     *
     * @return void
     */
    public function testWhatRestrictsNamingHalfATenantHoldsEverywhere(): void
    {
        self::rows();

        $chains = ['platform' => new TenantChain, 'o1' => new TenantChain([new Reference('tenant', 'o1')])];
        $read   = static fn (): Builder => DB::table('guardrails')->select(['tenant_type', 'tenant_id']);
        $pairs  = static fn (Builder $query): array => $query->get()->map(static fn (object $row): array => \array_values((array) $row))->all();

        foreach ($chains as $name => $chain) {
            $place      = $name === 'platform' ? ['platform'] : ['platform', 'o1'];
            $boundaries = DB::table('authorizable_boundaries');
            $guardrails = $chain->owners($read(), 'tenant_type', 'tenant_id');

            self::assertSame($boundaries, TenantColumns::restricting($chain, $boundaries, 'authorizable_boundaries'));
            self::assertSame($guardrails, TenantColumns::unionHalf($guardrails, $read, 'tenant_type', 'tenant_id'));
            self::assertEqualsCanonicalizing([...$place, 'no-type', 'no-key'], $boundaries->pluck('authorizable_id')->all(), $name);
            self::assertCount(\count($place) + 2, $pairs($guardrails), $name);
        }

        self::assertSame([[null, 'o1'], ['tenant', null]], $pairs(TenantColumns::halves($read, 'tenant_type', 'tenant_id')));
    }

    /**
     * Policy attachments are read where the chain reads them, and, in every
     * scope, those whose denies alone count: one naming half a tenant, and any
     * attachment of a policy naming half a tenant.
     *
     * @return void
     */
    public function testAttachmentsWhoseDeniesAloneCountAreReadInEveryScope(): void
    {
        self::rows();

        $owned = Policy::create(['name' => 'owned', 'document' => ['statements' => []]]);

        $grantee = ['authorizable_type' => 'stub_identity', 'authorizable_id' => 'owned'];

        DB::table('authorizable_policies')->insert(['policy_id' => $owned->getKey(), ...$grantee, 'tenant_type' => 'tenant', 'tenant_id' => 'o2']);
        DB::table('policies')->where('id', $owned->getKey())->update(['tenant_type' => null, 'tenant_id' => 'o2']);

        $denied = DB::table('authorizable_policies');

        self::assertSame($denied, TenantColumns::whereDenyOnly($denied, 'authorizable_policies'));
        self::assertEqualsCanonicalizing(['no-type', 'no-key', 'owned'], $denied->pluck('authorizable_id')->all());

        $added = TenantColumns::whereDenyOnly(DB::table('authorizable_policies')->where('authorizable_id', 'o1'), 'authorizable_policies', 'or');

        self::assertEqualsCanonicalizing(['o1', 'no-type', 'no-key', 'owned'], $added->pluck('authorizable_id')->all());

        $read = DB::table('authorizable_policies');

        self::assertSame($read, TenantColumns::attachments(new TenantChain([new Reference('tenant', 'o1')]), $read, 'authorizable_policies'));
        self::assertEqualsCanonicalizing(['platform', 'o1', 'no-type', 'no-key', 'owned'], $read->pluck('authorizable_id')->all());
        self::assertEqualsCanonicalizing(
            ['platform', 'no-type', 'no-key', 'owned'],
            TenantColumns::attachments(new TenantChain, DB::table('authorizable_policies'), 'authorizable_policies')->pluck('authorizable_id')->all(),
        );
    }

    /**
     * Tenant columns naming half a tenant are described as malformed, as
     * stored, and the removal of a row stored that way is written to the log
     * so, with the columns as stored, once the package connection's transaction
     * commits: a removal rolled back is never written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARowNamingHalfATenantIsReportedAsMalformed(): void
    {
        $logger = new RecordingLogger;

        $this->app?->instance('log', $logger);

        self::assertSame('malformed (tenant_type=null, tenant_id=o1)', TenantColumns::malformed(null, 'o1'));
        self::assertSame('malformed (tenant_type=tenant, tenant_id=null)', TenantColumns::malformed('tenant', null));
        self::assertSame('malformed (tenant_type=tenant, tenant_id=7)', TenantColumns::malformed('tenant', 7));

        try {
            DB::transaction(static function (): never {
                TenantColumns::reportRemoved('a guardrail', 'tenant', null);

                throw new \RuntimeException('rolled back');
            });
        } catch (\RuntimeException) {
            // The removal was rolled back.
        }

        self::assertSame([], $logger->records);

        DB::transaction(static function () use ($logger): void {
            TenantColumns::reportRemoved('a boundary', null, 'o1', ['policy_id' => 'p']);

            self::assertSame([], $logger->records);
        });

        self::assertSame([[
            'level'   => 'warning',
            'message' => 'Authorization: removed a boundary naming half a tenant, malformed (tenant_type=null, tenant_id=o1).',
            'context' => ['policy_id' => 'p', 'tenant_type' => null, 'tenant_id' => 'o1'],
        ]], $logger->records);
    }

    /**
     * Store a boundary, a guardrail and a policy attachment of one policy for
     * each pair of tenant columns, the grantee named by the pair's name, and
     * return the policy's key.
     *
     * @return string
     */
    private static function rows(): string
    {
        $policy = Policy::create(['name' => 'rows', 'document' => ['statements' => []]]);
        $key    = (string) $policy->getKey(); // @phpstan-ignore cast.string

        foreach (self::ROWS as $name => [$type, $id]) {
            $columns = ['policy_id' => $key, 'tenant_type' => $type, 'tenant_id' => $id];
            $grantee = ['authorizable_type' => 'stub_identity', 'authorizable_id' => $name, 'include_subtree' => true];

            DB::table('authorizable_boundaries')->insert([...$columns, ...$grantee]);
            DB::table('authorizable_policies')->insert([...$columns, ...$grantee]);
            DB::table('guardrails')->insert($columns);
        }

        return $key;
    }
}
