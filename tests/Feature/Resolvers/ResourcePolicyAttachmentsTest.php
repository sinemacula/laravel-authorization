<?php

declare(strict_types = 1);

namespace Tests\Feature\Resolvers;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyAttachments;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\TestCase;

/**
 * Feature tests for the queries resource policy attachments are read with: the
 * scope's own, and, united with them, those whose denies count in every scope,
 * an attachment naming half a tenant and any attachment of a policy naming half
 * a tenant (N130).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResourcePolicyAttachments::class)]
final class ResourcePolicyAttachmentsTest extends TestCase
{
    /**
     * The attachments to a resource are read in the scope, with what each is
     * attached to and its tenant columns, and, in every scope, those naming
     * half a tenant, either half, and those of a policy naming half a tenant,
     * in the check's application alone; another tenant's whole attachment, and
     * another type's, are not read.
     *
     * @return void
     */
    public function testTheAttachmentsToAResourceAreReadWithThoseHoldingEverywhere(): void
    {
        $made = $this->attachments();
        $read = static fn (): array => ResourcePolicyAttachments::of(new Policy, 'posts', static function (Builder $query): void {
            $query->whereNull('resource_policies.resource_id')->orWhere('resource_policies.resource_id', '7');
        })->get()->map(static fn (Policy $row): array => [
            $row->getAttribute('name'),
            $row->getAttribute(ResourcePolicyAttachments::RESOURCE_ID),
            $row->getAttribute(ResourcePolicyAttachments::TENANT_TYPE),
            $row->getAttribute(ResourcePolicyAttachments::TENANT_ID),
        ])->all();

        $expected = [
            ['type', null, null, null],
            ['in scope', '7', 'teams', '6'],
            ['key only', '7', null, 't-1'],
            ['type only', '7', 'teams', null],
            ['owned', '7', 'teams', '9'],
        ];

        self::assertNotEmpty($made);
        self::assertEqualsCanonicalizing($expected, TenantScope::within(new Reference('teams', '6'), null, $read));
        self::assertEqualsCanonicalizing([['type', null, null, null], ['key only', '7', null, 't-1'], ['type only', '7', 'teams', null], ['owned', '7', 'teams', '9']], $read());
        self::assertEqualsCanonicalizing([...$expected, ['mobile', '7', null, 't-2']], TenantScope::within(new Reference('teams', '6'), 'mobile', $read));
    }

    /**
     * The keys of the policies attached to records of a type are read in the
     * scope, and, in every scope, those attached by a row naming half a tenant
     * and those of a policy naming half a tenant, in the check's application;
     * an attachment to the whole type is not a record's.
     *
     * @return void
     */
    public function testThePoliciesAttachedToRecordsAreReadWithThoseHoldingEverywhere(): void
    {
        $made = $this->attachments();
        $text = static fn (mixed $key): string => (string) $key; // @phpstan-ignore cast.string
        $keys = static fn (): array => ResourcePolicyAttachments::onRecords(new Policy, 'posts')->pluck('policy_id')->map($text)->all();
        $ids  = static fn (string ...$names): array => \array_map(static fn (string $name): string => (string) $made[$name]->getKey(), $names); // @phpstan-ignore cast.string

        self::assertEqualsCanonicalizing($ids('in scope', 'key only', 'type only', 'owned'), TenantScope::within(new Reference('teams', '6'), null, $keys));
        self::assertEqualsCanonicalizing($ids('key only', 'type only', 'owned'), $keys());
        self::assertEqualsCanonicalizing($ids('in scope', 'key only', 'type only', 'owned', 'mobile'), TenantScope::within(new Reference('teams', '6'), 'mobile', $keys));
    }

    /**
     * Read beside each policy, the policies attached to records of the type by
     * a row naming half a tenant are told apart, in the check's application; a
     * policy naming half a tenant attached by a whole row is not one.
     *
     * @return void
     */
    public function testThePoliciesAttachedToRecordsByARowNamingHalfATenantAreToldApart(): void
    {
        $made  = $this->attachments();
        $flags = static fn (): array => Policy::query()->withoutGlobalScopes()
            ->select('name')
            ->selectSub(ResourcePolicyAttachments::halfOnRecords(new Policy, 'posts')->limit(1), 'flag')
            ->whereNotNull('id')
            ->get()
            ->filter(static fn (Policy $row): bool => $row->getAttribute('flag') !== null)
            ->map(static fn (Policy $row): mixed => $row->getAttribute('name'))
            ->values()
            ->all();

        self::assertCount(7, $made);
        self::assertEqualsCanonicalizing(['key only', 'type only'], $flags());
        self::assertEqualsCanonicalizing(['key only', 'type only', 'mobile'], TenantScope::within(null, 'mobile', $flags));
    }

    /**
     * Store a policy attached to `posts:7` in each of the ways read, and to the
     * whole type and another type, and return each by its name.
     *
     * @return array<string, \SineMacula\Laravel\Authorization\Models\Policy>
     */
    private function attachments(): array
    {
        $rows = [
            'type'         => ['resource_id' => null, 'tenant_type' => null, 'tenant_id' => null],
            'in scope'     => ['tenant_type' => 'teams', 'tenant_id' => '6'],
            'other tenant' => ['tenant_type' => 'teams', 'tenant_id' => '8'],
            'key only'     => ['tenant_type' => null, 'tenant_id' => 't-1'],
            'type only'    => ['tenant_type' => 'teams', 'tenant_id' => null],
            'owned'        => ['tenant_type' => 'teams', 'tenant_id' => '9'],
            'mobile'       => ['tenant_type' => null, 'tenant_id' => 't-2', 'application' => 'mobile'],
        ];

        $made = [];

        foreach ($rows as $name => $columns) {
            $made[$name] = Policy::create(['name' => $name, 'document' => ['statements' => []]]);

            DB::table('resource_policies')->insert(['policy_id' => $made[$name]->getKey(), 'resource_type' => 'posts', 'resource_id' => '7', ...$columns]);
        }

        $other = ['resource_type' => 'comments', 'resource_id' => '7', 'tenant_type' => null, 'tenant_id' => 't-1'];

        DB::table('resource_policies')->insert(['policy_id' => $made['in scope']->getKey(), ...$other]);
        DB::table('policies')->where('id', $made['owned']->getKey())->update(['tenant_type' => null, 'tenant_id' => 't-3']);

        return $made;
    }
}
