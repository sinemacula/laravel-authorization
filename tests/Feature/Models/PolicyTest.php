<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Support\PolicyDocument;
use Tests\Feature\Stubs\StubTenant;

/**
 * Feature tests for the string casts on the shipped `Policy` model, its tenant
 * relation, and the name it gives the evaluation policy it hydrates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Policy::class)]
final class PolicyTest extends StringCastsTestCase
{
    /**
     * The tenant relation resolves the tenant that owns the policy, and nothing
     * for a platform-wide one.
     *
     * @return void
     */
    public function testTenantRelationResolvesTheOwningTenant(): void
    {
        $tenant = StubTenant::query()->create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        $document = ['version' => 1, 'statements' => []];
        $owned    = Policy::query()->create(['name' => 'readers', 'document' => $document, 'tenant_type' => $tenant->getMorphClass(), 'tenant_id' => 'tenant-a']);
        $platform = Policy::query()->create(['name' => 'readers', 'document' => $document]);

        self::assertTrue($tenant->is($owned->tenant));
        self::assertNull($platform->tenant);
    }

    /**
     * Hydration names the evaluation policy after the model, even when the
     * stored document carries a name of its own.
     *
     * @return void
     */
    public function testToEvaluationPolicyNamesThePolicyAfterTheModel(): void
    {
        $policy = Policy::create([
            'id'       => 'c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e01',
            'name'     => 'stored-name',
            'document' => [
                'name'       => 'document-name',
                'statements' => [['effect' => 'allow', 'actions' => ['posts:create']]],
            ],
        ]);

        $fresh = $policy->fresh();

        self::assertNotNull($fresh);
        self::assertSame('document-name', $fresh->document['name'] ?? null);
        self::assertSame('stored-name', PolicyDocument::hydrate($fresh)->name);
    }

    /**
     * Hydration keeps the document's own name when the model has none, or only
     * an empty one.
     *
     * @return void
     */
    public function testToEvaluationPolicyKeepsTheDocumentNameWhenTheModelHasNone(): void
    {
        $document = \json_encode([
            'name'       => 'document-name',
            'statements' => [['effect' => 'allow', 'actions' => ['posts:create']]],
        ]);

        foreach (['missing' => [], 'empty' => ['name' => '']] as $label => $attributes) {
            $policy = new Policy;

            $policy->setRawAttributes($attributes + ['document' => $document]);

            self::assertSame('document-name', PolicyDocument::hydrate($policy)->name, $label);
        }
    }

    /**
     * A malformed document on a policy without a name raises the invalid policy
     * document exception under the unnamed placeholder, never a type error, so
     * the check still denies.
     *
     * @return void
     */
    public function testToEvaluationPolicyReportsAnUnnamedMalformedDocument(): void
    {
        $policy = new Policy;

        $policy->setRawAttributes(['document' => \json_encode(['statements' => 'not-a-list'])]);

        try {
            PolicyDocument::hydrate($policy);

            self::fail('A malformed document must raise an invalid policy document exception.');
        } catch (InvalidPolicyDocumentException $exception) {
            self::assertSame('[unnamed]', $exception->getPolicyName());
            self::assertSame('Invalid policy document \'[unnamed]\': Policy document requires a non-empty name.', $exception->getMessage());
        }
    }

    /**
     * Create an instance of the model under test.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    #[\Override]
    protected static function newModel(): Model
    {
        return new Policy;
    }

    /**
     * Return the model's fillable string columns.
     *
     * @return list<string>
     */
    #[\Override]
    protected static function stringColumns(): array
    {
        return ['name', 'description', 'tenant_type', 'tenant_id'];
    }
}
