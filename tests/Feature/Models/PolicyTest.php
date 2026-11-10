<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Context\DeclaredContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\PolicyValidator;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Support\DeclaredActionCatalogue;
use SineMacula\Laravel\Authorization\Support\PolicyDocument;
use Tests\Feature\Stubs\Enums\CataloguePermission;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;

/**
 * Feature tests for the string casts on the shipped `Policy` model, its tenant
 * and owner relations, the name it gives the evaluation policy it hydrates, and
 * the policy validator its `document` attribute writes through.
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
        self::assertTrue($tenant->is($owned->tenant()->first()));
        self::assertNull($platform->tenant);
    }

    /**
     * The owner relation resolves the grantee an inline policy belongs to, and
     * nothing for a managed one.
     *
     * @return void
     */
    public function testOwnerRelationResolvesTheGranteeOfAnInlinePolicy(): void
    {
        $user     = StubIdentity::create(['id' => 'user-1']);
        $document = ['version' => 1, 'statements' => []];
        $inline   = Policy::query()->create(['name' => 'mine', 'document' => $document, 'owner_type' => $user->getMorphClass(), 'owner_id' => 'user-1']);
        $managed  = Policy::query()->create(['name' => 'shared', 'document' => $document]);

        self::assertTrue($user->is($inline->owner));
        self::assertTrue($user->is($inline->owner()->first()));
        $eager = Policy::query()->with('owner')->whereKey($inline->getKey())->sole()->getRelation('owner');

        self::assertInstanceOf(Model::class, $eager);
        self::assertTrue($user->is($eager));
        self::assertNull($managed->owner);
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
     * Writing a statement without an effect is refused through the policy
     * validator, naming the policy and the fault.
     *
     * @return void
     */
    public function testWritingAnInvalidStatementIsRefused(): void
    {
        $this->expectRefusal('Invalid policy document \'readers\': Policy statement requires a string effect.');

        self::write(['statements' => [['actions' => ['posts:create']]]]);
    }

    /**
     * Writing a condition key the context key catalogue does not declare is
     * refused through the policy validator.
     *
     * @return void
     */
    public function testWritingAnUndeclaredConditionKeyIsRefused(): void
    {
        $this->app?->instance(ContextKeyCatalogue::class, new DeclaredContextKeyCatalogue);

        $this->expectRefusal('Invalid policy document \'readers\': Policy statement #0 condition key \'1bad\' is not a declared context key; ' . PolicyValidator::DECLARE_KEYS);

        self::write(['statements' => [['effect' => 'allow', 'actions' => ['posts:create'], 'conditions' => ['eq' => ['1bad' => 'x']]]]]);
    }

    /**
     * Writing a document over a configured limit is refused through the policy
     * validator.
     *
     * @return void
     */
    public function testWritingADocumentOverALimitIsRefused(): void
    {
        $this->config()->set('authorization.policies.limits.statements', 1);

        $this->expectRefusal('Invalid policy document \'readers\': Policy document has 2 statements, more than the 1 allowed.');

        self::write(['statements' => [['effect' => 'allow', 'actions' => ['posts:create']], ['effect' => 'deny', 'actions' => ['posts:delete']]]]);
    }

    /**
     * Writing a document whose action no declared permission matches is refused
     * through the policy validator and the bound action catalogue.
     *
     * @return void
     */
    public function testWritingADocumentNamingAnUndeclaredActionIsRefused(): void
    {
        $this->config()->set('authorization.permission_enums', [CataloguePermission::class]);

        $this->app?->instance(ActionCatalogue::class, $this->app->make(DeclaredActionCatalogue::class));

        $this->expectRefusal('Invalid policy document \'readers\': Policy statement #0 actions pattern \'comments:create\' matches no declared permission.');

        self::write(['statements' => [['effect' => 'allow', 'actions' => ['comments:create']]]]);
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
        return ['name', 'description', 'tenant_type', 'tenant_id', 'owner_type', 'owner_id'];
    }

    /**
     * Expect the write to be refused with the message.
     *
     * @param  string  $message
     * @return void
     */
    private function expectRefusal(string $message): void
    {
        $this->expectException(InvalidPolicyDocumentException::class);
        $this->expectExceptionMessage($message);
    }

    /**
     * Assign the document to a policy named `readers`.
     *
     * @param  array<string, mixed>  $document
     * @return void
     */
    private static function write(array $document): void
    {
        (new Policy(['name' => 'readers']))->setAttribute('document', $document);
    }

    /**
     * Return the configuration repository.
     *
     * @return \Illuminate\Config\Repository
     */
    private function config(): ConfigRepository
    {
        /** @var \Illuminate\Config\Repository */
        return $this->app?->make(ConfigRepository::class);
    }
}
