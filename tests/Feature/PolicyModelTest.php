<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Context\DeclaredContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\PolicyValidator;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Observers\PolicyObserver;
use SineMacula\Laravel\Authorization\Support\DeclaredActionCatalogue;
use SineMacula\Laravel\Authorization\Support\PolicyDocument;
use Tests\Feature\Stubs\EmptyActionCatalogue;
use Tests\Feature\Stubs\Enums\CataloguePermission;
use Tests\TestCase;

/**
 * Feature tests for the policy Eloquent model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(Policy::class)]
#[CoversClass(PolicyObserver::class)]
final class PolicyModelTest extends TestCase
{
    /**
     * Round-trip a policy through the database.
     *
     * @return void
     */
    public function testRoundTripsThroughDatabase(): void
    {
        $policy = Policy::create([
            'id'       => 'f5a39899-959b-462f-8ab2-faf25b8e31db',
            'name'     => 'full-round-trip',
            'document' => [
                'statements' => [
                    [
                        'effect'    => 'allow',
                        'actions'   => ['posts:*'],
                        'resources' => ['arn:posts:*'],
                    ],
                ],
            ],
        ]);

        $fresh = $policy->fresh();
        self::assertNotNull($fresh);

        $evaluation = PolicyDocument::hydrate($fresh);
        self::assertSame('full-round-trip', $evaluation->name);
        self::assertCount(1, $evaluation->statements);
        self::assertSame(PolicyEffect::ALLOW, $evaluation->statements[0]->effect);
    }

    /**
     * Invalid documents are rejected at write time.
     *
     * @return void
     */
    public function testRejectsInvalidDocumentOnWrite(): void
    {
        $this->expectException(InvalidPolicyDocumentException::class);

        Policy::create([
            'id'       => 'bf46448c-09ea-46f7-8e60-0f2ab3bb57ca',
            'name'     => 'bad',
            'document' => ['statements' => [['effect' => 'audit', 'actions' => ['x']]]],
        ]);
    }

    /**
     * Raw JSON strings are accepted and parsed.
     *
     * @return void
     */
    public function testAcceptsJsonStringDocument(): void
    {
        $json = \json_encode([
            'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]],
        ]);
        self::assertIsString($json);

        $policy = Policy::create([
            'id'       => 'f8c6e7d0-ea9f-473c-8ed7-f51e299466f1',
            'name'     => 'json-string',
            'document' => $json,
        ]);

        self::assertCount(1, PolicyDocument::hydrate($policy)->statements);
    }

    /**
     * A document over a limit is refused at write time.
     *
     * @return void
     */
    public function testRejectsADocumentOverALimitOnWrite(): void
    {
        $this->config()->set('authorization.policies.limits.statements', 1);

        $this->expectException(InvalidPolicyDocumentException::class);
        $this->expectExceptionMessage('Invalid policy document \'wide\': Policy document has 2 statements, more than the 1 allowed.');

        Policy::create(['name' => 'wide', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['a']], ['effect' => 'allow', 'actions' => ['b']]]]]);
    }

    /**
     * Every document is refused at write time when the catalogue declares no
     * action at all.
     *
     * @return void
     */
    public function testRejectsEveryWriteWhenNoActionIsDeclared(): void
    {
        $this->app?->instance(ActionCatalogue::class, new EmptyActionCatalogue);

        $this->expectExceptionMessage('Invalid policy document \'readers\': ' . PolicyValidator::NOTHING_DECLARED);

        Policy::create(['name' => 'readers', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:create']]]]]);
    }

    /**
     * A document naming only declared actions is written, and one naming an
     * action the code does not declare is refused at write time.
     *
     * @return void
     */
    public function testRejectsAnUndeclaredActionOnWrite(): void
    {
        $this->config()->set('authorization.permission_enums', [CataloguePermission::class]);
        $this->app?->instance(ActionCatalogue::class, $this->app->make(DeclaredActionCatalogue::class));

        self::assertTrue(Policy::create(['name' => 'readers', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:*']]]]])->exists);

        $this->expectExceptionMessage('Invalid policy document \'writers\': Policy statement #0 actions pattern \'posts:delete\' matches no declared permission.');

        Policy::create(['name' => 'writers', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:delete']]]]]);
    }

    /**
     * A condition key the context key catalogue does not declare, such as one
     * outside the key syntax, is refused at write time.
     *
     * @return void
     */
    public function testRejectsAnUndeclaredConditionKeyOnWrite(): void
    {
        $this->app?->instance(ContextKeyCatalogue::class, new DeclaredContextKeyCatalogue);

        $this->expectExceptionMessage('Invalid policy document \'keyed\': Policy statement #0 condition key \'request ip\' is not a declared context key');

        Policy::create(['name' => 'keyed', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['a'], 'conditions' => ['eq' => ['request ip' => 'x']]]]]]);
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
