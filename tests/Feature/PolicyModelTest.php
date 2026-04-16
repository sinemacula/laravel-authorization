<?php

declare(strict_types = 1);

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Observers\PolicyObserver;
use Tests\TestCase;

/**
 * Feature tests for the policy Eloquent model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
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
            'id'       => '01J00000000000000000POL10',
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

        $evaluation = $fresh->toEvaluationPolicy();
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
            'id'       => '01J00000000000000000POL11',
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
            'id'       => '01J00000000000000000POL12',
            'name'     => 'json-string',
            'document' => $json,
        ]);

        self::assertCount(1, $policy->toEvaluationPolicy()->statements);
    }
}
