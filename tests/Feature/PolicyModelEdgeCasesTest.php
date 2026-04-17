<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Observers\PolicyObserver;
use Tests\TestCase;

/**
 * Coverage for the `Policy` model's two edge-case branches:
 *
 * - `normaliseDocument()` rejects values that are neither an array
 *   nor a JSON-decodable non-empty string — an operator setting the
 *   raw attribute to an integer hits this.
 * - `toEvaluationPolicy()` wraps read-time failures in a typed
 *   exception when the persisted row was written through a raw
 *   insert that bypassed the mutator. Consumers invoking the
 *   method on a polluted row get a deterministic failure surface.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Policy::class)]
#[CoversClass(PolicyObserver::class)]
#[CoversClass(InvalidPolicyDocumentException::class)]
final class PolicyModelEdgeCasesTest extends TestCase
{
    /**
     * An empty JSON string value is neither an array nor a parseable
     * JSON string — `normaliseDocument()` rejects it with the typed
     * exception rather than hydrating an evaluation policy from a
     * non-object payload.
     *
     * @return void
     */
    public function testNonArrayNonJsonDocumentIsRejected(): void
    {
        DB::table('policies')->insert([
            'id'         => 'a6b38f42-3129-4279-8eea-f0b718f94a76',
            'name'       => 'bad-doc-scalar',
            'document'   => 'null',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $policy = Policy::findOrFail('a6b38f42-3129-4279-8eea-f0b718f94a76');

        $this->expectException(InvalidPolicyDocumentException::class);

        $policy->toEvaluationPolicy();
    }

    /**
     * A row whose `document` column was written through a raw
     * insert can contain bytes that fail at read time —
     * `toEvaluationPolicy()` wraps the inner failure in a typed
     * exception so callers can handle the failure uniformly.
     *
     * @return void
     */
    public function testToEvaluationPolicyWrapsReadTimeFailures(): void
    {
        DB::table('policies')->insert([
            'id'         => '55ca4f44-7257-4d16-8870-8e1c550b3f88',
            'name'       => 'corrupted',
            'document'   => \json_encode(['statements' => [['effect' => 'bogus', 'actions' => ['x']]]]),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $policy = Policy::findOrFail('55ca4f44-7257-4d16-8870-8e1c550b3f88');

        $this->expectException(InvalidPolicyDocumentException::class);

        $policy->toEvaluationPolicy();
    }
}
