<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Models\Policy;
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
            'id'         => '01JPOLBAD0000000000000002',
            'name'       => 'bad-doc-scalar',
            'document'   => 'null',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $policy = Policy::findOrFail('01JPOLBAD0000000000000002');

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
            'id'         => '01JPOLBAD0000000000000001',
            'name'       => 'corrupted',
            'document'   => \json_encode(['statements' => [['effect' => 'bogus', 'actions' => ['x']]]]),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $policy = Policy::findOrFail('01JPOLBAD0000000000000001');

        $this->expectException(InvalidPolicyDocumentException::class);

        $policy->toEvaluationPolicy();
    }
}
