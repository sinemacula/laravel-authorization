<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance;
use SineMacula\Laravel\Authorization\Evaluation\ExplanationRequest;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for the explanation request value object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExplanationRequest::class)]
final class ExplanationRequestTest extends TestCase
{
    /**
     * toArray() names the action, the resource, who the check was about and who
     * previewed it, from the scope it was decided in, and both scopes.
     *
     * @return void
     */
    public function testToArray(): void
    {
        $user      = new Reference('user', '1');
        $person    = new Reference('person', '2');
        $auditor   = new Reference('user', '9');
        $requested = new DecisionProvenance($user, $person, $auditor, new Reference('team', 'a'), 'web');
        $decided   = new DecisionProvenance($user, $person, $auditor, new Reference('team', 'b'), null);
        $request   = new ExplanationRequest('posts:read', 'posts:7', $requested, $decided);

        self::assertSame([
            'action'          => 'posts:read',
            'resource'        => 'posts:7',
            'subject'         => ['type' => 'user', 'id' => '1'],
            'identity'        => ['type' => 'person', 'id' => '2'],
            'previewer'       => ['type' => 'user', 'id' => '9'],
            'requested_scope' => ['tenant' => ['type' => 'team', 'id' => 'a'], 'application' => 'web'],
            'decision_scope'  => ['tenant' => ['type' => 'team', 'id' => 'b'], 'application' => null],
        ], $request->toArray());
    }

    /**
     * A check about no saved subject, on no resource, at platform scope,
     * renders each as null.
     *
     * @return void
     */
    public function testToArrayWithNothingNamed(): void
    {
        $request = new ExplanationRequest('posts:read', null, new DecisionProvenance, new DecisionProvenance);
        $array   = $request->toArray();

        self::assertNull($array['resource']);
        self::assertNull($array['subject']);
        self::assertNull($array['identity']);
        self::assertNull($array['previewer']);
        self::assertSame(['tenant' => null, 'application' => null], $array['decision_scope']);
    }
}
