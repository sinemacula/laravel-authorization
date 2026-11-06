<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Illuminate\Database\Eloquent\Attributes\ObservedBy;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\InlinePolicyAttachmentException;
use SineMacula\Laravel\Authorization\Models\Pivots\AuthorizablePolicyPivot;
use SineMacula\Laravel\Authorization\Observers\AuthorizablePolicyPivotObserver;
use Tests\Concerns\CatchesRefusals;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the policy attachment pivot, which the observer refusing an
 * inline policy to any grantee but its own watches.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizablePolicyPivot::class)]
final class AuthorizablePolicyPivotTest extends TestCase
{
    use CatchesRefusals;

    /**
     * The pivot is observed by the inline policy observer, so a row saved
     * through it for another grantee is refused.
     *
     * @return void
     */
    public function testThePivotIsWatchedForInlinePolicies(): void
    {
        $attributes = (new \ReflectionClass(AuthorizablePolicyPivot::class))->getAttributes(ObservedBy::class);

        self::assertCount(1, $attributes);
        self::assertSame([AuthorizablePolicyPivotObserver::class], $attributes[0]->getArguments());

        $owner  = StubIdentity::create(['id' => 'user-1']);
        $other  = StubIdentity::create(['id' => 'user-2']);
        $inline = $owner->createInlinePolicy('mine', ['version' => 1, 'statements' => []]);

        $refusal = self::refusalOf(static fn () => $other->policies()->attach($inline->id));

        self::assertInstanceOf(InlinePolicyAttachmentException::class, $refusal);
        self::assertSame('mine', $refusal->getPolicyName());

        self::assertSame(0, DB::table('authorizable_policies')->count());
    }
}
