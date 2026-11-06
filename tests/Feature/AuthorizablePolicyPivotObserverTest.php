<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\InlinePolicyAttachmentException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Observers\AuthorizablePolicyPivotObserver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the refusal of an inline policy written through a grantee's
 * `policies()` relation to a grantee it does not belong to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AuthorizablePolicyPivotObserver::class)]
final class AuthorizablePolicyPivotObserverTest extends TestCase
{
    /**
     * The relation attaches a grantee's own inline policy, and a managed
     * policy, as any write would.
     *
     * @return void
     */
    public function testTheRelationAttachesOwnAndManagedPolicies(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $inline  = $user->createInlinePolicy('mine', self::document());
        $managed = Policy::create(['name' => 'shared', 'document' => self::document()]);

        $user->policies()->attach($inline->id);
        $user->policies()->attach($managed->id);

        self::assertEqualsCanonicalizing([$inline->id, $managed->id], DB::table('authorizable_policies')->pluck('policy_id')->all());
    }

    /**
     * Attaching or syncing another grantee's inline policy through the
     * relation, to an identity or a role, is refused and writes nothing.
     *
     * @return void
     */
    public function testTheRelationRefusesAnotherGranteesInlinePolicy(): void
    {
        $owner  = StubIdentity::create(['id' => 'user-1']);
        $other  = StubIdentity::create(['id' => 'user-2']);
        $role   = Role::create(['name' => 'editor']);
        $inline = $owner->createInlinePolicy('mine', self::document());

        $writes = [
            'attach to another identity' => static fn () => $other->policies()->attach($inline->id),
            'sync to another identity'   => static fn () => $other->policies()->sync([$inline->id]),
            'attach to a role'           => static fn () => $role->policies()->attach($inline->id),
        ];

        foreach ($writes as $write => $refused) {
            try {
                $refused();
                self::fail("The relation allowed the write: {$write}.");
            } catch (InlinePolicyAttachmentException $exception) {
                self::assertSame('mine', $exception->getPolicyName(), $write);
            }
        }

        self::assertSame(0, DB::table('authorizable_policies')->count());
    }

    /**
     * A row naming no policy is left to the foreign key, which refuses it.
     *
     * @return void
     */
    public function testARowNamingNoPolicyIsLeftToTheForeignKey(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $this->expectException(QueryException::class);

        DB::transaction(static fn () => $user->policies()->attach('00000000-0000-0000-0000-000000000000'));
    }

    /**
     * Return a minimal valid policy document.
     *
     * @return array<string, mixed>
     */
    private static function document(): array
    {
        return ['version' => 1, 'statements' => []];
    }
}
