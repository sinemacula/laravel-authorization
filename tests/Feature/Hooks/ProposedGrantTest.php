<?php

declare(strict_types = 1);

namespace Tests\Feature\Hooks;

use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Enums\WideningReason;
use SineMacula\Laravel\Authorization\Hooks\ProposedGrant;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\TestCase;

/**
 * Unit tests for `ProposedGrant`, one grant a call proposes, as a grant hook
 * sees it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProposedGrant::class)]
final class ProposedGrantTest extends TestCase
{
    /**
     * A proposal of a model names the kind's grant action, the target by
     * reference, the scope, and the expiry as an immutable instant in UTC, with
     * no reasons yet.
     *
     * @return void
     */
    public function testAProposalOfAModelIsAnImmutableValue(): void
    {
        $role = new Role;

        $role->setRawAttributes(['id' => 'role-1'], true);

        $expiresAt = Carbon::parse('2030-01-02 03:04:05', 'Europe/Paris');
        $proposal  = ProposedGrant::of(GrantTarget::ROLE, $role, new GrantScope(new Reference('tenant', 'a'), 'admin', false), $expiresAt);

        self::assertSame('authorization:role.grant', $proposal->action);
        self::assertSame([$role->getMorphClass(), 'role-1'], [$proposal->target->type, $proposal->target->id]);
        self::assertSame('a', $proposal->tenant?->id);
        self::assertSame('admin', $proposal->application);
        self::assertFalse($proposal->includeSubtree);
        self::assertInstanceOf(\DateTimeImmutable::class, $proposal->expiresAt);
        self::assertSame('2030-01-02 02:04:05 UTC', $proposal->expiresAt->format('Y-m-d H:i:s T'));
        self::assertSame([], $proposal->reasons);

        $expiresAt->addYear();

        self::assertSame('2030-01-02 02:04:05 UTC', $proposal->expiresAt->format('Y-m-d H:i:s T'));
        self::assertNull(ProposedGrant::of(GrantTarget::ROLE, $role, GrantScope::platform(), null)->expiresAt);
    }

    /**
     * The reasons are added to a copy, and the key tells grants apart by
     * everything they propose, never by their reasons.
     *
     * @return void
     */
    public function testTheKeyIgnoresTheReasons(): void
    {
        $proposal = new ProposedGrant('authorization:role.grant', new Reference('roles', '1'), new Reference('tenant', 'a'), null, true, new \DateTimeImmutable('@100'));
        $reasoned = $proposal->withReasons([WideningReason::NEW_TENANT]);

        self::assertSame([], $proposal->reasons);
        self::assertSame([WideningReason::NEW_TENANT], $reasoned->reasons);
        self::assertSame($proposal->key(), $reasoned->key());
        self::assertSame([$proposal->target, $proposal->tenant, $proposal->expiresAt], [$reasoned->target, $reasoned->tenant, $reasoned->expiresAt]);

        $variants = [
            new ProposedGrant('authorization:permission.grant', new Reference('roles', '1'), new Reference('tenant', 'a'), null, true, new \DateTimeImmutable('@100')),
            new ProposedGrant('authorization:role.grant', new Reference('other', '1'), new Reference('tenant', 'a'), null, true, new \DateTimeImmutable('@100')),
            new ProposedGrant('authorization:role.grant', new Reference('roles', '2'), new Reference('tenant', 'a'), null, true, new \DateTimeImmutable('@100')),
            new ProposedGrant('authorization:role.grant', new Reference('roles', '1'), new Reference('other', 'a'), null, true, new \DateTimeImmutable('@100')),
            new ProposedGrant('authorization:role.grant', new Reference('roles', '1'), new Reference('tenant', 'b'), null, true, new \DateTimeImmutable('@100')),
            new ProposedGrant('authorization:role.grant', new Reference('roles', '1'), null, null, true, new \DateTimeImmutable('@100')),
            new ProposedGrant('authorization:role.grant', new Reference('roles', '1'), new Reference('tenant', 'a'), 'admin', true, new \DateTimeImmutable('@100')),
            new ProposedGrant('authorization:role.grant', new Reference('roles', '1'), new Reference('tenant', 'a'), null, false, new \DateTimeImmutable('@100')),
            new ProposedGrant('authorization:role.grant', new Reference('roles', '1'), new Reference('tenant', 'a'), null, true, new \DateTimeImmutable('@101')),
            new ProposedGrant('authorization:role.grant', new Reference('roles', '1'), new Reference('tenant', 'a'), null, true, null),
        ];

        foreach ($variants as $index => $variant) {
            self::assertNotSame($proposal->key(), $variant->key(), "variant {$index}");
        }
    }
}
