<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Models\BreakGlassActivation;
use Tests\Concerns\ActivatesBreakGlass;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the break-glass activation model: its table and connection
 * as the configuration names them, a UUID key, no timestamps of its own, every
 * instant kept in UTC whatever zone it is given in, the reach a boolean, and
 * the note, personal data, hidden from its array and JSON forms.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BreakGlassActivation::class)]
final class BreakGlassActivationTest extends TestCase
{
    use ActivatesBreakGlass;

    /**
     * The model reads the table the configuration names, prefix included, on
     * the package's connection.
     *
     * @return void
     */
    public function testItReadsTheConfiguredTableOnThePackagesConnection(): void
    {
        self::assertSame('break_glass_activations', (new BreakGlassActivation)->getTable());
        self::assertSame(DB::connection()->getName(), (new BreakGlassActivation)->getConnectionName());

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('authorization.tables.prefix', 'app_');

        self::assertSame('app_break_glass_activations', (new BreakGlassActivation)->getTable());

        $config->set('authorization.tables.break_glass', 'emergencies');

        self::assertSame('emergencies', (new BreakGlassActivation)->getTable());
    }

    /**
     * An activation is keyed by a UUID, keeps no timestamps of its own, stores
     * every instant in UTC, reads its reach as a boolean, and never shows its
     * note in its array or JSON form, though the attribute holds it.
     *
     * @return void
     */
    public function testItStoresInstantsInUtcAndHidesTheNote(): void
    {
        $user       = StubIdentity::create(['id' => 'user-1']);
        $activation = self::activate($user, self::emergencyRole(), [
            'activated_at'    => Carbon::parse('2026-07-01 08:00:00', 'America/New_York'),
            'expires_at'      => Carbon::parse('2026-07-01 09:00:00', 'America/New_York'),
            'ended_at'        => Carbon::parse('2026-07-01 08:30:00', 'America/New_York'),
            'include_subtree' => 0,
        ]);

        $stored = BreakGlassActivation::query()->findOrFail($activation->id);
        $row    = (array) DB::table('break_glass_activations')->first();

        self::assertTrue(Str::isUuid($activation->id));
        self::assertFalse($activation->timestamps);
        self::assertSame(['2026-07-01 12:00:00', '2026-07-01 13:00:00', '2026-07-01 12:30:00'], [$row['activated_at'], $row['expires_at'], $row['ended_at']]);
        self::assertSame('UTC', $stored->expires_at->getTimezone()->getName());
        self::assertSame('2026-07-01 13:00:00', $stored->expires_at->format('Y-m-d H:i:s'));
        $copied = $stored->only(['role_id', 'authorizable_type', 'authorizable_id', 'justification', 'activated_at', 'expires_at']);

        self::assertNull(BreakGlassActivation::query()->create($copied)->ended_at);
        self::assertFalse($stored->include_subtree);
        self::assertSame(self::NOTE, $stored->note);
        self::assertArrayNotHasKey('note', $stored->toArray());
        self::assertStringNotContainsString(self::NOTE, $stored->toJson());
        self::assertSame(['incident', 'user-1'], [$stored->justification, $stored->authorizable_id]);
    }

    /**
     * Every attribute is mass assignable, and every reference and code is read
     * as a string whatever it was given as.
     *
     * @return void
     */
    public function testEveryAttributeIsAssignableAndReadAsItsType(): void
    {
        $columns    = ['role_id', 'authorizable_type', 'authorizable_id', 'granted_by_type', 'granted_by_id', 'tenant_type', 'tenant_id', 'application', 'justification', 'note'];
        $activation = new BreakGlassActivation([...\array_fill_keys($columns, 7), 'ended_by_type' => 7, 'ended_by_id' => 7, 'end_reason' => 7, 'include_subtree' => 1]);

        foreach ([...$columns, 'ended_by_type', 'ended_by_id', 'end_reason'] as $column) {
            self::assertSame('7', $activation->getAttribute($column), $column);
        }

        self::assertTrue($activation->include_subtree);
        self::assertEqualsCanonicalizing(
            [...$columns, 'include_subtree', 'activated_at', 'expires_at', 'ended_at', 'ended_by_type', 'ended_by_id', 'end_reason'],
            $activation->getFillable(),
        );
    }
}
