<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics\Settings;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\Settings\SettingRow;

/**
 * Unit tests for one setting as the configuration report shows it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SettingRow::class)]
final class SettingRowTest extends TestCase
{
    /**
     * A setting left out takes the package's default; one set comes from a
     * source that is never guessed; a value set but not shown is redacted, and
     * a value shown as null is told from one not shown.
     *
     * @return void
     */
    public function testTheSourceAndRedactionAreShown(): void
    {
        self::assertSame(
            ['path' => 'authorization.a', 'known' => true, 'set' => false, 'value' => null, 'redacted' => false, 'type' => null, 'source' => 'default', 'status' => 'ok'],
            (new SettingRow('authorization.a', true, false, null, null, 'ok'))->toArray(),
        );
        self::assertSame(
            ['path' => 'authorization.b', 'known' => false, 'set' => true, 'value' => null, 'redacted' => true, 'type' => 'string', 'source' => 'unknown', 'status' => 'refused'],
            (new SettingRow('authorization.b', false, true, null, 'string', 'refused'))->toArray(),
        );
        self::assertFalse((new SettingRow('authorization.c', true, true, [null], 'null', 'ok'))->toArray()['redacted']);
        self::assertSame(300, (new SettingRow('authorization.d', true, true, [300], 'int', 'ok'))->toArray()['value']);
    }
}
