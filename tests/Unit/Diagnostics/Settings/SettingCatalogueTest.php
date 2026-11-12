<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics\Settings;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\Settings\SettingCatalogue;

/**
 * Unit tests for the catalogue of every setting the shipped configuration
 * defines.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SettingCatalogue::class)]
final class SettingCatalogueTest extends TestCase
{
    /**
     * The catalogue lists every setting of the shipped configuration, in its
     * order: each leaf, a map the application fills counting as one setting.
     *
     * @return void
     */
    public function testItListsEverySettingOfTheShippedConfiguration(): void
    {
        /** @var array<string, mixed> $shipped */
        $shipped = require \dirname(__DIR__, 4) . '/config/authorization.php';

        self::assertSame(self::leaves($shipped, 'authorization'), \array_keys(SettingCatalogue::SETTINGS));
    }

    /**
     * The break-glass settings show their switches and whole numbers, and keep
     * the roles and the justification codes opaque; the table is a table.
     *
     * @return void
     */
    public function testTheBreakGlassSettingsHaveTheirKinds(): void
    {
        self::assertSame(
            ['table', 'boolean', 'integer', 'opaque', 'opaque', 'boolean', 'integer'],
            \array_map(SettingCatalogue::kindOf(...), [
                'authorization.tables.break_glass',
                'authorization.break_glass.enabled',
                'authorization.break_glass.max_minutes',
                'authorization.break_glass.roles',
                'authorization.break_glass.justifications',
                'authorization.break_glass.notes',
                'authorization.break_glass.note_max_length',
            ]),
        );
    }

    /**
     * A setting the package does not define is opaque.
     *
     * @return void
     */
    public function testAnUnknownSettingIsOpaque(): void
    {
        self::assertSame(SettingCatalogue::CLASS_NAME, SettingCatalogue::kindOf('authorization.tenant_tree'));
        self::assertSame(SettingCatalogue::TABLE_PREFIX, SettingCatalogue::kindOf('authorization.tables.prefix'));
        self::assertSame('table_prefix', SettingCatalogue::TABLE_PREFIX);
        self::assertSame(SettingCatalogue::OPAQUE, SettingCatalogue::kindOf('authorization.password'));
    }

    /**
     * Return the path of each leaf of the configuration, a block of named
     * settings walked into, anything else a leaf.
     *
     * @param  array<array-key, mixed>  $config
     * @param  string  $path
     * @return list<string>
     */
    private static function leaves(array $config, string $path): array
    {
        $leaves = [];

        foreach ($config as $key => $value) {
            $leaves = \is_array($value) && $value !== [] && !\array_is_list($value)
                ? [...$leaves, ...self::leaves($value, "{$path}.{$key}")]
                : [...$leaves, "{$path}.{$key}"];
        }

        return $leaves;
    }
}
