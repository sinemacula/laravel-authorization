<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics\Settings;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\Settings\SettingCatalogue;
use SineMacula\Laravel\Authorization\Diagnostics\Settings\ValueRenderer;

/**
 * Unit tests for deciding whether the report may show a setting's value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ValueRenderer::class)]
final class ValueRendererTest extends TestCase
{
    /**
     * Return each value shown, by kind, with how it is shown.
     *
     * @return iterable<string, array{string, mixed, mixed}>
     */
    public static function shown(): iterable
    {
        yield 'a class' => [SettingCatalogue::CLASS_NAME, 'App\Tree', 'App\Tree'];
        yield 'a class with a leading backslash' => [SettingCatalogue::CLASS_NAME, '\App\Tree', '\App\Tree'];
        yield 'no class' => [SettingCatalogue::CLASS_NAME, null, null];
        yield 'a list of classes' => [SettingCatalogue::CLASS_LIST, ['App\A', 'App\B'], ['App\A', 'App\B']];
        yield 'a map of classes' => [SettingCatalogue::CLASS_MAP, ['post' => 'App\Post'], ['post' => 'App\Post']];
        yield 'a table' => [SettingCatalogue::TABLE, 'roles', 'roles'];
        yield 'a switch' => [SettingCatalogue::SWITCH, false, false];
        yield 'a whole number' => [SettingCatalogue::WHOLE_NUMBER, 300, 300];
        yield 'a whole number as the environment writes it' => [SettingCatalogue::WHOLE_NUMBER, '300', 300];
        yield 'a name' => [SettingCatalogue::NAME, 'redis-cache', 'redis-cache'];
        yield 'no name' => [SettingCatalogue::NAME, null, null];
        yield 'a map of names' => [SettingCatalogue::NAME_MAP, ['admin' => 'admin.access'], ['admin' => 'admin.access']];
        yield 'a list where a map of classes is expected' => [SettingCatalogue::CLASS_MAP, ['App\Post'], ['App\Post']];
        yield 'a list where a map of names is expected' => [SettingCatalogue::NAME_MAP, ['admin.access'], ['admin.access']];
    }

    /**
     * A value of a kind the report shows, with the shape the kind expects, is
     * shown.
     *
     * @param  string  $kind
     * @param  mixed  $value
     * @param  mixed  $shown
     * @return void
     */
    #[DataProvider('shown')]
    public function testAValueOfTheExpectedShapeIsShown(string $kind, mixed $value, mixed $shown): void
    {
        self::assertSame([$shown], ValueRenderer::render($kind, $value));
    }

    /**
     * Return each value never shown, by kind.
     *
     * @return iterable<string, array{string, mixed}>
     */
    public static function hidden(): iterable
    {
        yield 'a password where a class is expected' => [SettingCatalogue::CLASS_NAME, 'p@ss word'];
        yield 'an array where a class is expected' => [SettingCatalogue::CLASS_NAME, ['x']];
        yield 'a list holding a non-class' => [SettingCatalogue::CLASS_LIST, ['App\A', 'p@ss']];
        yield 'a map keyed by a non-name' => [SettingCatalogue::CLASS_MAP, ['p@ss word' => 'App\Post']];
        yield 'a table with a schema' => [SettingCatalogue::TABLE, 'public.roles'];
        yield 'a switch as a string' => [SettingCatalogue::SWITCH, 'true'];
        yield 'a number with a fraction' => [SettingCatalogue::WHOLE_NUMBER, '3.5'];
        yield 'a name holding a space' => [SettingCatalogue::NAME, 'p@ss word'];
        yield 'a map of names to a non-name' => [SettingCatalogue::NAME_MAP, ['admin' => 'p@ss word']];
        yield 'an opaque value' => [SettingCatalogue::OPAQUE, 'prefix'];
        yield 'an unknown kind' => ['secret', 'value'];
    }

    /**
     * A value of a kind never shown, or without the shape its kind expects, is
     * not shown.
     *
     * @param  string  $kind
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('hidden')]
    public function testAnyOtherValueIsHidden(string $kind, mixed $value): void
    {
        self::assertNull(ValueRenderer::render($kind, $value));
    }

    /**
     * A type is the value's debug type, with an array's number of entries.
     *
     * @return void
     */
    public function testTheTypeCountsAnArraysEntries(): void
    {
        self::assertSame('array(3)', ValueRenderer::typeOf([1, 2, 3]));
        self::assertSame('string', ValueRenderer::typeOf('secret'));
        self::assertSame('null', ValueRenderer::typeOf(null));
    }
}
