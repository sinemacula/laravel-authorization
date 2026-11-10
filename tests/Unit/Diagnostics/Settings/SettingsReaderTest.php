<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics\Settings;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
use SineMacula\Laravel\Authorization\Diagnostics\Settings\SettingCatalogue;
use SineMacula\Laravel\Authorization\Diagnostics\Settings\SettingRow;
use SineMacula\Laravel\Authorization\Diagnostics\Settings\SettingsReader;

/**
 * Unit tests for reading every setting as the report shows it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SettingsReader::class)]
final class SettingsReaderTest extends TestCase
{
    /**
     * Every setting the package defines is listed, then each unknown key the
     * check refused, once.
     *
     * @return void
     */
    public function testEverySettingThenEachUnknownKeyIsListed(): void
    {
        $unknown = new ConfigIssue('authorization.models.rol', IssueCode::UNKNOWN_KEY);
        $rows    = self::rows(['models' => ['rol' => 'X']], [$unknown, $unknown]);

        self::assertSame([...\array_keys(SettingCatalogue::SETTINGS), 'authorization.models.rol'], \array_keys($rows));
        self::assertFalse($rows['authorization.models.rol']['known']);
        self::assertSame('refused', $rows['authorization.models.rol']['status']);
        self::assertTrue($rows['authorization.models.rol']['redacted']);
    }

    /**
     * Each status is read from the issues: its own refusal, a check that failed
     * unforeseen, a skipped check or a refused block it sits in, a check left
     * to the boot, else ok.
     *
     * @return void
     */
    public function testEachStatusIsReadFromTheIssues(): void
    {
        $rows = self::rows(['cache' => 'redis', 'bulk' => ['chunk_size' => 0]], [
            new ConfigIssue('authorization.cache', IssueCode::INVALID_TYPE),
            new ConfigIssue('authorization.bulk.chunk_size', IssueCode::OUT_OF_RANGE),
            ConfigIssue::internal('authorization.connection', new \RuntimeException),
            new ConfigIssue('authorization.permission_providers.0', IssueCode::UNKNOWN_CLASS),
            ConfigIssue::skipped('authorization.usage.connection', 'authorization.usage.connection'),
        ], ['authorization.session.scopes']);

        self::assertSame('skipped', $rows['authorization.cache.ttl']['status']);
        self::assertSame('refused', $rows['authorization.bulk.chunk_size']['status']);
        self::assertSame('unchecked', $rows['authorization.connection']['status']);
        self::assertSame('refused', $rows['authorization.permission_providers']['status']);
        self::assertSame('skipped', $rows['authorization.usage.connection']['status']);
        self::assertSame('checked_at_boot', $rows['authorization.session.scopes']['status']);
        self::assertSame('ok', $rows['authorization.tenant_tree']['status']);
    }

    /**
     * A setting set shows its value where it may, its type and an unknown
     * source; one left out shows none and the default source; a setting under a
     * value that is not an array is left out.
     *
     * @return void
     */
    public function testValuesAreShownOnlyWhereTheyMayBe(): void
    {
        $rows = self::rows(['cache' => ['ttl' => '300', 'prefix' => 'secret'], 'tables' => 'roles']);

        self::assertSame(300, $rows['authorization.cache.ttl']['value']);
        self::assertSame('string', $rows['authorization.cache.ttl']['type']);
        self::assertSame('unknown', $rows['authorization.cache.ttl']['source']);
        self::assertNull($rows['authorization.cache.prefix']['value']);
        self::assertTrue($rows['authorization.cache.prefix']['redacted']);
        self::assertSame('default', $rows['authorization.cache.store']['source']);
        self::assertFalse($rows['authorization.tables.roles']['set']);
        self::assertFalse(self::rows('authorization')['authorization.connection']['set']);
    }

    /**
     * A setting mapping names to classes or permissions is shown as a map,
     * empty or not, and a list of classes as a list.
     *
     * @return void
     */
    public function testMapsAreShownAsMaps(): void
    {
        $rows = self::rows([
            'attributes'         => ['resources' => [], 'subjects' => ['user' => 'App\User']],
            'application_access' => [],
            'permission_enums'   => [],
        ]);

        self::assertSame('{}', \json_encode($rows['authorization.attributes.resources']['value']));
        self::assertSame('{"user":"App\\\User"}', \json_encode($rows['authorization.attributes.subjects']['value']));
        self::assertSame('{}', \json_encode($rows['authorization.application_access']['value']));
        self::assertSame('[]', \json_encode($rows['authorization.permission_enums']['value']));
    }

    /**
     * Return each row of the configuration, in the shape the report shows it,
     * keyed by path.
     *
     * @param  mixed  $root
     * @param  list<\SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue>  $issues
     * @param  list<string>  $checkedAtBoot
     * @return array<string, array<string, mixed>>
     */
    private static function rows(mixed $root, array $issues = [], array $checkedAtBoot = []): array
    {
        $rows = (new SettingsReader($root, new ConfigFindings($issues, $checkedAtBoot)))->rows();

        return \array_column(\array_map(static fn (SettingRow $row): array => $row->toArray(), $rows), null, 'path');
    }
}
