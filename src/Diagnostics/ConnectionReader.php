<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authorization\Diagnostics\Settings\SettingCatalogue;
use SineMacula\Laravel\Authorization\Diagnostics\Settings\ValueRenderer;

/**
 * Read which database connection, cache store and queue connection the package
 * uses, from the configuration alone (N119).
 *
 * Each is shown by its name, how it was chosen (`configured`, `default`, or
 * `none` for a cache store not configured, which keeps resolutions in memory
 * only) and its driver. Nothing else of the connection's or store's entry is
 * read, never a host, a user, a password or a URL, and nothing connects: the
 * database's `connectivity` is always `not_tested`, so the report is safe
 * before migrations run and with the database down.
 *
 * Each name and driver is shown by the rules the settings are (see
 * `Settings\ValueRenderer`): one that is not made of the characters names are,
 * such as a queue's URL, is shown as null, and its field is listed under
 * `redacted`, so the connection section never prints what the settings section
 * hides.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ConnectionReader
{
    /** @var array{database: null, cache: null, queue: null} What the report holds when the connection could not be read: each part, as null. */
    public const array UNREAD = ['database' => null, 'cache' => null, 'queue' => null];

    /**
     * Create a new reader.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The application's configuration. */
        private Repository $config,
    ) {}

    /**
     * Return the database connection, the cache store and the queue connection,
     * as the report shows them.
     *
     * @return array<string, array<string, list<string>|string|null>>
     */
    public function read(): array
    {
        [$database, $databaseChosen] = $this->chosen('authorization.connection', 'database.default');
        [$store, $storeChosen]       = $this->chosen('authorization.cache.store', null);
        [$queue, $queueChosen]       = $this->chosen('authorization.usage.connection', 'queue.default');

        return [
            'database' => self::shown([
                'name'         => $database,
                'chosen'       => $databaseChosen,
                'driver'       => $this->driver('database.connections', $database),
                'connectivity' => 'not_tested',
            ]),
            'cache' => self::shown([
                'store'  => $store,
                'chosen' => $storeChosen,
                'driver' => $this->driver('cache.stores', $store),
            ]),
            'queue' => self::shown([
                'connection' => $queue,
                'chosen'     => $queueChosen,
                'driver'     => $this->driver('queue.connections', $queue),
                'queue'      => $this->name('authorization.usage.queue'),
            ]),
        ];
    }

    /**
     * Return the fields of a part as shown: each that is not a name shown as
     * null, and listed under `redacted`.
     *
     * @param  array<string, string|null>  $fields
     * @return array<string, list<string>|string|null>
     */
    private static function shown(array $fields): array
    {
        $redacted = [];

        foreach ($fields as $field => $value) {
            if (ValueRenderer::render(SettingCatalogue::NAME, $value) !== null) {
                continue;
            }

            $fields[$field] = null;
            $redacted[]     = $field;
        }

        return [...$fields, 'redacted' => $redacted];
    }

    /**
     * Return the name the setting holds and `configured`, or else the name the
     * default setting holds and `default`, or null and `none` when there is no
     * default setting.
     *
     * @param  string  $setting
     * @param  string|null  $default
     * @return array{0: string|null, 1: string}
     */
    private function chosen(string $setting, ?string $default): array
    {
        $name = $this->name($setting);

        return match (true) {
            $name !== null    => [$name, 'configured'],
            $default === null => [null, 'none'],
            default           => [$this->name($default), 'default'],
        };
    }

    /**
     * Return the driver of the entry of the map the name names, read as Laravel
     * reads it, a dot in the name nesting, or null when there is none.
     *
     * @param  string  $map
     * @param  string|null  $name
     * @return string|null
     */
    private function driver(string $map, ?string $name): ?string
    {
        $driver = $name === null ? null : $this->config->get("{$map}.{$name}.driver");

        return \is_string($driver) ? $driver : null;
    }

    /**
     * Return the non-empty name the setting holds, or null.
     *
     * @param  string  $setting
     * @return string|null
     */
    private function name(string $setting): ?string
    {
        $name = $this->config->get($setting);

        return \is_string($name) && $name !== '' ? $name : null;
    }
}
