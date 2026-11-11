<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

use SineMacula\Laravel\Authorization\Config\ConfigBlock;
use SineMacula\Laravel\Authorization\Config\TableConfigValidator;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Read the prefix of the tables' default names and the name each package table
 * takes, as the report shows them, from the configuration alone.
 *
 * Each name is the one the package reads and the migrations create: the name
 * set explicitly, or the key's own with the prefix before it (see
 * `Config\TableNames`), and `explicit` says which. A value is shown only when
 * it passes the boot's checks (see `Config\TableConfigValidator`), so the
 * report never prints a value the settings section hides: a prefix that is
 * refused is shown as null, and so is a name that is refused, one left at its
 * default while the prefix is refused, and every name when the block is not an
 * array.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TableReader
{
    /** @var array{prefix: null, names: list<never>} What the report holds when the tables could not be read. */
    public const array UNREAD = ['prefix' => null, 'names' => []];

    /**
     * Create a new reader.
     *
     * @param  mixed  $root
     */
    public function __construct(

        /** The authorization configuration. */
        private mixed $root,
    ) {}

    /**
     * Return the prefix and the name of each table, in the order the shipped
     * configuration lists them.
     *
     * @return array{prefix: string|null, names: list<array{key: string, name: string|null, explicit: bool}>}
     */
    public function read(): array
    {
        $block  = $this->block();
        $prefix = $block === null ? null : self::checked(static fn (): string => TableConfigValidator::prefix(ConfigBlock::entry($block, TableNames::PREFIX, '')));
        $names  = [];

        foreach (\array_keys(TableConfigValidator::LENGTHS) as $key) {
            $name    = $block === null ? null : ConfigBlock::entry($block, $key, $key);
            $names[] = [
                'key'      => $key,
                'name'     => self::name($key, $name, $prefix),
                'explicit' => $block !== null && !TableNames::isDefault($key, $name),
            ];
        }

        return ['prefix' => $prefix, 'names' => $names];
    }

    /**
     * Return the `tables` block, or null when it is not an array.
     *
     * @return array<array-key, mixed>|null
     */
    private function block(): ?array
    {
        $block = \is_array($this->root) ? ConfigBlock::entry($this->root, 'tables', []) : null;

        return \is_array($block) ? $block : null;
    }

    /**
     * Return the name the table under the key takes, or null when it is
     * refused, or left at its default while the prefix is refused.
     *
     * @param  string  $key
     * @param  mixed  $name
     * @param  string|null  $prefix
     * @return string|null
     */
    private static function name(string $key, mixed $name, ?string $prefix): ?string
    {
        if ($prefix === null && TableNames::isDefault($key, $name)) {
            return null;
        }

        return self::checked(static fn (): string => TableConfigValidator::effective($key, $name, (string) $prefix));
    }

    /**
     * Return what the check returns, or null when it refuses the value.
     *
     * @param  \Closure(): string  $check
     * @return string|null
     */
    private static function checked(\Closure $check): ?string
    {
        try {
            return $check();
        } catch (InvalidAuthorizationConfigException) {
            return null;
        }
    }
}
