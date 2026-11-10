<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Database;

use Illuminate\Database\Schema\Blueprint;

/**
 * A blueprint that records the name of every index, unique index, primary key
 * and foreign key it builds, as Laravel names each one, so a test can check the
 * names a migration builds whatever the database keeps of them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingBlueprint extends Blueprint
{
    /** @var list<string> The names built, in the order they were built. */
    public static array $names = [];

    /**
     * Execute the blueprint against the database, then record the names of the
     * indexes and keys it built.
     *
     * @return void
     */
    #[\Override]
    public function build(): void
    {
        parent::build();

        foreach ($this->getCommands() as $command) {
            $name = $command->get('index');

            if (!\is_string($name)) {
                continue;
            }

            self::$names[] = $name;
        }
    }
}
