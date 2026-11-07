<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console\Support;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Reads the `--actor` option of the commands that write: the actor making the
 * change, as `{morphType}:{key}` (e.g. `user:1`), which every event the
 * command's write dispatches carries and every grant row it writes records.
 *
 * The morph type is resolved through the Eloquent morph map, or taken as a
 * class name, and the actor's row is loaded, so a mistyped actor is refused
 * rather than recorded; the reference names it by its morph class under the
 * morph map. Without the option the command records no actor, as trusted
 * console and system work does (N75).
 *
 * A command that writes through a management service names the actor as an
 * acting context (`acting()`), so the change is decided as that actor, as
 * delegated administration; `authorization:sync`, which writes the catalogue
 * the application declares, names it by reference alone (`parse()`), for the
 * record of trusted work.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ActorOption
{
    /**
     * Return the reference to the actor the option names, or null when it is
     * not given.
     *
     * @param  mixed  $value
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     *
     * @throws \InvalidArgumentException
     */
    public static function parse(mixed $value): ?Reference
    {
        return $value === null ? null : Reference::of(self::model($value));
    }

    /**
     * Return the acting context of the actor the option names, as
     * `ActingContext::for()` names it, or null when it is not given.
     *
     * @param  mixed  $value
     * @return \SineMacula\Laravel\Authorization\Administration\ActingContext|null
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public static function acting(mixed $value): ?ActingContext
    {
        return $value === null ? null : ActingContext::for(self::model($value));
    }

    /**
     * Load the row of the actor the option's value names, refusing a value not
     * in the `{morphType}:{key}` format.
     *
     * @param  mixed  $value
     * @return \Illuminate\Database\Eloquent\Model
     *
     * @throws \InvalidArgumentException
     */
    private static function model(mixed $value): Model
    {
        $parts = \explode(':', \is_string($value) ? $value : '', 2);

        if (\count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            throw new \InvalidArgumentException('The actor must be in the format {morphType}:{key} (e.g. user:1).');
        }

        return self::find($parts[0], $parts[1]);
    }

    /**
     * Load the actor's row from its morph type and key.
     *
     * @param  string  $type
     * @param  string  $key
     * @return \Illuminate\Database\Eloquent\Model
     *
     * @throws \InvalidArgumentException
     */
    private static function find(string $type, string $key): Model
    {
        $class = Relation::getMorphedModel($type) ?? $type;

        if (!\is_subclass_of($class, Model::class)) {
            throw new \InvalidArgumentException("The actor type '{$type}' is not an Eloquent model.");
        }

        return $class::query()->find($key) ?? throw new \InvalidArgumentException("No actor {$class} found with key '{$key}'.");
    }
}
