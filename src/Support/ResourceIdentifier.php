<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableResource;

/**
 * Turns the value a check is about into the resource identifier the evaluator
 * matches statements against.
 *
 * The Gate and the `authorize` route middleware both convert their argument
 * here, so a model, a resource or a string names the same resource whichever
 * way it is checked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ResourceIdentifier
{
    /**
     * Return the resource identifier of the value.
     *
     * Returns null for a null value (no resource) and false for a value the
     * evaluator cannot identify, such as an unsaved model, a number or a list,
     * so the check denies instead of matching every resource-less statement.
     * The resource contract wins over a model's own identifier, and a model is
     * identified as `morphClass:key`.
     *
     * @param  mixed  $value
     * @return false|string|null
     */
    public static function of(mixed $value): false|string|null
    {
        return match (true) {
            $value === null                                            => null,
            $value instanceof AuthorizableResource                     => $value->toResourceIdentifier(),
            $value instanceof Model                                    => self::modelIdentifier($value),
            \is_string($value)                                         => $value,
            \is_object($value) && \method_exists($value, '__toString') => (string) $value,
            default                                                    => false,
        };
    }

    /**
     * Identify a model as `morphClass:key`, or false when it has no usable key
     * (an unsaved model).
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return false|string
     */
    private static function modelIdentifier(Model $model): false|string
    {
        $key = $model->getKey();

        return \is_scalar($key) && $key !== '' ? $model->getMorphClass() . ':' . $key : false;
    }
}
