<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;

/**
 * An Eloquent model whose constructor needs an argument and counts the times it
 * runs, so a test can tell that naming the model's type never builds one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConstructedStubModel extends Model
{
    /** @var int The number of times the constructor has run. */
    public static int $constructed = 0;

    /**
     * Create a new model, counting the construction.
     *
     * @param  string  $name
     */
    public function __construct(string $name) // @phpstan-ignore sineMaculaLaravel.modelBehaviour
    {
        parent::__construct(['name' => $name]);

        self::$constructed++;
    }
}
