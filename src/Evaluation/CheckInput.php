<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * One check of a bulk check (AUTHZ-10.3): the action, the resource and the
 * caller's context, exactly as `check()` takes them.
 *
 * `checkMany()` takes a list of them and decides each as `check()` would,
 * returning one decision for each, keyed as they are.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CheckInput
{
    /**
     * Create a new check input.
     *
     * @param  string  $action
     * @param  mixed  $resource
     * @param  array<string, mixed>  $context
     */
    public function __construct(

        /** The action to decide. */
        public string $action,

        /** The resource, in any form `check()` accepts: a model, a model class, a `(type, id)` pair, a reference, a string or null. */
        public mixed $resource = null,

        /** The caller's context, which a policy reads under `input`. */
        public array $context = [],
    ) {}
}
