<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

use Illuminate\Container\Container;

/**
 * Marks while a query scope is being decided, so a model-level scope applied
 * meanwhile can tell it would be deciding inside a decision, and refuse
 * (`reentrant`): it is on the subject's model, or on a model the decision reads
 * (the grants, roles, policies and tenants), and would otherwise recurse or
 * read the decision's own sources through itself.
 *
 * The mark is kept in the container, never in a static property, and is removed
 * when the outermost decision ends, however it ends.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Reentrancy
{
    /** @var string The container key bound while a query scope is being decided. */
    private const string DECIDING = 'authorization.query_scope.deciding';

    /**
     * Run the callback marked as deciding a query scope, and return what it
     * returns.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $callback
     * @return TResult
     */
    public static function guarded(\Closure $callback): mixed
    {
        $container = Container::getInstance();
        $isOuter   = !$container->bound(self::DECIDING);

        if ($isOuter) {
            $container->instance(self::DECIDING, true);
        }

        try {
            return $callback();
        } finally {
            if ($isOuter) {
                $container->forgetInstance(self::DECIDING);
            }
        }
    }

    /**
     * Determine whether a query scope is being decided.
     *
     * @return bool
     */
    public static function isDeciding(): bool
    {
        return Container::getInstance()->bound(self::DECIDING);
    }
}
