<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use SineMacula\Laravel\Authorization\Query\ResourceShape;

/**
 * Builds a resource shape no model gives, from one a model gives with some of
 * its parts replaced, so a test can reach a shape `ResourceShape::of()` never
 * makes on the database under test.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ReshapesResources
{
    /**
     * Return the shape with the parts given, by name, in place of its own.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ResourceShape  $shape
     * @param  array<string, mixed>  $parts
     * @return \SineMacula\Laravel\Authorization\Query\ResourceShape
     *
     * @throws \ReflectionException
     */
    protected static function reshaped(ResourceShape $shape, array $parts): ResourceShape
    {
        $class       = new \ReflectionClass(ResourceShape::class);
        $constructor = new \ReflectionMethod(ResourceShape::class, '__construct');
        $copy        = $class->newInstanceWithoutConstructor();
        $arguments   = [];

        foreach ($constructor->getParameters() as $parameter) {
            $name             = $parameter->getName();
            $arguments[$name] = \array_key_exists($name, $parts) ? $parts[$name] : $class->getProperty($name)->getValue($shape);
        }

        $constructor->invokeArgs($copy, $arguments);

        return $copy;
    }
}
