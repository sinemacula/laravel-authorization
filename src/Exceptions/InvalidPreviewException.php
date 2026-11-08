<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a preview (`Authorization::previewFor()`, AUTHZ-11.4) is asked to
 * do what it does not do in this version (N87): to change its target, through
 * `for()`, `forUser()`, `previewFor()` or `permissionsFor()` naming a subject,
 * or the scope it was admitted in, through a listing in another tenant or
 * application; to decide through policies other than the stored ones, with
 * `withPolicies()`, before or after it is built; or to preview a subject that
 * names no record, which no event could name.
 *
 * Changing either party or the scope would need an admission of its own, and a
 * hypothetical policy would answer what the target could never do, so each is a
 * programming error rather than a denial, and Laravel renders it as a 500.
 * Nothing about the target is decided or revealed before it is thrown.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidPreviewException extends \LogicException
{
    /**
     * Refuse a call that would change the subject a preview is about.
     *
     * @param  string  $method
     * @return self
     */
    public static function retargeted(string $method): self
    {
        return new self("A preview cannot change its target through {$method}(); build a new preview with Authorization::previewFor().");
    }

    /**
     * Refuse a listing in a tenant or application other than the one the
     * preview was admitted in.
     *
     * @return self
     */
    public static function rescoped(): self
    {
        return new self('A preview lists only in the tenant and application it was built for; build a new preview for another scope.');
    }

    /**
     * Refuse a policy override on a preview, or a preview of a manager that
     * carries one.
     *
     * @return self
     */
    public static function hypothetical(): self
    {
        return new self('A preview decides through the stored policies alone; withPolicies() cannot be combined with previewFor().');
    }

    /**
     * Refuse a target that names no record, which no preview event could name.
     *
     * @return self
     */
    public static function unidentified(): self
    {
        return new self('A preview needs a target that names a record, a model or a tenant with a key, so every preview decision can name it.');
    }
}
