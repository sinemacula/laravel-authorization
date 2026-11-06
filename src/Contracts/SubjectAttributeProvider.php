<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Subject attribute provider contract (N30, AUTHZ-8.5).
 *
 * Supplies the attributes of the subjects of one morph type (a department, a
 * clearance and the like), which conditions and `${…}` references read under
 * `subject`. It is registered for its morph type in
 * `authorization.attributes.subjects` and resolved from the container.
 *
 * The attributes it declares enter the context key catalogue at boot as
 * `subject.<path>`, and only those are exposed: a value it returns for a key it
 * does not declare is dropped. It may not declare a built-in (`id`, `type` or
 * anything under `tenant`), which the package supplies from the check's
 * subject. It is asked at most once for a check, and only when a statement
 * reads `subject`. A provider that throws aborts the check with
 * `AttributeProviderFailed`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SubjectAttributeProvider
{
    /**
     * Return the attributes the provider supplies, each a dot path relative to
     * `subject` mapped to its type, such as `['department' => 'string']`.
     *
     * @return array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>
     */
    public function attributes(): array;

    /**
     * Return the subject's attribute values, nested by key, so `['clearance' =>
     * ['level' => 3]]` supplies `subject.clearance.level`. A key left out is
     * missing.
     *
     * @param  object  $subject
     * @return array<string, mixed>
     */
    public function values(object $subject): array;
}
