<?php

declare(strict_types = 1);

namespace Tests\Fixtures\QueryScoping;

use SineMacula\Laravel\Authorization\Contracts\ScopeInvariant;
use SineMacula\Laravel\Authorization\Contracts\SubjectAttributeProvider;

/**
 * A subject attribute provider, marked `ScopeInvariant`, that declares a
 * department and gives every subject the same one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class InvariantSubjectAttributes implements ScopeInvariant, SubjectAttributeProvider
{
    /**
     * Declare the department.
     *
     * @return array<string, string>
     */
    #[\Override]
    public function attributes(): array
    {
        return ['department' => 'string'];
    }

    /**
     * Give every subject the sales department.
     *
     * @param  object  $subject
     * @return array<string, mixed>
     */
    #[\Override]
    public function values(object $subject): array
    {
        return ['department' => 'sales'];
    }
}
