<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console\Support;

use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionAttributeException;
use SineMacula\Laravel\Authorization\Support\PermissionMetadataReader;

/**
 * Expands `PermissionEnum` classes into the flat list of `PermissionTuple`
 * entries the diff engine consumes.
 *
 * The walker is the only side of the sync pipeline that reflects over enum
 * cases. It reads the `#[Permission]` attribute via the shared
 * `PermissionMetadataReader`, rejects the explicit-empty-guards configuration
 * with a typed exception, and expands multi-guard attributes into one tuple per
 * guard.
 *
 * Input ordering is preserved across both the enum list and the cases within
 * each enum; the diff engine sorts the final buckets so the walker does not
 * need deterministic output of its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PermissionEnumWalker
{
    /**
     * Create a new enum walker.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\PermissionMetadataReader  $reader
     */
    public function __construct(

        /** Metadata reader used to hydrate each case's description, category, and guards. */
        private PermissionMetadataReader $reader,

    ) {}

    /**
     * Walk every case in every supplied enum class and produce the expected
     * `(name, guard)` tuple list.
     *
     * @param  list<class-string<\SineMacula\Laravel\Authorization\Contracts\PermissionEnum>>  $enumClasses
     * @return list<\SineMacula\Laravel\Authorization\Console\Support\PermissionTuple>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionAttributeException
     */
    public function walk(array $enumClasses): array
    {
        $tuples = [];

        foreach ($enumClasses as $enumClass) {
            foreach ($this->walkEnum($enumClass) as $tuple) {
                $tuples[] = $tuple;
            }
        }

        return $tuples;
    }

    /**
     * Walk a single enum class and yield one tuple per `(case, guard)`
     * combination.
     *
     * @param  class-string<\SineMacula\Laravel\Authorization\Contracts\PermissionEnum>  $enumClass
     * @return list<\SineMacula\Laravel\Authorization\Console\Support\PermissionTuple>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionAttributeException
     */
    private function walkEnum(string $enumClass): array
    {
        $reflection = new \ReflectionEnum($enumClass);
        $tuples     = [];

        foreach ($reflection->getCases() as $case) {
            foreach ($this->expandCase($enumClass, $case) as $tuple) {
                $tuples[] = $tuple;
            }
        }

        return $tuples;
    }

    /**
     * Expand a single case into one tuple per guard, validating the attribute
     * shape first.
     *
     * @param  class-string<\SineMacula\Laravel\Authorization\Contracts\PermissionEnum>  $enumClass
     * @param  \ReflectionEnumUnitCase  $case
     * @return list<\SineMacula\Laravel\Authorization\Console\Support\PermissionTuple>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionAttributeException
     */
    private function expandCase(string $enumClass, \ReflectionEnumUnitCase $case): array
    {
        $metadata = $this->reader->read($case);

        $this->guardAgainstEmptyGuardList($enumClass, $case->getName(), $metadata);

        /** @var \BackedEnum $value */
        $value = $case->getValue();
        $name  = (string) $value->value;

        $guards = $metadata->guards ?? [null];
        $tuples = [];

        foreach ($guards as $guard) {
            $tuples[] = new PermissionTuple(
                name: $name,
                guard: $guard,
                description: $metadata->description,
                category: $metadata->category,
            );
        }

        return $tuples;
    }

    /**
     * Reject the explicit `guards: []` configuration — the empty array is never
     * a meaningful expansion target and almost certainly a mistake.
     *
     * @param  class-string<\SineMacula\Laravel\Authorization\Contracts\PermissionEnum>  $enumClass
     * @param  string  $caseName
     * @param  \SineMacula\Laravel\Authorization\Attributes\Permission  $metadata
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionAttributeException
     */
    private function guardAgainstEmptyGuardList(string $enumClass, string $caseName, PermissionMeta $metadata): void
    {
        if ($metadata->guards !== null && $metadata->guards === []) {
            throw new InvalidPermissionAttributeException(enumClass: $enumClass, caseName: $caseName, reason: '\'guards\' must be null or a non-empty list of guard names.');
        }
    }
}
