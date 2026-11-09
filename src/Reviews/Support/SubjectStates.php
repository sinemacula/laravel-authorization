<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Reviews\Enums\SubjectState;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\SubjectGrants;

/**
 * What an access review knows of the subjects of its rows, read for the rows it
 * returns alone, one query for each morph type among them, never one for each
 * subject.
 *
 * A subject the review was given resolved is as `SubjectGrants::isInactive()`
 * reads it: inactive when it or its identity reports itself inactive. Any other
 * is read through the model its morph type names, on the write connection and
 * outside every global scope, so a record deleted softly is read too: inactive
 * when it is deleted softly, or is an identity that reports itself inactive;
 * active when it is read and is neither; unknown when its type names no model
 * or its record is gone. A review lists an inactive subject's stored grants all
 * the same (N93).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SubjectStates
{
    /**
     * Return the rows, each with what is known of its subject: the given
     * subject's state for every row when one is given, else each read by its
     * reference.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Reviews\ReviewRow>  $rows
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @return list<\SineMacula\Laravel\Authorization\Reviews\ReviewRow>
     */
    public static function apply(array $rows, ?Subject $subject = null): array
    {
        if ($subject !== null) {
            $state = SubjectGrants::isInactive($subject) ? SubjectState::INACTIVE : SubjectState::ACTIVE;

            return \array_map(static fn (ReviewRow $row): ReviewRow => $row->withSubjectState($state), $rows);
        }

        $states = self::of(\array_map(static fn (ReviewRow $row): Reference => $row->subject, $rows));

        return \array_map(static fn (ReviewRow $row): ReviewRow => $row->withSubjectState($states[self::key($row->subject)] ?? SubjectState::UNKNOWN), $rows);
    }

    /**
     * Return what is known of each subject, by its key, reading the subjects of
     * each morph type in one query.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $subjects
     * @return array<string, \SineMacula\Laravel\Authorization\Reviews\Enums\SubjectState>
     */
    public static function of(array $subjects): array
    {
        $groups = [];

        foreach ($subjects as $subject) {
            $group = ReviewOrder::key([$subject->type]);

            $groups[$group]['type']              = $subject->type;
            $groups[$group]['ids'][$subject->id] = $subject->id;
        }

        $states = [];

        foreach ($groups as ['type' => $type, 'ids' => $ids]) {
            foreach (self::read($type, \array_values($ids)) as [$id, $state]) {
                $states[self::key(new Reference($type, $id))] = $state;
            }
        }

        return $states;
    }

    /**
     * Return what is known of the subjects of the morph type with the keys,
     * each as its key and its state, leaving out those that are not found.
     *
     * @param  string  $type
     * @param  list<string>  $ids
     * @return list<array{string, \SineMacula\Laravel\Authorization\Reviews\Enums\SubjectState}>
     */
    private static function read(string $type, array $ids): array
    {
        $class = Relation::getMorphedModel($type) ?? $type;

        if (!\is_a($class, Model::class, true)) {
            return [];
        }

        $states = [];

        foreach ((new $class)->newQueryWithoutScopes()->useWritePdo()->whereKey($ids)->get() as $model) {
            /** @var int|string $key */
            $key = $model->getKey();

            $states[] = [(string) $key, self::isInactive($model) ? SubjectState::INACTIVE : SubjectState::ACTIVE];
        }

        return $states;
    }

    /**
     * Determine whether the subject's record is deleted softly, or is an
     * identity that reports itself inactive.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return bool
     */
    private static function isInactive(Model $model): bool
    {
        $isTrashed = \method_exists($model, 'trashed') && $model->trashed() === true;

        return $isTrashed || ($model instanceof AuthorizableIdentity && !$model->isAuthorizationActive());
    }

    /**
     * Return the key of a subject's reference.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $subject
     * @return string
     */
    private static function key(Reference $subject): string
    {
        return ReviewOrder::key([$subject->type, $subject->id]);
    }
}
