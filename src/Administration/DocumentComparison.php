<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Support\DocumentDigest;
use SineMacula\Laravel\Authorization\Support\PolicyDocument;

/**
 * Compares two versions of a policy document conservatively, statement by
 * statement, for a delegated rewrite (see `DefinitionConstraints`) and a
 * boundary replaced by another (see `Narrowing`).
 *
 * Two statements are the same when they have the same effect, actions,
 * resources, principals and conditions, compared as canonical JSON (see
 * `DocumentDigest`), so the order of an object's keys never matters, the order
 * of a list always does, and a statement's sid, which only names it in traces,
 * never does. Two documents of different schema versions are never the same and
 * never narrower. Then:
 *
 * - the new document can only narrow when every allow statement it holds is one
 *   the old one held, and every deny statement the old one held it still holds:
 *   it only removes allows or adds denies, so it allows nothing the old one did
 *   not, and denies everything the old one denied;
 * - anything else, a changed condition, action list or resource included, is
 *   taken to widen, so nothing the comparison cannot prove is ever judged
 *   narrowing.
 *
 * A boundary allows what its allows name and its denies leave, so the same rule
 * tells a boundary that only caps more. A document that cannot be read is
 * neither the same nor narrower.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DocumentComparison
{
    /**
     * Return the policy the document, as stored, holds, or null when it cannot
     * be read.
     *
     * @param  mixed  $document
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy|null
     */
    public static function read(mixed $document): ?Policy
    {
        try {
            return \is_array($document) ? Policy::fromArray(PolicyDocument::named($document, PolicyDocument::UNNAMED)) : null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Determine whether the new document can only narrow what the old one
     * allows: it holds no allow the old one did not, and every deny the old one
     * held, in the same schema version. A document the same as the old one in
     * authority terms, holding exactly its statements, is one.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy|null  $old
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy|null  $new
     * @return bool
     */
    public static function isNarrower(?Policy $old, ?Policy $new): bool
    {
        return $new !== null && self::keepsDenies($old, $new) && self::added($old, $new) === [];
    }

    /**
     * Determine whether the new document still holds every deny the old one
     * held, in the same schema version, so it lifts no deny.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy|null  $old
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy|null  $new
     * @return bool
     */
    public static function keepsDenies(?Policy $old, ?Policy $new): bool
    {
        if ($old === null || $new === null || $old->version !== $new->version) {
            return false;
        }

        return \array_diff_key(self::denies(self::keys($old->statements)), self::keys($new->statements)) === [];
    }

    /**
     * Return the allow statements of the new document the old one did not hold,
     * every allow of the new one when there is no old one.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy|null  $old
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $new
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Statement>
     */
    public static function added(?Policy $old, Policy $new): array
    {
        $before = $old === null ? [] : self::keys($old->statements);

        return \array_values(\array_diff_key(self::allows(self::keys($new->statements)), $before));
    }

    /**
     * Return the statements keyed by what they say (see the class summary).
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Statement>  $statements
     * @return array<string, \SineMacula\Laravel\Authorization\Evaluation\Statement>
     */
    private static function keys(array $statements): array
    {
        $keyed = [];

        foreach ($statements as $statement) {
            $keyed[self::keyOf($statement)] = $statement;
        }

        return $keyed;
    }

    /**
     * Return the key of what the statement says: the digest of its effect,
     * actions, resources, principals and conditions as canonical JSON; one no
     * other statement shares when they cannot be encoded.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @return string
     */
    private static function keyOf(Statement $statement): string
    {
        $says = [
            'effect'        => $statement->effect->value,
            'actions'       => $statement->actions,
            'not_actions'   => $statement->notActions,
            'resources'     => $statement->resources,
            'not_resources' => $statement->notResources,
            'principals'    => $statement->principals,
            'conditions'    => $statement->conditions,
        ];

        try {
            return DocumentDigest::of(['statement' => $says])->digest;
        } catch (\JsonException) {
            return \spl_object_hash($statement);
        }
    }

    /**
     * Return the allow statements among the keyed statements.
     *
     * @param  array<string, \SineMacula\Laravel\Authorization\Evaluation\Statement>  $statements
     * @return array<string, \SineMacula\Laravel\Authorization\Evaluation\Statement>
     */
    private static function allows(array $statements): array
    {
        return \array_filter($statements, static fn (Statement $statement): bool => $statement->effect === PolicyEffect::ALLOW);
    }

    /**
     * Return the deny statements among the keyed statements.
     *
     * @param  array<string, \SineMacula\Laravel\Authorization\Evaluation\Statement>  $statements
     * @return array<string, \SineMacula\Laravel\Authorization\Evaluation\Statement>
     */
    private static function denies(array $statements): array
    {
        return \array_filter($statements, static fn (Statement $statement): bool => $statement->effect === PolicyEffect::DENY);
    }
}
