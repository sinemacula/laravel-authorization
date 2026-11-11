<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Contracts\ConsoleSubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Exceptions\UnresolvedSubjectException;
use SineMacula\Laravel\Authorization\Subject;

/**
 * The default console subject resolver: the saved model a `{morphType}:{key}`
 * reference names, mapped to its principal and identity as the Gate's user is.
 *
 * The morph type is resolved through the Eloquent morph map, or taken as a
 * class name, and must name an Eloquent model, whose row with the key is
 * loaded. The model is then handed to the bound subject resolver's `forUser()`,
 * the package's one translation of a model into the subject decisions are about
 * (N55): under the shipped resolver, the model is its own principal and
 * identity; under an application's resolver with principals, a person is mapped
 * to the principal it acts as, with itself as the identity. The subject
 * returned must be about the model named, as its principal or its identity, or
 * the reference is ambiguous, and its principal must be a saved model that is
 * an authorizable identity, or the model cannot be checked; either is refused.
 * So is a reference whose lookup or mapping fails, a database error or a key
 * the key column cannot hold included, without naming the failure.
 *
 * The subject keeps its principal, its identity and its guard, and loses the
 * tenant, the application, any session, anything said of its credential's
 * scopes and any platform marker the subject resolver gave it, so nothing is
 * taken from whoever is signed in to the console, and where it is decided is
 * the command's to name. The bound subject resolver is read on every call, so
 * one bound after this resolver was built is honoured.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ReferenceSubjectResolver implements ConsoleSubjectResolver
{
    /**
     * Create a new console subject resolver.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Container the bound subject resolver is read from. */
        private Container $container,
    ) {}

    /**
     * Resolve the saved subject the reference names, with its principal,
     * identity and guard, and no tenant, application, session, platform marker
     * or word on its credential's scopes.
     *
     * @param  string  $reference
     * @return \SineMacula\Laravel\Authorization\Subject
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnresolvedSubjectException
     */
    #[\Override]
    public function resolve(string $reference): Subject
    {
        $model     = self::model($reference);
        $resolved  = $this->forUser($model);
        $principal = $resolved->subject;

        if (!self::isAbout($resolved, $model)) {
            throw UnresolvedSubjectException::ambiguous($reference);
        }

        if (!$principal instanceof AuthorizableIdentity || !$principal instanceof Model || !$principal->exists) {
            throw UnresolvedSubjectException::unsupported($reference);
        }

        return new Subject($principal, $resolved->identity, guard: $resolved->guard);
    }

    /**
     * Return the subject the bound subject resolver maps the model to, refusing
     * the model when the resolver cannot be read or fails.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return \SineMacula\Laravel\Authorization\Subject
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnresolvedSubjectException
     */
    private function forUser(Model $model): Subject
    {
        try {
            /** @var \SineMacula\Laravel\Authorization\Contracts\SubjectResolver $subjects */
            $subjects = $this->container->make(SubjectResolver::class);

            return $subjects->forUser($model);
        } catch (\Throwable $exception) {
            throw UnresolvedSubjectException::unresolvable($exception);
        }
    }

    /**
     * Load the saved model the reference names, refusing a reference not in the
     * `{morphType}:{key}` format, a type that names no Eloquent model, a key no
     * row has, and a lookup that fails, as one whose key the key column cannot
     * hold does on some databases.
     *
     * @param  string  $reference
     * @return \Illuminate\Database\Eloquent\Model
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnresolvedSubjectException
     */
    private static function model(string $reference): Model
    {
        $parts = \explode(':', $reference, 2);

        if (\count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            throw UnresolvedSubjectException::malformed();
        }

        [$type, $key] = $parts;
        $class        = Relation::getMorphedModel($type) ?? $type;

        if (!\is_subclass_of($class, Model::class)) {
            throw UnresolvedSubjectException::unknownType($type);
        }

        try {
            $model = $class::query()->find($key);
        } catch (\Throwable $exception) { // @phpstan-ignore catch.neverThrown (the query may fail, as one with a key the key column cannot hold does on PostgreSQL)
            throw UnresolvedSubjectException::unresolvable($exception);
        }

        return $model ?? throw UnresolvedSubjectException::notFound($reference);
    }

    /**
     * Determine whether the subject resolved is about the model named: the
     * model is its principal or its identity.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $resolved
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return bool
     */
    private static function isAbout(Subject $resolved, Model $model): bool
    {
        return self::isSame($resolved->subject, $model) || self::isSame($resolved->identity, $model);
    }

    /**
     * Determine whether the party is the model: a model with the same key,
     * table and connection, the model itself included.
     *
     * @param  object|null  $party
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return bool
     */
    private static function isSame(?object $party, Model $model): bool
    {
        return $party instanceof Model && $model->is($party);
    }
}
