<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console\Support;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Evaluation\Explanation;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * What one `authorization:why` invocation asks (AUTHZ-11.5, N90, N91): the
 * action, the resource, the scope, the caller-supplied input and the format,
 * read from its arguments and options, and the one check that explains it.
 *
 * Each option is read strictly, and anything it cannot read is refused with
 * `InvalidArgumentException`, whose message names the option and never a value
 * it was given:
 *
 * - `--tenant` omitted is the platform, never the tenant in place; given, it is
 *   `{morphType}:{key}`. A type the morph map or a class name resolves to an
 *   Eloquent model names that model's row, which must exist, by its morph
 *   class; any other type is the tenant reference as given.
 * - `--application` omitted is no application, so only the grants for every
 *   application count; given, it must name one.
 * - `--context` is a JSON object read as the `input` namespace alone, so
 *   `{"purpose":"support"}` supplies `input.purpose`. Malformed JSON, a value
 *   that is not an object, and a key naming a trusted namespace, or a dotted
 *   key starting with one, are refused.
 * - `--format` is `text`, the default, or `json`.
 *
 * The resource is passed to the check as it was given, the string reference
 * `check()` takes, or none, which checks without a resource.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class WhyInvocation
{
    /** @var string The format that prints the explanation as text. */
    public const string TEXT = 'text';

    /** @var string The format that prints the explanation's versioned JSON alone. */
    public const string JSON = 'json';

    /**
     * Create a new invocation.
     *
     * @param  string  $action
     * @param  string|null  $resource
     * @param  \SineMacula\Laravel\Authorization\Support\AuthorizationScope  $scope
     * @param  array<array-key, mixed>  $input
     * @param  bool  $isJson
     */
    private function __construct(

        /** The action explained. */
        public string $action,

        /** The resource reference the action is taken on, or null for none. */
        public ?string $resource,

        /** The tenant, or the platform, and the application the check is decided in. */
        public AuthorizationScope $scope,

        /** What the caller passes, held under the `input` namespace. */
        public array $input,

        /** Whether the explanation is printed as its versioned JSON rather than as text. */
        public bool $isJson,
    ) {}

    /**
     * Read the invocation from the command's arguments and options, refusing
     * any it cannot read; the context may fill none of the trusted namespaces.
     *
     * @param  array<string, mixed>  $arguments
     * @param  array<string, mixed>  $options
     * @param  list<string>  $trusted
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function of(array $arguments, array $options, array $trusted): self
    {
        $resource = $arguments['resource'] ?? null;

        return new self(
            \is_string($arguments['action'] ?? null) ? $arguments['action'] : throw new \InvalidArgumentException('The action must be given.'),
            \is_string($resource) ? $resource : null,
            self::scope($options['tenant'] ?? null, self::application($options['application'] ?? null)),
            self::input($options['context'] ?? null, $trusted),
            self::isJsonFormat($options['format'] ?? null),
        );
    }

    /**
     * Explain the check about the subject, in the scope, on the trusted path:
     * with the scope's tenant and application in place, both as the ambient
     * grant scope and as the subject's (N71), and restored afterwards, even
     * when the check throws. The subject keeps its principal, identity and
     * guard, and has no session, whatever the resolver gave it.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $authorization
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return \SineMacula\Laravel\Authorization\Evaluation\Explanation
     */
    public function explain(AuthorizationManager $authorization, Subject $subject): Explanation
    {
        $scoped = $this->scope->subjectIn(new Subject($subject->subject, $subject->identity, guard: $subject->guard));

        return $this->scope->within(fn (): Explanation => $authorization->for($scoped)->explain($this->action, $this->resource, $this->input));
    }

    /**
     * Return the application the option names, or null when it is not given.
     *
     * @param  mixed  $application
     * @return string|null
     *
     * @throws \InvalidArgumentException
     */
    private static function application(mixed $application): ?string
    {
        if ($application === null) {
            return null;
        }

        if (!\is_string($application) || $application === '') {
            throw new \InvalidArgumentException('The --application option must name an application.');
        }

        return $application;
    }

    /**
     * Return the scope the options name: the platform when no tenant is given,
     * the tenant otherwise, on the application or on none.
     *
     * @param  mixed  $tenant
     * @param  string|null  $application
     * @return \SineMacula\Laravel\Authorization\Support\AuthorizationScope
     *
     * @throws \InvalidArgumentException
     */
    private static function scope(mixed $tenant, ?string $application): AuthorizationScope
    {
        if ($tenant === null) {
            return AuthorizationScope::platform($application);
        }

        $parts = \explode(':', \is_string($tenant) ? $tenant : '', 2);

        if (\count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            throw new \InvalidArgumentException('The --tenant option must be in the format {morphType}:{key} (e.g. team:1).');
        }

        return AuthorizationScope::tenant(self::tenant($parts[0], $parts[1]), $application);
    }

    /**
     * Return the reference to the tenant of the type and key: the row of the
     * Eloquent model the type resolves to, by its morph class, or the type and
     * key as given when it resolves to none.
     *
     * @param  string  $type
     * @param  string  $key
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     *
     * @throws \InvalidArgumentException
     */
    private static function tenant(string $type, string $key): Reference
    {
        $class = Relation::getMorphedModel($type) ?? $type;

        if (!\is_subclass_of($class, Model::class)) {
            return new Reference($type, $key);
        }

        $model = $class::query()->find($key) ?? throw new \InvalidArgumentException("No tenant '{$type}:{$key}' was found.");

        return Reference::of($model);
    }

    /**
     * Return the input the context option supplies, or none when it is not
     * given, refusing malformed JSON, a value that is not an object, and a key
     * naming a trusted namespace.
     *
     * @param  mixed  $context
     * @param  list<string>  $trusted
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private static function input(mixed $context, array $trusted): array
    {
        if ($context === null) {
            return [];
        }

        $json = \is_string($context) ? $context : '';

        if (!self::decoded($json, false) instanceof \stdClass) {
            throw new \InvalidArgumentException('The --context option must be a JSON object, read as the input namespace.');
        }

        /** @var array<array-key, mixed> $input */
        $input = self::decoded($json, true);

        self::refuseTrusted($input, $trusted);

        return $input;
    }

    /**
     * Return the JSON decoded, objects as objects or as arrays, refusing JSON
     * that is malformed.
     *
     * @param  string  $json
     * @param  bool  $isAssociative
     * @return mixed
     *
     * @throws \InvalidArgumentException
     */
    private static function decoded(string $json, bool $isAssociative): mixed
    {
        try {
            return \json_decode($json, $isAssociative, 512, \JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new \InvalidArgumentException('The --context option must be valid JSON.');
        }
    }

    /**
     * Refuse input whose key names a trusted namespace, or starts with one
     * followed by a dot, which only its trusted source may fill.
     *
     * @param  array<array-key, mixed>  $input
     * @param  list<string>  $trusted
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function refuseTrusted(array $input, array $trusted): void
    {
        foreach (\array_keys($input) as $key) {
            $namespace = \explode('.', (string) $key, 2)[0];

            if (\in_array($namespace, $trusted, true)) {
                throw new \InvalidArgumentException("The --context option supplies the input namespace alone and cannot fill the trusted namespace '{$namespace}'.");
            }
        }
    }

    /**
     * Determine whether the format option asks for JSON, refusing any format
     * but `text` and `json`.
     *
     * @param  mixed  $format
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private static function isJsonFormat(mixed $format): bool
    {
        return match ($format) {
            null, self::TEXT => false,
            self::JSON       => true,
            default          => throw new \InvalidArgumentException('The --format option must be text or json.'),
        };
    }
}
