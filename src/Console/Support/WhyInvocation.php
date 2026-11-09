<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console\Support;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Evaluation\Explanation;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

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
 * The resource is passed to the check as `check()` takes it (N92):
 * `{morphType}:{key}` as the `(type, id)` pair of that record, so its tenant,
 * its resource policies and its attribute provider apply as they do to any
 * check on the pair; `{morphType}:*` as the type alone, a model class when the
 * type is one; and a string with no colon, or any string with `--opaque`, as an
 * opaque identifier. No model is loaded for it. A reference with an empty type
 * or key is refused, and none checks without a resource.
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
     * @param  array{string, string}|\SineMacula\Laravel\Authorization\Support\ResourceReference|string|null  $resource
     * @param  \SineMacula\Laravel\Authorization\Support\AuthorizationScope  $scope
     * @param  array<array-key, mixed>  $input
     * @param  bool  $isJson
     */
    private function __construct(

        /** The action explained. */
        public string $action,

        /** The resource as the check takes it: a `(type, id)` pair, a type alone, an opaque identifier, or null for none. */
        public array|ResourceReference|string|null $resource,

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
        return new self(
            \is_string($arguments['action'] ?? null) ? $arguments['action'] : throw new \InvalidArgumentException('The action must be given.'),
            self::resource($arguments['resource'] ?? null, ($options['opaque'] ?? false) === true),
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
     * Return the resource the argument names as the check takes it: a
     * `{morphType}:{key}` reference as the `(type, id)` pair of that record, a
     * `{morphType}:*` one as the type alone, and a string with no colon, or any
     * string when it is opaque, as the identifier it is; null for none. A
     * reference with an empty type or key is refused.
     *
     * @param  mixed  $resource
     * @param  bool  $isOpaque
     * @return array{string, string}|\SineMacula\Laravel\Authorization\Support\ResourceReference|string|null
     *
     * @throws \InvalidArgumentException
     */
    private static function resource(mixed $resource, bool $isOpaque): array|ResourceReference|string|null
    {
        if (!\is_string($resource) || $isOpaque || !\str_contains($resource, ':')) {
            return \is_string($resource) ? $resource : null;
        }

        [$type, $id] = \explode(':', $resource, 2);

        if ($type === '' || $id === '') {
            throw new \InvalidArgumentException('The resource must be in the format {morphType}:{key} or {morphType}:* (e.g. post:42), or be given with --opaque.');
        }

        return $id === '*' ? self::type($type) : [$type, $id];
    }

    /**
     * Return the type alone as the check takes it: the model class, which the
     * check names by its morph class, or the type as given when it is no model
     * class.
     *
     * @param  string  $type
     * @return \SineMacula\Laravel\Authorization\Support\ResourceReference|string
     */
    private static function type(string $type): ResourceReference|string
    {
        return \is_subclass_of($type, Model::class) ? $type : ResourceReference::type($type);
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

        return AuthorizationScope::tenant(TenantOption::reference('tenant', $tenant), $application);
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
            $namespace = \explode('.', (string) $key)[0];

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
