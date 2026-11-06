<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Config\ContextConfigValidator;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\ContextSource;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use Tests\Feature\Stubs\ContributingAuthenticationContext;
use Tests\Feature\Stubs\PlanContextSource;
use Tests\Feature\Stubs\ReservedContextSource;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `ContextConfigValidator`, the boot-time validation of
 * `authorization.context`: its keys and its sources.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ContextConfigValidator::class)]
final class ContextConfigValidatorTest extends TestCase
{
    /** @var string The reason a namespace that cannot map its keys is refused for. */
    private const string NOT_A_TYPE_MAP = 'each namespace must map key paths to the names of their types, such as [\'tenant\' => [\'plan\' => \'string\']].';

    /**
     * Keys mapped to their types, by name or as a type, and sources each
     * supplying a namespace of their own, pass; so does an empty config.
     *
     * @return void
     */
    public function testValidKeysAndSourcesPass(): void
    {
        ContextConfigValidator::validate([], $this->container());
        ContextConfigValidator::validate(['keys' => [], 'sources' => []], $this->container());
        ContextConfigValidator::validate([
            'keys'    => ['input' => ['post.status' => 'string', 'post.words' => ContextKeyType::NUMBER], 'plan' => ['tier' => 'string']],
            'sources' => [PlanContextSource::class],
        ], $this->container());

        $this->expectNotToPerformAssertions();
    }

    /**
     * Provide `context` configs that are refused, with the key and the reason.
     *
     * @return iterable<string, array{0: mixed, 1: string, 2: string}>
     */
    public static function invalidConfigs(): iterable
    {
        $declare = 'must be a namespace and one or more \'.\'-separated segments of letters, digits, \'_\' and \'-\', and at most 128 characters.';

        yield 'a context that is not an array' => ['context', 'authorization.context', 'expected an array with keys and sources, got string.'];
        yield 'keys that are not an array' => [['keys' => 'input.post'], 'authorization.context.keys', 'expected an array of namespaces to their keys, got string.'];
        yield 'a namespace that is not a name' => [['keys' => [['post' => 'string']]], 'authorization.context.keys', self::NOT_A_TYPE_MAP];
        yield 'keys that are not a map' => [['keys' => ['input' => 'string']], 'authorization.context.keys', self::NOT_A_TYPE_MAP];
        yield 'a key that is not a path' => [['keys' => ['input' => ['string']]], 'authorization.context.keys', self::NOT_A_TYPE_MAP];
        yield 'a type that is not a name' => [['keys' => ['input' => ['post' => 1]]], 'authorization.context.keys', self::NOT_A_TYPE_MAP];
        yield 'an unknown type' => [
            ['keys' => ['input' => ['post' => 'text']]],
            'authorization.context.keys',
            'Context key \'input.post\' has an unknown type \'text\'; use one of string, number, bool, time, ip, list.',
        ];
        yield 'a malformed path' => [['keys' => ['input' => ['post..status' => 'string']]], 'authorization.context.keys', "Context key 'input.post..status' {$declare}"];
        yield 'a malformed namespace' => [['keys' => ['1input' => ['post' => 'string']]], 'authorization.context.keys', "Context key '1input.post' {$declare}"];
        yield 'a package key with another type' => [
            ['keys' => ['request' => ['ip' => 'string']]],
            'authorization.context.keys',
            'Context key \'request.ip\' is already declared as ip.',
        ];
        yield 'a key under resource' => [
            ['keys' => ['resource' => ['status' => 'string']]],
            'authorization.context.keys',
            'Context key \'resource.status\' is under the namespace \'resource\', whose keys are the package\'s built-ins and those an attribute provider declares; '
                . 'register a provider in authorization.attributes.subjects or authorization.attributes.resources.',
        ];
        yield 'sources that are not an array' => [['sources' => PlanContextSource::class], 'authorization.context.sources', 'expected an array of class names, got string.'];
        yield 'a source that is not a class-string' => [['sources' => [42]], 'authorization.context.sources.0', 'entry must be a non-empty class-string, got int.'];
        yield 'an empty source' => [['sources' => ['']], 'authorization.context.sources.0', 'entry must be a non-empty class-string, got string.'];
        yield 'a source that does not exist' => [['sources' => ['App\Missing']], 'authorization.context.sources.0', 'class \'App\Missing\' does not exist.'];
        yield 'a source not implementing the contract' => [
            ['sources' => [StubIdentity::class]],
            'authorization.context.sources.0',
            'class \'' . StubIdentity::class . '\' does not implement ' . ContextSource::class . '.',
        ];
        yield 'a source claiming a reserved namespace' => [
            ['sources' => [PlanContextSource::class, ReservedContextSource::class]],
            'authorization.context.sources.1',
            'source \'' . ReservedContextSource::class . '\' supplies the namespace \'request\', which is not a name or is reserved'
                . ' (authentication, request, environment, input, subject, resource).',
        ];
        yield 'two sources claiming one namespace' => [
            ['sources' => [PlanContextSource::class, PlanContextSource::class]],
            'authorization.context.sources.1',
            'source \'' . PlanContextSource::class . '\' supplies the namespace \'plan\', which \'' . PlanContextSource::class . '\' supplies too.',
        ];
    }

    /**
     * A `context` config that is not keys mapped to their types and sources
     * each supplying a namespace of their own is refused with the key and the
     * reason.
     *
     * @param  mixed  $context
     * @param  string  $key
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('invalidConfigs')]
    public function testRefusesAnInvalidContextConfig(mixed $context, string $key, string $reason): void
    {
        try {
            ContextConfigValidator::validate($context, $this->container());
            self::fail('InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame($key, $exception->getConfigKey());
            self::assertSame($reason, $exception->getReason());
        }
    }

    /**
     * A source supplying a namespace that is not a name is refused.
     *
     * @return void
     */
    public function testRefusesASourceSupplyingANamespaceThatIsNotAName(): void
    {
        $source = new class implements ContextSource {
            /**
             * Return a namespace that is not a name.
             *
             * @return string
             */
            #[\Override]
            public function namespace(): string
            {
                return 'the plan';
            }

            /**
             * Return no values.
             *
             * @return array<string, mixed>
             */
            #[\Override]
            public function values(): array
            {
                return [];
            }
        };

        $this->container()->instance($source::class, $source);

        $this->expectException(InvalidAuthorizationConfigException::class);
        $this->expectExceptionMessage('supplies the namespace \'the plan\', which is not a name or is reserved');

        ContextConfigValidator::validate(['sources' => [$source::class]], $this->container());
    }

    /**
     * A source claiming a namespace the bound authentication context
     * contributes is refused at boot, naming the context; with no source
     * claiming it, the config passes.
     *
     * @return void
     */
    public function testRefusesASourceClaimingANamespaceTheAuthenticationContextContributes(): void
    {
        $this->container()->instance(AuthenticationContext::class, new ContributingAuthenticationContext(['plan']));

        ContextConfigValidator::validate(['keys' => ['plan' => ['tier' => 'string']]], $this->container());

        try {
            ContextConfigValidator::validate(['sources' => [PlanContextSource::class]], $this->container());
            self::fail('InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame('authorization.context.sources.0', $exception->getConfigKey());
            self::assertSame(
                'source \'' . PlanContextSource::class . '\' supplies the namespace \'plan\', which \'' . ContributingAuthenticationContext::class . '\' supplies too.',
                $exception->getReason(),
            );
        }
    }

    /**
     * Provide namespaces an authentication context may not contribute: one that
     * is not a name, a reserved one, and one listed twice.
     *
     * @return iterable<string, array{list<string>, string}>
     */
    public static function unclaimableContributions(): iterable
    {
        yield 'not a name' => [['the mfa'], 'the mfa'];
        yield 'reserved' => [['request'], 'request'];
        yield 'listed twice' => [['mfa', 'sso', 'mfa'], 'mfa'];
    }

    /**
     * An authentication context contributing a namespace that is not a name, is
     * reserved or is listed twice is refused at boot, even with no source
     * configured.
     *
     * @param  list<string>  $contributed
     * @param  string  $namespace
     * @return void
     */
    #[DataProvider('unclaimableContributions')]
    public function testRefusesAnUnclaimableContributedNamespace(array $contributed, string $namespace): void
    {
        $this->container()->instance(AuthenticationContext::class, new ContributingAuthenticationContext($contributed));

        try {
            ContextConfigValidator::validate([], $this->container());
            self::fail('InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame('authorization.context', $exception->getConfigKey());
            self::assertSame(
                'authentication context \'' . ContributingAuthenticationContext::class . "' contributes the namespace '{$namespace}', which is not a name, is reserved ("
                    . \implode(', ', ContextSource::RESERVED_NAMESPACES) . ') or is listed twice.',
                $exception->getReason(),
            );
        }
    }

    /**
     * Return the application container.
     *
     * @return \Illuminate\Foundation\Application
     *
     * @throws \LogicException
     */
    private function container(): Application
    {
        return $this->app ?? throw new \LogicException('The application has not been created.');
    }
}
