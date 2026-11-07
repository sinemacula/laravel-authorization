<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Config\SessionConfigValidator;
use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Resolvers\NoSessionPolicy;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use Tests\Feature\Stubs\EmptyActionCatalogue;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\StubSessionPolicySource;
use Tests\TestCase;

/**
 * Feature tests for `SessionConfigValidator`, the boot-time validation of
 * `authorization.session`: its source and its scope map, checked against the
 * permissions the package and the application declare.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(SessionConfigValidator::class)]
final class SessionConfigValidatorTest extends TestCase
{
    /** @var string The reason a scope of the wrong shape is refused for. */
    private const string NOT_A_SCOPE = 'each scope must be a non-empty string, listed on its own or mapped to a non-empty list of action patterns, such as'
        . ' [\'posts.read\', \'editor\' => [\'posts:*\']].';

    /**
     * Declare the stub permission enum, `posts:create` and `posts:delete`, as
     * the application's permissions, before anything reads them, and check the
     * scope map against the catalogue the package binds.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        $this->container()->forgetExtenders(ActionCatalogue::class);
        $this->container()->forgetScopedInstances();
    }

    /**
     * The default source, any class implementing the contract, a config without
     * a source and an empty config pass, as does a map whose scopes each cover
     * a declared permission: mapped to patterns, listed on their own, or naming
     * one of the package's own.
     *
     * @return void
     */
    public function testValidSourcesAndScopeMapsPass(): void
    {
        SessionConfigValidator::validate([], $this->container());
        SessionConfigValidator::validate(['source' => NoSessionPolicy::class, 'scopes' => []], $this->container());
        SessionConfigValidator::validate(['source' => StubSessionPolicySource::class], $this->container());
        SessionConfigValidator::validate([
            'scopes' => [
                'editor'  => ['posts:*'],
                'creator' => ['posts:create', 'posts:delete'],
                'posts:create',
                'posts:*',
                'admin' => [PackagePermissions::GUARDRAIL_MANAGE],
            ],
        ], $this->container());

        $this->addToAssertionCount(4);
    }

    /**
     * Provide `session` configs that are refused, with the key and the reason.
     *
     * @return iterable<string, array{0: mixed, 1: string, 2: string}>
     */
    public static function invalidConfigs(): iterable
    {
        $scopes = 'authorization.session.scopes';
        $source = 'authorization.session.source';

        yield 'a session that is not an array' => ['session', 'authorization.session', 'expected an array with a source and scopes, got string.'];
        yield 'a null source' => [['source' => null], $source, 'a session policy source class is required; set it to \\' . NoSessionPolicy::class . ' for no credential cap.'];
        yield 'an empty source' => [['source' => ''], $source, 'expected a class-string, got string.'];
        yield 'a source that is not a string' => [['source' => 42], $source, 'expected a class-string, got int.'];
        yield 'a missing source class' => [['source' => 'App\Missing\Source'], $source, 'class \'App\Missing\Source\' does not exist.'];
        yield 'a source that is no source' => [['source' => \stdClass::class], $source, 'class \'stdClass\' does not implement ' . SessionPolicySource::class . '.'];
        yield 'scopes that are not an array' => [['scopes' => 'editor'], $scopes, 'expected an array of scopes to their action patterns, got string.'];
        yield 'a scope listed as a number' => [['scopes' => [7]], $scopes, self::NOT_A_SCOPE];
        yield 'an empty scope listed' => [['scopes' => ['']], $scopes, self::NOT_A_SCOPE];
        yield 'an empty scope mapped' => [['scopes' => ['' => ['posts:create']]], $scopes, self::NOT_A_SCOPE];
        yield 'a scope mapped to a string' => [['scopes' => ['editor' => 'posts:*']], $scopes, self::NOT_A_SCOPE];
        yield 'a scope mapped to nothing' => [['scopes' => ['editor' => []]], $scopes, self::NOT_A_SCOPE];
        yield 'a scope mapped to a keyed array' => [['scopes' => ['editor' => ['a' => 'posts:*']]], $scopes, self::NOT_A_SCOPE];
        yield 'a scope mapped to an empty pattern' => [['scopes' => ['editor' => ['posts:*', '']]], $scopes, self::NOT_A_SCOPE];
        yield 'a scope mapped to a number' => [['scopes' => ['editor' => ['posts:*', 7]]], $scopes, self::NOT_A_SCOPE];
        yield 'a scope named twice' => [['scopes' => ['posts:create', 'posts:create' => ['posts:delete']]], $scopes, 'the scope \'posts:create\' is named more than once.'];
        yield 'a mapped pattern covering nothing' => [
            ['scopes' => ['editor' => ['posts:create', 'users:*']]],
            $scopes,
            'the scope \'editor\' names \'users:*\', which covers no declared permission.',
        ];
        yield 'a listed scope covering nothing' => [['scopes' => ['posts:read']], $scopes, 'the scope \'posts:read\' names \'posts:read\', which covers no declared permission.'];
    }

    /**
     * A `session` config that is malformed, or whose scope map names a pattern
     * covering no declared permission, is refused under its key, with the
     * reason.
     *
     * @param  mixed  $config
     * @param  string  $key
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('invalidConfigs')]
    public function testInvalidConfigsAreRefused(mixed $config, string $key, string $reason): void
    {
        try {
            SessionConfigValidator::validate($config, $this->container());
            self::fail('The config was accepted.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame($key, $exception->getConfigKey());
            self::assertSame($reason, $exception->getReason());
        }
    }

    /**
     * The scope map is checked against the bound action catalogue, which is
     * resolved only when the map names a scope: an empty map passes whatever
     * the catalogue holds, and a catalogue declaring nothing refuses every
     * pattern but those covering the package's own permissions.
     *
     * @return void
     */
    public function testTheScopeMapIsCheckedAgainstTheBoundCatalogueOnlyWhenItNamesAScope(): void
    {
        $resolved = new \ArrayObject;

        $this->container()->bind(ActionCatalogue::class, static function () use ($resolved): ActionCatalogue {
            $resolved->append(true);

            return new EmptyActionCatalogue;
        });

        SessionConfigValidator::validate(['scopes' => []], $this->container());

        self::assertCount(0, $resolved);

        SessionConfigValidator::validate(['scopes' => ['admin' => ['authorization:*']]], $this->container());

        self::assertCount(1, $resolved);

        $this->expectException(InvalidAuthorizationConfigException::class);
        $this->expectExceptionMessage('the scope \'editor\' names \'posts:create\', which covers no declared permission.');

        SessionConfigValidator::validate(['scopes' => ['editor' => ['posts:create']]], $this->container());
    }

    /**
     * Return the application the tests validate against.
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
