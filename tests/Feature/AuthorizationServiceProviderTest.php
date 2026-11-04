<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\ServiceProvider;
use Illuminate\Translation\Translator;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use Tests\TestCase;

/**
 * Feature tests for the service provider's language-file wiring: the package's
 * lines load under the `authorization` namespace, publish under the
 * `authorization-lang` tag, and reach the manager through the translator it is
 * given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationServiceProvider::class)]
final class AuthorizationServiceProviderTest extends TestCase
{
    /**
     * The shipped English lines load under the `authorization` namespace.
     *
     * @return void
     */
    public function testLoadsTheLanguageLinesUnderThePackageNamespace(): void
    {
        self::assertSame('This action is unauthorized.', $this->translator()->get('authorization::authorization.denied'));
    }

    /**
     * The `authorization-lang` tag publishes the shipped `lang` directory into
     * the application's `lang/vendor/authorization` directory.
     *
     * @return void
     */
    public function testLangTagPublishesTheLanguageFiles(): void
    {
        $paths = ServiceProvider::pathsToPublish(AuthorizationServiceProvider::class, 'authorization-lang');

        self::assertCount(1, $paths);

        $source = (string) \array_key_first($paths);

        self::assertSame(\realpath(__DIR__ . '/../../lang'), \realpath($source));
        self::assertSame($this->app->langPath('vendor/authorization'), $paths[$source]); // @phpstan-ignore method.nonObject
    }

    /**
     * The manager words a denial through the application's translator, in its
     * current locale.
     *
     * @return void
     */
    public function testManagerTranslatesTheDenialInTheCurrentLocale(): void
    {
        $translator = $this->translator();
        $translator->addLines(['authorization.denied' => 'Action non autorisée.'], 'fr', 'authorization');
        $translator->setLocale('fr');

        try {
            $this->app->make(AuthorizationManager::class)->authorize('posts:create'); // @phpstan-ignore method.nonObject
            self::fail('Expected AuthorizationException.');
        } catch (AuthorizationException $exception) {
            self::assertSame('Action non autorisée.', $exception->getMessage());
        }
    }

    /**
     * Resolve the application's translator.
     *
     * @return \Illuminate\Translation\Translator
     */
    private function translator(): Translator
    {
        /** @var \Illuminate\Translation\Translator */
        return $this->app->make('translator'); // @phpstan-ignore method.nonObject
    }
}
