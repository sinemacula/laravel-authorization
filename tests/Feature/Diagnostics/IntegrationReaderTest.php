<?php

declare(strict_types = 1);

namespace Tests\Feature\Diagnostics;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Diagnostics\IntegrationReader;
use Tests\Feature\Stubs\CustomRoleMiddlewareDouble;
use Tests\TestCase;

/**
 * Feature tests for reading how the package is wired into the application.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IntegrationReader::class)]
final class IntegrationReaderTest extends TestCase
{
    /**
     * The application the suite boots has every integration registered, and a
     * middleware alias the application took for its own is shown with its
     * class.
     *
     * @return void
     */
    public function testTheBootedApplicationIsWired(): void
    {
        $app = $this->container();

        $app->make('router')->aliasMiddleware('role', CustomRoleMiddlewareDouble::class);

        $states = self::states(new IntegrationReader($app, $app->make('config')));

        self::assertSame(['enabled', null], $states['gate']);
        self::assertSame(['registered', null], $states['blade_directives']);
        self::assertSame(['registered', null], $states['query_macro']);
        self::assertSame(['registered', null], $states['grammar_macro']);
        self::assertSame(['other', CustomRoleMiddlewareDouble::class], $states['middleware.role']);
        self::assertSame(['registered', null], $states['middleware.permission']);
    }

    /**
     * The Gate hook is disabled by its switch and unknown when the switch
     * cannot be read; what the container has not built is unavailable, never
     * built for the report.
     *
     * @return void
     */
    public function testWhatIsNotBuiltIsUnavailable(): void
    {
        $container = new Container;

        $disabled = self::states(new IntegrationReader($container, new Repository(['authorization' => ['gate' => ['enabled' => false]]])));
        $unknown  = self::states(new IntegrationReader($container, new Repository(['authorization' => ['gate' => 'off']])));
        $missing  = self::states(new IntegrationReader($container, new Repository(['authorization' => []])));

        self::assertSame('disabled', $disabled['gate'][0]);
        self::assertSame('unknown', $unknown['gate'][0]);
        self::assertSame('not_registered', $missing['gate'][0]);
        self::assertSame('unavailable', $missing['blade_directives'][0]);
        self::assertSame('unavailable', $missing['middleware.authorize'][0]);
        self::assertFalse($container->bound('router'));
    }

    /**
     * Return the state and detail of each integration, keyed by name.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\IntegrationReader  $reader
     * @return array<string, array{string, string|null}>
     */
    private static function states(IntegrationReader $reader): array
    {
        $states = [];

        foreach ($reader->read() as $integration) {
            $states[$integration['name']] = [$integration['state'], $integration['detail']];
        }

        return $states;
    }
}
