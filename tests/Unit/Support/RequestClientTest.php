<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Illuminate\Container\Container;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Support\RequestClient;

/**
 * Unit tests for `RequestClient`, the client of the routed request an operation
 * is begun in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequestClient::class)]
final class RequestClientTest extends TestCase
{
    /** @var \Illuminate\Container\Container|null The container in place before the test. */
    private ?Container $previous = null;

    /**
     * Put a container of the test's own in place.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->previous = Container::getInstance();

        Container::setInstance(new Container);
    }

    /**
     * Put the container in place before the test back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Container::setInstance($this->previous);

        parent::tearDown();
    }

    /**
     * A routed request gives its IP address and user agent.
     *
     * @return void
     */
    public function testARoutedRequestGivesItsClient(): void
    {
        Container::getInstance()->instance('request', self::request(['REMOTE_ADDR' => '203.0.113.9', 'HTTP_USER_AGENT' => 'Browser/1.0'], true));

        self::assertSame(['203.0.113.9', 'Browser/1.0'], RequestClient::current());
    }

    /**
     * A routed request without a user agent gives its IP address alone.
     *
     * @return void
     */
    public function testAMissingUserAgentIsNull(): void
    {
        $request = self::request(['REMOTE_ADDR' => '203.0.113.9'], true);

        $request->headers->remove('User-Agent');

        Container::getInstance()->instance('request', $request);

        self::assertSame(['203.0.113.9', null], RequestClient::current());
    }

    /**
     * No request, a request that is not routed, as a console command or a
     * queued job holds, and anything bound that is not a request give no
     * client.
     *
     * @return void
     */
    public function testWithoutARoutedRequestThereIsNoClient(): void
    {
        self::assertSame([null, null], RequestClient::current());

        Container::getInstance()->instance('request', self::request(['REMOTE_ADDR' => '203.0.113.9', 'HTTP_USER_AGENT' => 'Browser/1.0'], false));

        self::assertSame([null, null], RequestClient::current());

        Container::getInstance()->instance('request', new \stdClass);

        self::assertSame([null, null], RequestClient::current());
    }

    /**
     * Return a request with the server values, routed or not.
     *
     * @param  array<string, string>  $server
     * @param  bool  $isRouted
     * @return \Illuminate\Http\Request
     */
    private static function request(array $server, bool $isRouted): Request
    {
        $request = Request::create('/posts', 'GET', [], [], [], $server);

        if ($isRouted) {
            $request->setRouteResolver(static fn (): Route => new Route('GET', '/posts', static fn (): null => null));
        }

        return $request;
    }
}
