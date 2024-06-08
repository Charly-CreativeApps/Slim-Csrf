<?php

/**
 * Slim Framework (https://slimframework.com)
 *
 * @license https://github.com/slimphp/Slim-Csrf/blob/master/LICENSE.md (MIT License)
 */

declare(strict_types=1);

namespace Slim\Csrf\Tests;

use ArrayIterator;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Prophecy\PhpUnit\ProphecyTrait;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Server\RequestHandlerInterface;
use ReflectionException;
use ReflectionMethod;
use RuntimeException;
use Slim\Csrf\Guard;

use function session_start;
use function substr;

class GuardTest extends TestCase
{
    use ProphecyTrait;

    /**
     * Helper function to mask a token using private method {@link Guard::maskToken()}
     *
     * @param Guard $middleware instance of the csrf middleware
     * @param string $token token to mask
     *
     * @return string masked token
     *
     * @throws ReflectionException
     */
    private function maskToken(Guard $middleware, string $token): string
    {
        $maskTokenMethod = new ReflectionMethod($middleware, 'maskToken');
        $maskTokenMethod->setAccessible(true);

        return $maskTokenMethod->invoke($middleware, $token);
    }

    public function testStrengthLowerThan16ThrowsException()
    {
        $storage = [];
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('CSRF middleware instantiation failed. Minimum strength is 16.');
        new Guard($responseFactoryProphecy->reveal(), 'test', $storage, null, 200, 15);
    }

    /**
     * Use session_start() before instantiating the Guard middleware or provide array storage.
     */
    public function testSetStorageThrowsExceptionWhenFallingBackOnSessionThatHasNotBeenStarted()
    {
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid CSRF storage.');
        new Guard($responseFactoryProphecy->reveal(), 'test');
    }

    /**
     * @runInSeparateProcess
     */
    public function testSetStorageSetsKeysOnSessionObjectWhenNotExist()
    {
        session_start();
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        new Guard($responseFactoryProphecy->reveal(), 'test');

        $this->assertArrayHasKey('test', $_SESSION);
    }

    public function testSetFailureHandler()
    {
        $self = $this;

        $storage = [];
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage);

        $called = 0;
        $handler = function () use ($self, &$called) {
            $called++;
            $responseProphecy = $self->prophesize(ResponseInterface::class);
            return $responseProphecy->reveal();
        };
        $mw->setFailureHandler($handler);

        $requestProphecy = $this->prophesize(ServerRequestInterface::class);
        $requestProphecy
            ->getMethod()
            ->willReturn('POST')
            ->shouldBeCalledOnce();

        $requestProphecy
            ->withAttribute(Argument::type('string'), Argument::type('string'))
            ->willReturn($requestProphecy->reveal())
            ->shouldBeCalledTimes(2);

        $requestProphecy
            ->getParsedBody()
            ->willReturn([])
            ->shouldBeCalledOnce();

        $requestProphecy
            ->getHeader(Argument::type('string'))
            ->willReturn([])
            ->shouldBeCalledTimes(2);

        $requestHandlerProphecy = $this->prophesize(RequestHandlerInterface::class);

        $mw->process($requestProphecy->reveal(), $requestHandlerProphecy->reveal());
        $this->assertEquals(1, $called);
    }

    public function testDefaultFailureHandler()
    {
        $streamProphecy = $this->prophesize(StreamInterface::class);
        $streamProphecy
            ->write('Failed CSRF check!')
            ->shouldBeCalledOnce();

        $responseProphecy = $this->prophesize(ResponseInterface::class);

        $responseProphecy
            ->getBody()
            ->willReturn($streamProphecy->reveal())
            ->shouldBeCalledOnce();

        $responseProphecy
            ->withStatus(400)
            ->willReturn($responseProphecy->reveal())
            ->shouldBeCalledOnce();

        $responseProphecy
            ->withHeader('Content-Type', 'text/plain')
            ->willReturn($responseProphecy->reveal())
            ->shouldBeCalledOnce();

        $responseProphecy
            ->withBody($streamProphecy->reveal())
            ->willReturn($responseProphecy->reveal())
            ->shouldBeCalledOnce();

        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $responseFactoryProphecy
            ->createResponse()
            ->willReturn($responseProphecy->reveal());

        $storage = [];
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage);

        $requestProphecy = $this->prophesize(ServerRequestInterface::class);
        $requestProphecy
            ->getMethod()
            ->willReturn('POST')
            ->shouldBeCalledOnce();

        $requestProphecy
            ->withAttribute(Argument::type('string'), Argument::type('string'))
            ->willReturn($requestProphecy->reveal())
            ->shouldBeCalledTimes(2);

        $requestProphecy
            ->getParsedBody()
            ->willReturn([])
            ->shouldBeCalledOnce();

        $requestProphecy
            ->getHeader(Argument::type('string'))
            ->willReturn([])
            ->shouldBeCalledTimes(2);

        $requestHandlerProphecy = $this->prophesize(RequestHandlerInterface::class);

        $response = $mw->process($requestProphecy->reveal(), $requestHandlerProphecy->reveal());
        $this->assertSame($response, $responseProphecy->reveal());
    }

    public function testValidateToken()
    {
        $storage = [
            'test-name' => 'value'
        ];
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage);

        $maskedToken = $this->maskToken($mw, 'value');
        $this->assertTrue($mw->validateToken('test-name', $maskedToken));

        $maskedToken2 = $this->maskToken($mw, 'value');
        $this->assertTrue($mw->validateToken('test-name', $maskedToken2));

        $this->assertNotSame($maskedToken, $maskedToken2);
    }

    public function testNotValidatingBadToken()
    {
        $storage = [
            'test-name' => 'value'
        ];
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage);

        $maskedToken = 'MY_BAD_BASE64???';
        $this->assertFalse($mw->validateToken('test-name', $maskedToken), 'Token contains bad base64 characters');

        $maskedToken2 = $this->maskToken($mw, 'value');
        // Remove some part of base64
        $maskedToken2 = substr($maskedToken2, 0, -6);
        $this->assertFalse($mw->validateToken('test-name', $maskedToken2), 'Token size should be even');
    }

    public function testGetTokenNameAndValue()
    {
        $storage = [];
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage);

        $this->assertNull($mw->getTokenName());
        $this->assertNull($mw->getTokenValue());

        $loadLastKeyPairMethod = new ReflectionMethod($mw, 'loadLastKeyPair');
        $loadLastKeyPairMethod->setAccessible(true);
        $loadLastKeyPairMethod->invoke($mw);

        $storage = [
            'test-name' => 'value',
        ];
        $mw->setStorage($storage);
        $loadLastKeyPairMethod->invoke($mw);

        $this->assertEquals('test-name', $mw->getTokenName());

        $unmaskTokenMethod = new ReflectionMethod($mw, 'unmaskToken');
        $unmaskTokenMethod->setAccessible(true);
        $unmaskedToken = $unmaskTokenMethod->invoke($mw, $mw->getTokenValue());
        $this->assertEquals('value', $unmaskedToken);
    }

    public function testGetPersistentTokenMode()
    {
        $storage = [];
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage, null, 200, 16, true);

        $this->assertTrue($mw->getPersistentTokenMode());
    }

    public function testGetTokenNameKeyAndValue()
    {
        $storage = [];
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage);

        $this->assertEquals('test-name', $mw->getTokenNameKey());
        $this->assertEquals('test-value', $mw->getTokenValueKey());
    }

    public function testRemoveTokenFromStorage()
    {
        $storage = [
            'test-name' => 'value',
        ];
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage);

        $removeTokenFromStorageMethod = new ReflectionMethod($mw, 'removeTokenFromStorage');
        $removeTokenFromStorageMethod->setAccessible(true);
        $removeTokenFromStorageMethod->invoke($mw, 'test-name');

        $this->assertArrayNotHasKey('test-name', $storage);
    }

    public function testEnforceStorageLimitWithArray()
    {
        $storage = [
            'test-name' => 'value',
            'test-name2' => 'value2',
        ];
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage, null, 1);

        $enforceStorageLimitMethod = new ReflectionMethod($mw, 'enforceStorageLimit');
        $enforceStorageLimitMethod->setAccessible(true);
        $enforceStorageLimitMethod->invoke($mw);

        $this->assertArrayNotHasKey('test-name', $storage);
        $this->assertArrayHasKey('test-name2', $storage);
    }

    public function testNotEnforceStorageLimitWithArrayWhenLimitIsZero()
    {
        $initial_storage = $storage = [
            'test-name' => 'value',
            'test-name2' => 'value2',
        ];
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage, null, 0);

        $enforceStorageLimitMethod = new ReflectionMethod($mw, 'enforceStorageLimit');
        $enforceStorageLimitMethod->setAccessible(true);
        $enforceStorageLimitMethod->invoke($mw);

        $this->assertSame($initial_storage, $storage);
    }

    public function testEnforceStorageLimitWithIterator()
    {
        $storage = new ArrayIterator([
            'test-name' => 'value',
            'test-name2' => 'value',
        ]);
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage, null, 1);

        $enforceStorageLimitMethod = new ReflectionMethod($mw, 'enforceStorageLimit');
        $enforceStorageLimitMethod->setAccessible(true);
        $enforceStorageLimitMethod->invoke($mw);

        $this->assertArrayNotHasKey('test-name', $storage);
        $this->assertArrayHasKey('test-name2', $storage);
    }

    public function testTokenIsRemovedFromStorageWhenPersistentModeIsOff()
    {
        $storage = [
            'test-name' => 'test-value123',
        ];

        $responseProphecy = $this->prophesize(ResponseInterface::class)
            ->willImplement(ResponseInterface::class);

        $requestHandlerProphecy = $this->prophesize(RequestHandlerInterface::class);
        $requestHandlerProphecy
            ->handle(Argument::type(ServerRequestInterface::class))
            ->willReturn($responseProphecy->reveal())
            ->shouldBeCalledOnce();

        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);

        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage);

        $requestProphecy = $this->prophesize(ServerRequestInterface::class);
        $requestProphecy
            ->getMethod()
            ->willReturn('POST')
            ->shouldBeCalledOnce();
        $requestProphecy
            ->withAttribute(Argument::type('string'), Argument::type('string'))
            ->willReturn($requestProphecy->reveal())
            ->shouldBeCalledTimes(2);
        $requestProphecy
            ->getParsedBody()
            ->willReturn([
                'test-name' => 'test-name',
                'test-value' => $this->maskToken($mw, 'test-value123'),
            ])
            ->shouldBeCalledOnce();


        $mw->process($requestProphecy->reveal(), $requestHandlerProphecy->reveal());
        self::assertArrayNotHasKey('test-name', $storage);
    }

    public function testTokenIsRemovedFromStorageWhenPersistentModeIsOffOnFailure()
    {
        $storage = [
            'test-name' => 'test-value123',
            'test-name2' => 'test-value234',
        ];

        $streamProphecy = $this->prophesize(StreamInterface::class);
        $streamProphecy
            ->write('Failed CSRF check!')
            ->shouldBeCalledOnce();

        $responseProphecy = $this->prophesize(ResponseInterface::class);

        $responseProphecy
            ->getBody()
            ->willReturn($streamProphecy->reveal())
            ->shouldBeCalledOnce();

        $responseProphecy
            ->withStatus(400)
            ->willReturn($responseProphecy->reveal())
            ->shouldBeCalledOnce();

        $responseProphecy
            ->withHeader('Content-Type', 'text/plain')
            ->willReturn($responseProphecy->reveal())
            ->shouldBeCalledOnce();

        $responseProphecy
            ->withBody($streamProphecy->reveal())
            ->willReturn($responseProphecy->reveal())
            ->shouldBeCalledOnce();

        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $responseFactoryProphecy
            ->createResponse()
            ->willReturn($responseProphecy->reveal());

        $requestHandlerProphecy = $this->prophesize(RequestHandlerInterface::class);

        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage, null, 1);
        $mw->setStorage($storage); // pass $storage in by reference so we can inspect it later

        $requestProphecy = $this->prophesize(ServerRequestInterface::class);
        $requestProphecy
            ->getMethod()
            ->willReturn('GET')
            ->shouldBeCalledOnce();

        $requestProphecy
            ->getParsedBody()
            ->willReturn([
                             'test-name' => 'test-value123',
                         ])
            ->shouldBeCalledOnce();

        $mw->process($requestProphecy->reveal(), $requestHandlerProphecy->reveal());

        $this->assertArrayNotHasKey('test-name', $storage);
    }

    public function testTokenInBodyOfGetIsInvalid()
    {
        $storage = [
            'test-name' => 'test-value123',
        ];

        // we set up a failure handler that we expect to be called because a GET cannot have a token
        $self = $this;
        $failureHandlerCalled = 0;
        $failureHandler = function () use ($self, &$failureHandlerCalled) {
            $failureHandlerCalled++;
            $responseProphecy = $self->prophesize(ResponseInterface::class);
            return $responseProphecy->reveal();
        };

        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);

        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage, $failureHandler);

        $requestHandlerProphecy = $this->prophesize(RequestHandlerInterface::class);

        $requestProphecy = $this->prophesize(ServerRequestInterface::class);
        $requestProphecy
            ->getMethod()
            ->willReturn('GET')
            ->shouldBeCalledOnce();
        $requestProphecy
            ->getParsedBody()
            ->willReturn([
                'test-name' => 'test-name',
                'test-value' => 'test-value123',
            ])
            ->shouldBeCalledOnce();

        $mw->process($requestProphecy->reveal(), $requestHandlerProphecy->reveal());
        self::assertSame(1, $failureHandlerCalled);
    }

    public function testProcessAppendsNewTokensWhenPersistentTokenModeIsOff()
    {
        $storage = [];
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage);

        $responseProphecy = $this->prophesize(ResponseInterface::class);

        $requestProphecy = $this->prophesize(ServerRequestInterface::class);
        $requestProphecy->getParsedBody()->willReturn(null)->shouldBeCalledOnce();
        $requestProphecy->getHeader(Argument::type('string'))->willReturn([])->shouldBeCalledTimes(2);
        $requestProphecy
            ->getMethod()
            ->willReturn('GET')
            ->shouldBeCalledOnce();

        $requestProphecy
            ->withAttribute(Argument::type('string'), Argument::type('string'))
            ->willReturn($requestProphecy->reveal())
            ->shouldBeCalledTimes(2);

        $requestHandlerProphecy = $this->prophesize(RequestHandlerInterface::class);

        $requestHandlerProphecy
            ->handle($requestProphecy)
            ->willReturn($responseProphecy->reveal())
            ->shouldBeCalledOnce();

        $mw->process($requestProphecy->reveal(), $requestHandlerProphecy->reveal());
    }

    public function testProcessAppendsNewTokensWhenPersistentTokenModeIsOn()
    {
        $storage = [
            'test-name123' => 'test-value123',
        ];
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage, null, 200, 16, true);

        $responseProphecy = $this->prophesize(ResponseInterface::class);

        $requestProphecy = $this->prophesize(ServerRequestInterface::class);
        $requestProphecy->getParsedBody()->willReturn(null)->shouldBeCalledOnce();
        $requestProphecy->getHeader(Argument::type('string'))->willReturn([])->shouldBeCalledTimes(2);
        $requestProphecy
            ->getMethod()
            ->willReturn('GET')
            ->shouldBeCalledOnce();

        $requestProphecy
            ->withAttribute('test-name', 'test-name123')
            ->willReturn($requestProphecy->reveal())
            ->shouldBeCalledOnce();

        $requestProphecy
            ->withAttribute('test-value', Argument::type('string'))
            ->willReturn($requestProphecy->reveal())
            ->shouldBeCalledOnce();

        $requestHandlerProphecy = $this->prophesize(RequestHandlerInterface::class);

        $requestHandlerProphecy
            ->handle($requestProphecy)
            ->willReturn($responseProphecy->reveal())
            ->shouldBeCalledOnce();

        $mw->process($requestProphecy->reveal(), $requestHandlerProphecy->reveal());
    }

    public function testCanGetLastKeyPairFromIterator()
    {
        $storage = new ArrayIterator([
            'test-key1' => 'value1',
            'test-key2' => 'value2',
        ]);
        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);
        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage, null, 1);

        $enforceStorageLimitMethod = new ReflectionMethod($mw, 'getLastKeyPair');
        $enforceStorageLimitMethod->setAccessible(true);
        $keyPair = $enforceStorageLimitMethod->invoke($mw);

        $this->assertIsArray($keyPair);
        $this->assertArrayHasKey('test-name', $keyPair);
        $this->assertArrayHasKey('test-value', $keyPair);
        $this->assertEquals('test-key2', $keyPair['test-name']);

        $unmaskTokenMethod = new ReflectionMethod($mw, 'unmaskToken');
        $unmaskTokenMethod->setAccessible(true);
        $unmaskedToken = $unmaskTokenMethod->invoke($mw, $keyPair['test-value']);
        $this->assertEquals('value2', $unmaskedToken);
    }

    public function testTokenFromHeaderOnDelete()
    {
        $storage = [
            'test-name' => 'test-value123',
        ];

        $responseProphecy = $this->prophesize(ResponseInterface::class)
            ->willImplement(ResponseInterface::class);

        $requestHandlerProphecy = $this->prophesize(RequestHandlerInterface::class);
        $requestHandlerProphecy
            ->handle(Argument::type(ServerRequestInterface::class))
            ->willReturn($responseProphecy->reveal())
            ->shouldBeCalledOnce();

        $responseFactoryProphecy = $this->prophesize(ResponseFactoryInterface::class);

        $mw = new Guard($responseFactoryProphecy->reveal(), 'test', $storage);

        $requestProphecy = $this->prophesize(ServerRequestInterface::class);
        $requestProphecy
            ->getMethod()
            ->willReturn('DELETE')
            ->shouldBeCalledOnce();
        $requestProphecy
            ->withAttribute(Argument::type('string'), Argument::type('string'))
            ->willReturn($requestProphecy->reveal())
            ->shouldBeCalledTimes(2);
        $requestProphecy
            ->getParsedBody()
            ->willReturn([])
            ->shouldBeCalledOnce();
        $requestProphecy
            ->getHeader('test-name')
            ->willReturn(['test-name'])
            ->shouldBeCalledOnce();
        $requestProphecy
            ->getHeader('test-value')
            ->willReturn([$this->maskToken($mw, 'test-value123')])
            ->shouldBeCalledOnce();

        $mw->process($requestProphecy->reveal(), $requestHandlerProphecy->reveal());
    }
}
