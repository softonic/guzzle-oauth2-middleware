<?php

namespace Softonic\OAuth2\Guzzle\Middleware\Test;

use DateTime;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use Softonic\OAuth2\Guzzle\Middleware\AccessTokenCacheHandler;

class AccessTokenCacheHandlerTest extends TestCase
{
    public function testGetCacheKeyIsDifferentBetweenOauthClients()
    {
        $mockCache = $this->createMock(CacheItemPoolInterface::class);

        $options = [];
        $providerA = $this->createMock(AbstractProvider::class);
        $providerA->expects($this->any())
            ->method('getAuthorizationUrl')
            ->willReturn('http://example.com?client_id=a');

        $providerB = $this->createMock(AbstractProvider::class);
        $providerB->expects($this->any())
            ->method('getAccessToken')
            ->willReturn('http://example.com?client_id=b');

        $cacheHandler = new AccessTokenCacheHandler($mockCache);
        $this->assertNotEquals(
            $cacheHandler->getCacheKey($providerA, $options),
            $cacheHandler->getCacheKey($providerB, $options)
        );
    }

    public function testGetCacheKeyIsEqualForSameProvider()
    {
        $mockCache = $this->createMock(CacheItemPoolInterface::class);

        $options = [];
        $providerA = $this->createMock(AbstractProvider::class);
        $providerB = $this->createMock(AbstractProvider::class);

        $cacheHandler = new AccessTokenCacheHandler($mockCache);
        $this->assertEquals(
            $cacheHandler->getCacheKey($providerA, $options),
            $cacheHandler->getCacheKey($providerB, $options)
        );
    }

    public function testGetCacheKeyIsDifferentBetweenSameProviderButDifferentOptions()
    {
        $mockCache = $this->createMock(CacheItemPoolInterface::class);

        $optionsA = [
            'grant_type' => 'client_credentials',
            'scope' => 'myscopeA',
        ];
        $optionsB = [
            'grant_type' => 'client_credentials',
            'scope' => 'myscopeB',
        ];

        $provider = $this->createMock(AbstractProvider::class);

        $cacheHandler = new AccessTokenCacheHandler($mockCache);
        $this->assertNotEquals(
            $cacheHandler->getCacheKey($provider, $optionsA),
            $cacheHandler->getCacheKey($provider, $optionsB)
        );
    }

    public function testGetTokenByProviderWhenNotSet()
    {
        $mockProvider = $this->createMock(AbstractProvider::class);
        $mockCache = $this->createMock(CacheItemPoolInterface::class);
        $mockCacheItem = $this->createMock(CacheItemInterface::class);

        $mockCache->expects($this->once())
            ->method('getItem')
            ->with($this->matchCacheKey())
            ->willReturn($mockCacheItem);

        $mockCacheItem->expects($this->once())
            ->method('isHit')
            ->willReturn(false);

        $cacheHandler = new AccessTokenCacheHandler($mockCache);
        $this->assertFalse($cacheHandler->getTokenByprovider($mockProvider, []));
    }

    public function testGetTokenByProviderWhenSet()
    {
        $mockProvider = $this->createMock(AbstractProvider::class);
        $mockCache = $this->createMock(CacheItemPoolInterface::class);
        $mockCacheItem = $this->createMock(CacheItemInterface::class);

        $mockCache->expects($this->once())
            ->method('getItem')
            ->with($this->matchCacheKey())
            ->willReturn($mockCacheItem);

        $mockCacheItem->expects($this->once())
            ->method('isHit')
            ->willReturn(true);

        $mockCacheItem->expects($this->once())
            ->method('get')
            ->willReturn('mytoken');

        $cacheHandler = new AccessTokenCacheHandler($mockCache);
        $this->assertSame('mytoken', $cacheHandler->getTokenByprovider($mockProvider, []));
    }

    public function testSaveTokenByProvider()
    {
        $mockProvider = $this->createMock(AbstractProvider::class);
        $mockCache = $this->createMock(CacheItemPoolInterface::class);
        $mockCacheItem = $this->createMock(CacheItemInterface::class);
        $mockAccessToken = $this->createMock(AccessToken::class);

        $expiryTimestamp = 1498146237;
        $mockAccessToken->expects($this->once())
            ->method('getToken')
            ->willReturn('mytoken');
        $mockAccessToken->expects($this->once())
            ->method('getExpires')
            ->willReturn($expiryTimestamp);

        $mockCache->expects($this->once())
            ->method('getItem')
            ->with($this->matchCacheKey())
            ->willReturn($mockCacheItem);

        $mockCache->expects($this->once())
            ->method('save')
            ->with($mockCacheItem)
            ->willReturn(true);

        $mockCacheItem->expects($this->once())
            ->method('set')
            ->with('mytoken');

        $mockCacheItem->expects($this->once())
            ->method('expiresAt')
            ->with(
                $this->isInstanceOf(DateTime::class)
            );

        $cacheHandler = new AccessTokenCacheHandler($mockCache);
        $this->assertTrue($cacheHandler->saveTokenByProvider($mockAccessToken, $mockProvider, []));
    }

    public function testDeleteItemByProvider()
    {
        $mockProvider = $this->createMock(AbstractProvider::class);
        $mockCache = $this->createMock(CacheItemPoolInterface::class);

        $mockCache->expects($this->once())
            ->method('deleteItem')
            ->with($this->matchCacheKey())
            ->willReturn(true);

        $cacheHandler = new AccessTokenCacheHandler($mockCache);
        $this->assertTrue($cacheHandler->deleteItemByprovider($mockProvider, []));
    }

    private function matchCacheKey()
    {
        return $this->matchesRegularExpression('/^oauth2_token_[a-f0-9]{32}$/');
    }
}
