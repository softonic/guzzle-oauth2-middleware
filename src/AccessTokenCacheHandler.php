<?php

namespace Softonic\OAuth2\Guzzle\Middleware;

use League\OAuth2\Client\Provider\AbstractProvider as OAuth2Provider;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Cache\CacheItemPoolInterface;

class AccessTokenCacheHandler
{
    const CACHE_KEY_PREFIX = 'oauth2-token-';

    public function __construct(CacheItemPoolInterface $cache)
    {
        $this->cache = $cache;
    }

    /**
     * @return string|bool False if no token can be found in cache, the token's value otherwise.
     */
    public function getTokenByProvider(OAuth2Provider $provider, array $options)
    {
        $cacheKey = $this->getCacheKey($provider, $options);
        $cacheItem = $this->cache->getItem($cacheKey);
        if ($cacheItem->isHit()) {
            return $cacheItem->get();
        }
        return false;
    }

    public function saveTokenByProvider(AccessToken $accessToken, OAuth2Provider $provider, array $options): bool
    {
        $cacheKey = $this->getCacheKey($provider, $options);
        $cacheItem = $this->cache->getItem($cacheKey);
        $cacheItem->set(
            $accessToken->getToken()
        );
        $expiration = new \DateTime();
        $expiration->setTimestamp($accessToken->getExpires());
        $cacheItem->expiresAt(
            $expiration
        );
        return $this->cache->save($cacheItem);
    }

    public function deleteItemByProvider(OAuth2Provider $provider, array $options): bool
    {
        return $this->cache->deleteItem($this->getCacheKey($provider, $options));
    }

    public function getCacheKey(OAuth2Provider $provider, array $options): string
    {
        return static::CACHE_KEY_PREFIX . md5(print_r($provider, true) . serialize($options));
    }
}
