<?php

namespace Softonic\OAuth2\Guzzle\Middleware;

use League\OAuth2\Client\Provider\AbstractProvider as OAuth2Provider;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class RetryOnAuthorizationError
{
    private $provider;
    private $cacheHandler;

    public function __construct(OAuth2Provider $provider, AccessTokenCacheHandler $cacheHandler)
    {
        $this->provider = $provider;
        $this->cacheHandler = $cacheHandler;
    }

    public function __invoke(
        int $retries,
        RequestInterface $request,
        ResponseInterface $response = null,
        \Exception $exception = null
    ): bool {
        $statusCode = $response->getStatusCode();
        if ($retries < 1 && $statusCode === 401) {
            $this->cacheHandler->deleteItemByProvider($this->provider);
            return true;
        }
        return false;
    }
}
