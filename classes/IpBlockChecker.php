<?php
/**
 * IpBlockChecker -- core decision logic (whitelist + cache + fail mode + real IP).
 *
 * Mirrors the shared reference design used for WordPress/Magento:
 *   1. Resolve the real client IP (respect behind_proxy).
 *   2. Honour the whitelist (never blocked).
 *   3. Cache each decision by md5(ip|user_agent|referrer) via PrestaShop's cache.
 *   4. Ask the API; on any failure apply the fail mode (default fail open = allow).
 *
 * @author IP-Block.com
 */

if (!defined('_PS_VERSION_')) {
    exit;
}

class IpBlockChecker
{
    /** @var IpBlockClient */
    private $client;
    /** @var bool */
    private $failOpen;
    /** @var int */
    private $cacheTtl;
    /** @var bool */
    private $behindProxy;
    /** @var string[] */
    private $whitelist;

    public function __construct(IpBlockClient $client, $failOpen, $cacheTtl, $behindProxy, $whitelistRaw)
    {
        $this->client = $client;
        $this->failOpen = (bool) $failOpen;
        $this->cacheTtl = max(0, (int) $cacheTtl);
        $this->behindProxy = (bool) $behindProxy;
        $this->whitelist = $this->parseWhitelist($whitelistRaw);
    }

    /**
     * Determine the real client IP address.
     *
     * When behind a proxy/CDN, trust CF-Connecting-IP first, then the first
     * hop of X-Forwarded-For. Otherwise use REMOTE_ADDR.
     *
     * @return string
     */
    public function getClientIp()
    {
        if ($this->behindProxy) {
            if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
                return trim($_SERVER['HTTP_CF_CONNECTING_IP']);
            }
            if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
                $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
                return trim($parts[0]);
            }
        }

        return isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '';
    }

    /**
     * Main entry point: should this visitor be blocked?
     *
     * @return bool
     */
    public function isBlocked($ip, $userAgent, $referrer)
    {
        // No IP -> cannot screen; fail safe (allow).
        if ($ip === '') {
            return false;
        }

        // Whitelisted IPs are never blocked.
        if (in_array($ip, $this->whitelist, true)) {
            return false;
        }

        $cacheKey = 'ipblock_' . md5($ip . '|' . $userAgent . '|' . $referrer);

        // Cache lookup (native PrestaShop cache).
        if ($this->cacheTtl > 0) {
            $cached = $this->cacheGet($cacheKey);
            if ($cached !== null) {
                return $cached === '1';
            }
        }

        // Live lookup.
        $action = $this->client->check($ip, $userAgent, $referrer);

        if ($action === null) {
            // Error/timeout/non-2xx/missing action => apply fail mode.
            // fail open => allow (do not block); fail closed => block.
            return !$this->failOpen;
        }

        $blocked = ($action === 'block');

        if ($this->cacheTtl > 0) {
            $this->cacheSet($cacheKey, $blocked ? '1' : '0');
        }

        return $blocked;
    }

    /**
     * @return string[]
     */
    private function parseWhitelist($raw)
    {
        if (!is_string($raw) || $raw === '') {
            return array();
        }
        $lines = preg_split('/\r\n|\r|\n/', $raw);
        $out = array();
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line !== '') {
                $out[] = $line;
            }
        }

        return $out;
    }

    /**
     * Read a cached decision ('1' block, '0' allow, null on miss).
     * Wrapped in try/catch so a missing cache backend degrades to "no cache".
     *
     * @return string|null
     */
    private function cacheGet($key)
    {
        try {
            $cache = Cache::getInstance();
            if ($cache && $cache->exists($key)) {
                return (string) $cache->get($key);
            }
        } catch (Exception $e) {
            // ignore -- treat as cache miss
        }

        return null;
    }

    private function cacheSet($key, $value)
    {
        try {
            $cache = Cache::getInstance();
            if ($cache) {
                $cache->set($key, $value, $this->cacheTtl);
            }
        } catch (Exception $e) {
            // ignore -- caching is best effort
        }
    }
}
