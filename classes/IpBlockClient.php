<?php
/**
 * IpBlockClient -- thin HTTP client for the ip-block.com API.
 *
 * Contract:
 *   POST {api_url}
 *   Content-Type: application/json
 *   body: {"api_key","site_id","ip","user_agent","referrer"}   (api_key in BODY)
 *   response: {"action":"allow"|"block"}
 *   1 second timeout. Any error/timeout/non-2xx/missing action => null.
 *
 * @author IP-Block.com
 */

if (!defined('_PS_VERSION_')) {
    exit;
}

class IpBlockClient
{
    /** @var string */
    private $apiUrl;
    /** @var string */
    private $apiKey;
    /** @var string */
    private $siteId;
    /** @var int seconds */
    private $timeout;

    public function __construct($apiUrl, $apiKey, $siteId, $timeout = 1)
    {
        $this->apiUrl = $apiUrl;
        $this->apiKey = (string) $apiKey;
        $this->siteId = (string) $siteId;
        $this->timeout = max(1, (int) $timeout);
    }

    /**
     * Ask the service whether an IP should be allowed or blocked.
     *
     * @return string|null 'allow', 'block', or null on any failure.
     */
    public function check($ip, $userAgent, $referrer)
    {
        $payload = json_encode(array(
            'api_key' => $this->apiKey,
            'site_id' => $this->siteId,
            'ip' => $ip,
            'user_agent' => $userAgent,
            'referrer' => $referrer,
        ));

        $response = $this->post($this->apiUrl, $payload);
        if ($response === null) {
            return null;
        }

        $data = json_decode($response, true);
        if (!is_array($data) || !isset($data['action'])) {
            return null; // missing action => fail mode upstream
        }

        return $data['action'] === 'block' ? 'block' : 'allow';
    }

    /**
     * Optional health check: GET {base}/ping -> {"status":"ok"}.
     *
     * @return bool
     */
    public function ping()
    {
        $pingUrl = preg_replace('#/check/?$#', '/ping', $this->apiUrl);

        $ch = curl_init($pingUrl);
        curl_setopt_array($ch, array(
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => $this->timeout,
            CURLOPT_HTTPGET => true,
        ));
        $body = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($status < 200 || $status >= 300 || $body === false) {
            return false;
        }
        $data = json_decode($body, true);

        return is_array($data) && isset($data['status']) && $data['status'] === 'ok';
    }

    /**
     * Perform the POST. Returns the raw body on 2xx, otherwise null.
     *
     * @return string|null
     */
    private function post($url, $jsonPayload)
    {
        if (!function_exists('curl_init')) {
            return null;
        }

        $ch = curl_init($url);
        curl_setopt_array($ch, array(
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $jsonPayload,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeout,        // hard cap (seconds)
            CURLOPT_CONNECTTIMEOUT => $this->timeout,
            CURLOPT_HTTPHEADER => array(
                'Content-Type: application/json',
                'Accept: application/json',
            ),
        ));

        $body = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_errno($ch);
        curl_close($ch);

        if ($error !== 0 || $body === false || $status < 200 || $status >= 300) {
            return null;
        }

        return $body;
    }
}
