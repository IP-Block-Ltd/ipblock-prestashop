<?php
/**
 * IP Block Protection for PrestaShop
 *
 * Integrates the ip-block.com IP screening service. On every FRONT-OFFICE
 * request it determines the real client IP, asks the ip-block.com API whether
 * that visitor should be allowed, and blocks flagged visitors (redirect or 403).
 *
 * Back-office (admin) requests are NEVER screened so the operator can never be
 * locked out of PrestaShop. The whitelist is always honoured.
 *
 * Shared API contract:
 *   POST https://api.ip-block.com/v1/check
 *   body: {"api_key","site_id","ip","user_agent","referrer"}
 *   response: {"action":"allow"|"block"}  -> block ONLY when action === "block"
 *   1 second timeout; any error/timeout/non-2xx/missing action => fail mode.
 *
 * @author    IP-Block.com
 * @copyright IP-Block.com
 * @license   GPL-3.0-or-later
 */

if (!defined('_PS_VERSION_')) {
    exit;
}

require_once __DIR__ . '/classes/IpBlockClient.php';
require_once __DIR__ . '/classes/IpBlockChecker.php';

class IpBlockProtection extends Module
{
    /** Configuration keys stored in the ps_configuration table. */
    const CFG_ENABLED       = 'IPBLOCK_ENABLED';
    const CFG_SITE_ID       = 'IPBLOCK_SITE_ID';
    const CFG_API_KEY       = 'IPBLOCK_API_KEY';
    const CFG_API_URL       = 'IPBLOCK_API_URL';
    const CFG_FAIL_OPEN     = 'IPBLOCK_FAIL_OPEN';
    const CFG_CACHE_TTL     = 'IPBLOCK_CACHE_TTL';
    const CFG_BEHIND_PROXY  = 'IPBLOCK_BEHIND_PROXY';
    const CFG_BLOCK_ACTION  = 'IPBLOCK_BLOCK_ACTION';
    const CFG_BLOCK_MESSAGE = 'IPBLOCK_BLOCK_MESSAGE';
    const CFG_WHITELIST     = 'IPBLOCK_WHITELIST';

    const DEFAULT_API_URL  = 'https://api.ip-block.com/v1/check';
    const BLOCKED_REDIRECT = 'https://www.ip-block.com/blocked.php';

    public function __construct()
    {
        $this->name = 'ipblockprotection';
        $this->tab = 'administration';
        $this->version = '1.0.0';
        $this->author = 'IP-Block.com';
        $this->need_instance = 0;
        // Works on PrestaShop 1.7, 8.x and 9.x (built/verified against 9.1.4).
        $this->ps_versions_compliancy = array('min' => '1.7.0.0', 'max' => _PS_VERSION_);
        $this->bootstrap = true;

        parent::__construct();

        $this->displayName = $this->l('IP Block Protection');
        $this->description = $this->l('Screens front-office visitors against the ip-block.com service and blocks flagged IP addresses.');
        $this->confirmUninstall = $this->l('Are you sure you want to uninstall IP Block Protection?');
    }

    /**
     * Install: register the earliest front dispatcher hook and seed defaults.
     */
    public function install()
    {
        if (!parent::install()) {
            return false;
        }

        // actionDispatcherBefore fires in Dispatcher::dispatch() before the
        // front controller is instantiated/run -- the earliest safe hook.
        if (!$this->registerHook('actionDispatcherBefore')) {
            return false;
        }

        // Sensible, safe-by-default configuration.
        Configuration::updateValue(self::CFG_ENABLED, 0);
        Configuration::updateValue(self::CFG_SITE_ID, '');
        Configuration::updateValue(self::CFG_API_KEY, '');
        Configuration::updateValue(self::CFG_API_URL, self::DEFAULT_API_URL);
        Configuration::updateValue(self::CFG_FAIL_OPEN, 1);   // default FAIL OPEN (allow)
        Configuration::updateValue(self::CFG_CACHE_TTL, 300);
        Configuration::updateValue(self::CFG_BEHIND_PROXY, 0);
        Configuration::updateValue(self::CFG_BLOCK_ACTION, 'redirect');
        Configuration::updateValue(self::CFG_BLOCK_MESSAGE, 'Access denied.');
        Configuration::updateValue(self::CFG_WHITELIST, '');

        return true;
    }

    public function uninstall()
    {
        foreach (array(
            self::CFG_ENABLED, self::CFG_SITE_ID, self::CFG_API_KEY, self::CFG_API_URL,
            self::CFG_FAIL_OPEN, self::CFG_CACHE_TTL, self::CFG_BEHIND_PROXY,
            self::CFG_BLOCK_ACTION, self::CFG_BLOCK_MESSAGE, self::CFG_WHITELIST,
        ) as $key) {
            Configuration::deleteByName($key);
        }

        return parent::uninstall();
    }

    /**
     * Earliest front-office hook. Runs the IP screening guard.
     *
     * @param array $params Contains 'controller_type' and 'controller_class'.
     */
    public function hookActionDispatcherBefore($params)
    {
        if (!Configuration::get(self::CFG_ENABLED)) {
            return;
        }

        // NEVER screen the back office / installer / CLI. Only guard the
        // front controller and module front controllers (storefront).
        $controllerType = isset($params['controller_type']) ? (int) $params['controller_type'] : 0;
        if ($controllerType !== Dispatcher::FC_FRONT && $controllerType !== Dispatcher::FC_MODULE) {
            return;
        }

        $checker = $this->buildChecker();

        $ip = $checker->getClientIp();
        $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
        $referrer = isset($_SERVER['HTTP_REFERER']) ? (string) $_SERVER['HTTP_REFERER'] : '';

        if ($checker->isBlocked($ip, $userAgent, $referrer)) {
            $this->denyAccess();
        }
    }

    /**
     * Build the checker with a configured HTTP client.
     */
    private function buildChecker()
    {
        $client = new IpBlockClient(
            Configuration::get(self::CFG_API_URL) ?: self::DEFAULT_API_URL,
            Configuration::get(self::CFG_API_KEY),
            Configuration::get(self::CFG_SITE_ID),
            1 // 1 second timeout (contract)
        );

        return new IpBlockChecker(
            $client,
            (bool) Configuration::get(self::CFG_FAIL_OPEN),
            (int) Configuration::get(self::CFG_CACHE_TTL),
            (bool) Configuration::get(self::CFG_BEHIND_PROXY),
            (string) Configuration::get(self::CFG_WHITELIST)
        );
    }

    /**
     * Apply the configured block action: redirect (default) or 403 message.
     */
    private function denyAccess()
    {
        $action = Configuration::get(self::CFG_BLOCK_ACTION);

        if ($action === 'message') {
            header('HTTP/1.1 403 Forbidden');
            header('Content-Type: text/plain; charset=utf-8');
            $message = Configuration::get(self::CFG_BLOCK_MESSAGE);
            echo $message !== false && $message !== '' ? $message : 'Access denied.';
            exit;
        }

        // Default: redirect to the ip-block.com blocked page.
        header('Location: ' . self::BLOCKED_REDIRECT, true, 302);
        exit;
    }

    /**
     * Admin configuration screen (Modules > IP Block Protection > Configure).
     */
    public function getContent()
    {
        $output = '';

        if (Tools::isSubmit('submitIpBlock')) {
            $output .= $this->postProcess();
        }

        return $output . $this->renderForm();
    }

    /**
     * Validate + persist submitted settings.
     */
    private function postProcess()
    {
        $ttl = (int) Tools::getValue(self::CFG_CACHE_TTL);
        if ($ttl < 0) {
            $ttl = 0;
        }

        $apiUrl = trim((string) Tools::getValue(self::CFG_API_URL));
        if ($apiUrl === '' || !Validate::isUrl($apiUrl)) {
            $apiUrl = self::DEFAULT_API_URL;
        }

        Configuration::updateValue(self::CFG_ENABLED, (int) Tools::getValue(self::CFG_ENABLED));
        Configuration::updateValue(self::CFG_SITE_ID, trim((string) Tools::getValue(self::CFG_SITE_ID)));
        Configuration::updateValue(self::CFG_API_KEY, trim((string) Tools::getValue(self::CFG_API_KEY)));
        Configuration::updateValue(self::CFG_API_URL, $apiUrl);
        Configuration::updateValue(self::CFG_FAIL_OPEN, (int) Tools::getValue(self::CFG_FAIL_OPEN));
        Configuration::updateValue(self::CFG_CACHE_TTL, $ttl);
        Configuration::updateValue(self::CFG_BEHIND_PROXY, (int) Tools::getValue(self::CFG_BEHIND_PROXY));
        Configuration::updateValue(self::CFG_BLOCK_ACTION, Tools::getValue(self::CFG_BLOCK_ACTION) === 'message' ? 'message' : 'redirect');
        Configuration::updateValue(self::CFG_BLOCK_MESSAGE, (string) Tools::getValue(self::CFG_BLOCK_MESSAGE));
        // Whitelist: HTML=false so newlines/IPs are preserved verbatim.
        Configuration::updateValue(self::CFG_WHITELIST, (string) Tools::getValue(self::CFG_WHITELIST), false);

        return $this->displayConfirmation($this->l('Settings updated.'));
    }

    /**
     * Build the HelperForm configuration form.
     */
    private function renderForm()
    {
        $switch = array(
            'type' => 'switch',
            'is_bool' => true,
            'values' => array(
                array('id' => 'on', 'value' => 1, 'label' => $this->l('Yes')),
                array('id' => 'off', 'value' => 0, 'label' => $this->l('No')),
            ),
        );

        $fields_form = array(
            'form' => array(
                'legend' => array(
                    'title' => $this->l('IP Block Protection settings'),
                    'icon' => 'icon-shield',
                ),
                'input' => array(
                    array_merge($switch, array(
                        'label' => $this->l('Enable protection'),
                        'name' => self::CFG_ENABLED,
                        'desc' => $this->l('Master on/off switch for front-office IP screening.'),
                    )),
                    array(
                        'type' => 'text',
                        'label' => $this->l('Site ID'),
                        'name' => self::CFG_SITE_ID,
                        'desc' => $this->l('Your ip-block.com site identifier.'),
                    ),
                    array(
                        'type' => 'text',
                        'label' => $this->l('API key'),
                        'name' => self::CFG_API_KEY,
                        'desc' => $this->l('Your ip-block.com API key (sent in the request body).'),
                    ),
                    array(
                        'type' => 'text',
                        'label' => $this->l('API URL'),
                        'name' => self::CFG_API_URL,
                        'desc' => $this->l('Default: ') . self::DEFAULT_API_URL,
                    ),
                    array_merge($switch, array(
                        'label' => $this->l('Fail open'),
                        'name' => self::CFG_FAIL_OPEN,
                        'desc' => $this->l('When the API errors or times out: Yes = allow the visitor (default), No = block.'),
                    )),
                    array(
                        'type' => 'text',
                        'label' => $this->l('Cache TTL (seconds)'),
                        'name' => self::CFG_CACHE_TTL,
                        'desc' => $this->l('How long each decision is cached. 0 = check on every request. Default 300.'),
                    ),
                    array_merge($switch, array(
                        'label' => $this->l('Behind a proxy / CDN'),
                        'name' => self::CFG_BEHIND_PROXY,
                        'desc' => $this->l('Read the real IP from CF-Connecting-IP / X-Forwarded-For.'),
                    )),
                    array(
                        'type' => 'select',
                        'label' => $this->l('Block action'),
                        'name' => self::CFG_BLOCK_ACTION,
                        'options' => array(
                            'query' => array(
                                array('id' => 'redirect', 'name' => $this->l('Redirect to blocked page (default)')),
                                array('id' => 'message', 'name' => $this->l('Show HTTP 403 message')),
                            ),
                            'id' => 'id',
                            'name' => 'name',
                        ),
                    ),
                    array(
                        'type' => 'textarea',
                        'label' => $this->l('Block message'),
                        'name' => self::CFG_BLOCK_MESSAGE,
                        'desc' => $this->l('Shown when Block action = message.'),
                    ),
                    array(
                        'type' => 'textarea',
                        'label' => $this->l('Whitelist'),
                        'name' => self::CFG_WHITELIST,
                        'desc' => $this->l('IP addresses that are never blocked, one per line.'),
                    ),
                ),
                'submit' => array('title' => $this->l('Save')),
            ),
        );

        $helper = new HelperForm();
        $helper->module = $this;
        $helper->name_controller = $this->name;
        $helper->token = Tools::getAdminTokenLite('AdminModules');
        $helper->currentIndex = AdminController::$currentIndex . '&configure=' . $this->name;
        $helper->submit_action = 'submitIpBlock';
        $helper->default_form_language = (int) Configuration::get('PS_LANG_DEFAULT');
        $helper->fields_value = array(
            self::CFG_ENABLED => Configuration::get(self::CFG_ENABLED),
            self::CFG_SITE_ID => Configuration::get(self::CFG_SITE_ID),
            self::CFG_API_KEY => Configuration::get(self::CFG_API_KEY),
            self::CFG_API_URL => Configuration::get(self::CFG_API_URL),
            self::CFG_FAIL_OPEN => Configuration::get(self::CFG_FAIL_OPEN),
            self::CFG_CACHE_TTL => Configuration::get(self::CFG_CACHE_TTL),
            self::CFG_BEHIND_PROXY => Configuration::get(self::CFG_BEHIND_PROXY),
            self::CFG_BLOCK_ACTION => Configuration::get(self::CFG_BLOCK_ACTION),
            self::CFG_BLOCK_MESSAGE => Configuration::get(self::CFG_BLOCK_MESSAGE),
            self::CFG_WHITELIST => Configuration::get(self::CFG_WHITELIST),
        );

        return $helper->generateForm(array($fields_form));
    }
}
