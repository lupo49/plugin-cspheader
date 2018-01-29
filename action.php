<?php

/**
 * DokuWiki Content Security Policy (CSP) plugin
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Matthias Schulte <post@lupo49.de>
 * @link       http://www.dokuwiki.org/plugin:cspheader
 */

// must be run within Dokuwiki
if (!defined('DOKU_INC')) die();
if (!defined('DOKU_PLUGIN')) define('DOKU_PLUGIN', DOKU_INC . 'lib/plugins/');

require_once DOKU_PLUGIN.'action.php';

class action_plugin_cspheader extends DokuWiki_Action_Plugin {

    /**
     * CSP Headers
     */
    const CSP_HEADER = 'Content-Security-Policy: ';
    const X_CSP_HEADER = 'X-Content-Security-Policy: ';

    /**
     * @var array $directives Mapping plugin's options to CSP directives
     */
    private $directives = array(
        'allowValue' => 'allow ',
        'imgsrcValue' => 'img-src ',
        'scriptsrcValue' => 'script-src ',
        'objectsrcValue' => 'object-src ',
        'framesrcValue' => 'frame-src ',
        'fontsrcValue' => 'font-src ',
        'xhrsrcValue' => 'xhr-src ',
        'frameancestorsValue' => 'frame-ancestors ',
        'stylesrcValue' => 'style-src ',
        'reporturiValue' => 'report-uri ',
        'policyuriValue' => 'policy-uri ',
    );

    /**
     * @var array $cspvalues
     */
    private $cspvalues = array();

    /**
     * Register the event handler.
     * @param Doku_Event_Handler $controller
     */
    function register(Doku_Event_Handler $controller) {
        $controller->register_hook('ACTION_HEADERS_SEND', 'BEFORE', $this, 'handle_headers_send');
    }

    /**
     * Handler for the ACTION_HEADERS_SEND event
     * @param &$event
     * @param $params
     */
    function handle_headers_send(&$event, $params) {
        global $conf;

        if($this->getConf('enableHeader')) {
            // Take care of spaces and semicolons betweeen the directives

            // host-expr examples: http://*.foo.com, mail.foo.com:443, https://store.foo.com
            // Besides FQDNs there are some keywords which are allowed 'self', 'none' or data:-URIs
            // Documentation: https://developer.mozilla.org/en/Security/CSP/CSP_policy_directives

            // allow host-expr
            $this->set_csp_value('allowValue');

            // options [inline-script|eval-script]
            $opt_inline = $this->getConf('optionsInline') ? ' inline-script' : '';
            $opt_eval = $this->getConf('optionsEval') ? ' eval-script' : '';
            if($opt_inline || $opt_eval) {
                $optionsline = 'options'. $opt_inline . $opt_eval;
                array_push($this->cspvalues, $optionsline);
            }

            // img-src host-expr
            $this->set_csp_value('imgsrcValue');

            // media-src host-expr
            $this->set_csp_value('mediasrcValue');

            // script-src host-expr
            $this->set_csp_value('scriptsrcValue');

            // object-src host-expr
            $this->set_csp_value('objectsrcValue');

            // frame-src host-expr
            $this->set_csp_value('framesrcValue');

            // font-src host-expr
            $this->set_csp_value('fontsrcValue');

            // xhr-src host-expr
            $this->set_csp_value('xhrsrcValue');

            // frame-ancestors host-expr
            $this->set_csp_value('frameancestorsValue');

            // style-src host-expr
            $this->set_csp_value('stylesrcValue');

            // report-uri uri
            $this->set_csp_value('reporturiValue');

            // policy-uri uri
            $this->set_csp_value('policyuriValue');

            // concat array elements seperated by a semicolon and a space
            $header = implode('; ', $this->cspvalues);

            if($conf["allowdebug"]) msg("CSPheader plugin (DEBUG): ". $header);

            // add the CSP header to the existing headers
            array_push($event->data, self::CSP_HEADER . $header);
            array_push($event->data, self::X_CSP_HEADER . $header);
        }
    }

    /**
     * Sets the CSP
     * @param string $option
     */
     private function set_csp_value($option) {
        $conf = $this->getConf($option);
        if($conf) {
            array_push($this->cspvalues, $this->directives[$option] . $conf);
        }
    }
}
