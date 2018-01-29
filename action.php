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
     * Register the eventhandler.
     */
    function register(Doku_Event_Handler $controller) {
        $controller->register_hook('ACTION_HEADERS_SEND', 'BEFORE', $this, 'handle_headers_send');
    }

    /**
     * Handler for the ACTION_HEADERS_SEND event
     */
    function handle_headers_send(&$event, $params) {
        global $conf;
        $xcspheader = 'X-Content-Security-Policy: ';
        $cspheader = 'Content-Security-Policy: ';
        $cspvalues = array();

        if($this->getConf('enableHeader')) {
            // Take care of spaces and semicolons betweeen the directives

            // host-expr examples: http://*.foo.com, mail.foo.com:443, https://store.foo.com
            // Besides FQDNs there are some keywords which are allowed 'self', 'none' or data:-URIs
            // Documentation: https://developer.mozilla.org/en/Security/CSP/CSP_policy_directives

            // allow host-expr
            if($this->getConf('allowValue')) {
                $allow = 'allow ' . $this->getConf('allowValue');
                array_push($cspvalues, $allow);
            }

            // options [inline-script|eval-script]
            if($this->getConf('optionsInline') || $this->getConf('optionsEval')) {
                $optionsline = 'options';

                if($this->getConf('optionsInline')) $optionsline .= ' inline-script';
                if($this->getConf('optionsEval')) $optionsline .= ' eval-script';

                array_push($cspvalues, $optionsline);
            }

            // img-src host-expr
            if($this->getConf('imgsrcValue')) {
                $imgsrc = 'img-src ' . $this->getConf('imgsrcValue');
                array_push($cspvalues, $imgsrc);
            }

            // media-src host-expr
            if($this->getConf('mediasrcValue')) {
                $mediasrc = ' media-src ' . $this->getConf('mediasrcValue');
                array_push($cspvalues, $mediasrc);
            }

            // script-src host-expr
            if($this->getConf('scriptsrcValue')) {
                $scriptsrc = 'script-src ' . $this->getConf('scriptsrcValue');
                array_push($cspvalues, $scriptsrc);
            }

            // object-src host-expr
            if($this->getConf('objectsrcValue')) {
                $objectsrc = 'object-src ' . $this->getConf('objectsrcValue');
                array_push($cspvalues, $objectsrc);
            }

            // frame-src host-expr
            if($this->getConf('framesrcValue')) {
                $framesrc = 'frame-src ' . $this->getConf('framesrcValue');
                array_push($cspvalues, $framesrc);
            }

            // font-src host-expr
            if($this->getConf('fontsrcValue')) {
                $fontsrc = 'font-src ' . $this->getConf('fontsrcValue');
                array_push($cspvalues, $fontsrc);
            }

            // xhr-src host-expr
            if($this->getConf('xhrsrcValue')) {
                $xhrsrc = 'xhr-src ' . $this->getConf('xhrsrcValue');
                array_push($cspvalues, $xhrsrc);
            }

            // frame-ancestors host-expr
            if($this->getConf('frameancestorsValue')) {
                $frameancestors = 'frame-ancestors ' . $this->getConf('frameancestorsValue');
                array_push($cspvalues, $frameancestors);
            }

            // style-src host-expr
            if($this->getConf('stylesrcValue')) {
                $stylesrc = 'style-src ' . $this->getConf('stylesrcValue');
                array_push($cspvalues, $stylesrc);
            }

            // report-uri uri
            if($this->getConf('reporturiValue')) {
                $reportui = 'report-uri ' . $this->getConf('reporturiValue');
                array_push($cspvalues, $reportui);
            }

            // policy-uri uri
            if($this->getConf('policyuriValue')) {
                $policyuri = 'policy-uri ' . $this->getConf('policyuriValue');
                array_push($cspvalues, $policyuri);
            }

            // concat each array element seperated by a semicolon and a space
            $xcspheader .= implode('; ', $cspvalues); 
            $cspheader .= implode('; ', $cspvalues);

            if($conf["allowdebug"]) msg("CSPheader plugin (DEBUG): ". $cspheader);

            // add the CSP header to the existing headers
            array_push($event->data, $cspheader);
            array_push($event->data, $xcspheader);
        }
    }
}
