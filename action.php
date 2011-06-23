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
     * return some info
     */
    function getInfo() {
        return array (
            'author' => 'Matthias Schulte',
            'email'  => 'post@lupo49.de',
            'date'   => '2011-06-23',
            'name'   => 'Content Security Policy (CSP) plugin',
            'desc'   => 'Injects Content Security Policy (CSP) headers.',
            'url'    => 'http://www.dokuwiki.org/plugin:cspheader',
        );
    }

    /**
     * Register the eventhandler.
     */
    function register(&$controller) {
        $controller->register_hook('ACTION_HEADERS_SEND', 'BEFORE', $this, 'handle_headers_send');
    }

    /**
     * Handler for the ACTION_HEADERS_SEND event
     */
    function handle_headers_send(&$event, $params) {
        // Documentation: https://developer.mozilla.org/en/Security/CSP/CSP_policy_directives
       $cspheader = 'X-Content-Security-Policy:';
       
        if($this->getConf('enableHeader')) {
            
            // Set the value for the "allow" directive
            if($this->getConf('allowValue')) {
                $cspheader .= 'allow ' . '\'' . $this->getConf('allowValue') . '\'';
            } else {
                $cspheader .= 'allow \'self\'';
            }
            
            // add the CSP header to the existing headers
            array_push($event->data, $cspheader);
        }
    }
}