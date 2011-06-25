<?php

/**
 * Options for the CSP Header Plugin
 * 
 * @author    Matthias Schulte <post@lupo49.de>
 */

$conf['enableHeader']        = 0;       // Enable/Disable the header
$conf['allowValue']          = '\'self\'';  // Set value for the "allow" directive
$conf['optionsInline']       = 0;       // Set values for tha "options inline-script" directive
$conf['optionsEval']         = 0;       // Set values for tha "options eval-script" directive
$conf['imgsrcValue']         = '';
$conf['mediasrcValue']       = '';
$conf['scriptsrcValue']      = '';
$conf['objectsrcValue']      = '';
$conf['framesrcValue']       = '';
$conf['fontsrcValue']        = '';
$conf['xhrsrcValue']         = '';
$conf['frameancestorsValue'] = '';
$conf['stylesrcValue']       = '';
$conf['reporturiValue']      = '';
$conf['policyuriValue']      = '';