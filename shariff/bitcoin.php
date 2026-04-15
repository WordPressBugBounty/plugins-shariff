<?php /** @noinspection PhpCSValidationInspection */
/**
 * Generates an QR code for bitcoin.
 *
 * @package Shariff Wrapper
 */

// prevent external use (as is requested by the automated Plugin Check)
if ( ! defined( 'ABSPATH' ) ) { define( 'ABSPATH', __DIR__ . '/' ); }
if ( ! defined( 'ABSPATH' ) ) exit;

// Includes php class for QR code generation.
require './includes/phpqrcode.php';

// Gets the bitcoin address.
$bitcoinaddress = htmlspecialchars( $_GET['bitcoinaddress'] );
// real plausi check on valid address and nothing else
if ( ! preg_match( '/^([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,87})$/', $bitcoinaddress ) ) { http_response_code(400);  die(); }

// Creates the page.
echo '<html lang="en"><head><title>Bitcoin</title></head><body>';
echo '<div style="text-align:center;"><h1>Bitcoin</h1></div>';
echo '<p style="text-align:center;"><a href="bitcoin:' . $bitcoinaddress . '">bitcoin:' . $bitcoinaddress . '</a></p>';
echo '<p style="text-align:center;">';
QRcode::svg( $bitcoinaddress, false, 'h', 5 );
echo '</p>';
echo '<p style="text-align:center;">Information: <a href="https://www.bitcoin.org" target="_blank">bitcoin.org</a></p>';
echo '</body></html>';
