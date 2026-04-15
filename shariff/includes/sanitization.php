<?php
/**
 *
 * @package Shariff Wrapper
 *
 */

// Prevent direct calls.
if ( ! class_exists( 'WP' ) ) { die(); }
// and again the same because the WP Plugin Check does not understand what the line above does ;-)
if ( ! defined( 'ABSPATH' ) ) exit; 


/**
 * Strip hex-encoded input of hackers to naked plain text the
 * WP core functions can work with
**/
function strip_hackers( $input ) {
    // make URL encodings readable (e.g. %3c to < )
    $input = rawurldecode( $input );
    // convert potencial hex-codes to plain text for checks with wp_kess() and so on (e.g. \x3c -> <)
    $input = preg_replace_callback('/\\\\x([0-9a-fA-F]{2})/', function($m) { return chr(hexdec($m[1])); }, $input);
    // convert HTML entities (e.g. &#x3c; to < )
    $input = html_entity_decode( $input, ENT_QUOTES | ENT_HTML5, 'UTF-8' );

    return $input;
}

/**
 * Sanitizes input from the basic settings page.
 *
 * @param array $input Input from settings page to sanitize.
 *
 * @return array Sanitized array with settings.
 */
function shariff3uu_basic_sanitize( $input ) {
	// Create array.
	$valid = array();

	if ( isset( $input['version'] ) ) {
          $valid['version'] = ( isset( $input['version'] ) && preg_match( '/^\d+(\.\d+){0,2}$/', $input['version'] ) ) ? $input['version'] : '0.0.0';		
	}
	if ( isset( $input['services'] ) ) {
		$valid['services'] = trim( preg_replace( '/[^A-Za-z|]/', '', sanitize_text_field( strip_hackers($input['services']) ) ), '|' );
	}
        if ( isset( $input['add_after'] ) && is_array( $input['add_after'] ) ) {
          // check all array elements with sanitize_key()
          $valid['add_after'] = array_map( 'sanitize_key', $input['add_after'] );
          // remove empty
          $valid['add_after'] = array_filter( $valid['add_after'] );
        }
        if ( isset( $input['add_before'] ) && is_array( $input['add_before'] ) ) {
          // check all array elements with sanitize_key()
          $valid['add_before'] = array_map( 'sanitize_key', $input['add_before'] );
          // remove empty 
          $valid['add_before'] = array_filter( $valid['add_before'] );
        }
	if ( isset( $input['disable_on_protected'] ) ) {
	  $valid['disable_on_protected'] = isset( $input['disable_on_protected'] ) ? 1 : 0;
	}
	if ( isset( $input['disable_outside_loop'] ) ) {
          $valid['disable_outside_loop'] = isset( $input['disable_outside_loop'] ) ? 1 : 0;
	}
	if ( isset( $input['custom_hooks'] ) ) {
		$valid['custom_hooks'] = sanitize_text_field( strip_hackers($input['custom_hooks']) );
	}
	if ( isset( $input['custom_hooks_shortcode'] ) ) {
		$valid['custom_hooks_shortcode'] = sanitize_text_field( strip_hackers($input['custom_hooks_shortcode']) );
	}

	// Remove empty elements.
	$valid = array_filter( $valid );

	return $valid;
}

/**
 * Sanitizes input from the design settings page.
 *
 * @param array $input Input from settings page to sanitize.
 *
 * @return array Sanitized array with settings.
 */
function shariff3uu_design_sanitize( $input ) {
	// Create array.
	$valid = array();

	if ( isset( $input['lang'] ) ) {
          // all implemented languages
          $allowed_lang = [ 'bg', 'cs', 'da', 'de', 'en', 'es', 'fi', 'fr', 'hr', 'hu', 'it', 'ja', 'ko', 'nl', 'no', 'pl', 'pt', 'ro', 'ru', 'sk', 'sl', 'sr', 'sv', 'tr', 'zh' ];
          // default en
          $valid['lang'] = in_array( $input['lang'], $allowed_lang, true ) ? $input['lang'] : 'en';
	}
	if ( isset( $input['autolang'] ) ) {
		$valid['autolang'] = isset( $input['autolang'] ) ? 1 : 0;
	}
	if ( isset( $input['theme'] ) ) {
		$valid['theme'] = in_array( $input['theme'], ['color', 'grey', 'white', 'round', 'wcag'], true ) ? $input['theme'] : '';
	}
	if ( isset( $input['buttonsize'] ) ) {
		$valid['buttonsize'] = in_array( $input['buttonsize'], ['small', 'medium', 'large'], true ) ? $input['buttonsize'] : 'medium';
	}
	if ( isset( $input['buttonstretch'] ) ) {
		$valid['buttonstretch'] = isset( $input['buttonstretch'] ) ? 1 : 0;
	}
	if ( isset( $input['borderradius'] ) ) {
		$valid['borderradius'] = min( max( absint( $input['borderradius'] ), 1 ), 50 );
	}
	if ( isset( $input['maincolor'] ) ) {
		$valid['maincolor'] = (isset($input['maincolor']) && preg_match('/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/', $input['maincolor'])) ? $input['maincolor'] : '';
	}
	if ( isset( $input['secondarycolor'] ) ) {
		$valid['secondarycolor'] = (isset($input['secondarycolor']) && preg_match('/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/', $input['secondarycolor'])) ? $input['secondarycolor'] : '';
	}
	if ( isset( $input['vertical'] ) ) {
		$valid['vertical'] = isset( $input['vertical'] ) ? 1 : 0;		
	}
	if ( isset( $input['align'] ) ) {
		$valid['align'] = in_array($input['align'], ['left', 'center', 'right']) ? $input['align'] : 'left';
	}
	if ( isset( $input['align_widget'] ) ) {
		$valid['align_widget'] = in_array($input['align_widget'], ['left', 'center', 'right']) ? $input['align_widget'] : 'left';
	}
	if ( isset( $input['style'] ) ) {
		$valid['style'] = sanitize_text_field( strip_hackers($input['style']) ); 
	}
	if ( isset( $input['cssclass'] ) ) {
		$valid['cssclass'] = sanitize_text_field( strip_hackers($input['cssclass']) );
	}
	if ( isset( $input['headline'] ) ) {
		// check against allowed tags
		$valid['headline'] = wp_kses( strip_hackers($input['headline']) , $GLOBALS['allowed_tags'] );
	}
	if ( isset( $input['headline_zero'] ) ) {
		$valid['headline_zero'] = wp_kses( strip_hackers($input['headline_zero']) , $GLOBALS['allowed_tags'] );
	}
	if ( isset( $input['hideuntilcss'] ) ) {
		$valid['hideuntilcss'] = absint( $input['hideuntilcss'] );
	}
	if ( isset( $input['popup'] ) ) {
		$valid['popup'] = absint( $input['popup'] );
	}

	// Remove empty elements.
	$valid = array_filter( $valid );

	return $valid;
}

/**
 * Sanitize input from the advanced settings page.
 *
 * @param array $input Input from settings page to sanitize.
 *
 * @return array Sanitized array with settings.
 */
function shariff3uu_advanced_sanitize( $input ) {
	// Creates array.
	$valid = array();

	if ( isset( $input['info_url'] ) ) {
		$valid['info_url'] = esc_url_raw( strip_hackers( $input['info_url'] ) );
	}
	if ( isset( $input['info_text'] ) ) {
		$valid['info_text'] = sanitize_text_field( strip_hackers( $input['info_text'] ) );
	}
	if ( isset( $input['twitter_via'] ) ) {
		$input['twitter_via'] = ltrim( strip_hackers( $input['twitter_via'] ), "@" );
		$valid['twitter_via'] = preg_replace( '/[^a-zA-Z0-9_]/', '', $input['twitter_via'] );
	}
	if ( isset( $input['bluesky_via'] ) ) {
		$input['bluesky_via'] = ltrim( strip_hackers( $input['bluesky_via'] ), "@" );
		$valid['bluesky_via'] = preg_replace( '/[^a-zA-Z0-9\.\-]/', '', $input['bluesky_via'] );
	}
	if ( isset( $input['mastodon_via'] ) ) {
		$valid['mastodon_via'] = ltrim( sanitize_text_field( strip_hackers( $input['mastodon_via'] ) ), "@");
	}
	if ( isset( $input['patreonid'] ) ) {
		$input['patreonid'] = strip_hackers( $input['patreonid'] );
		$valid['patreonid'] = preg_replace( '/[^a-zA-Z0-9_\-]/', '', $input['patreonid'] );
	}
	if ( isset( $input['paypalbuttonid'] ) ) {
		$valid['paypalbuttonid'] = sanitize_text_field( strip_hackers( $input['paypalbuttonid'] ) );
	}
	if ( isset( $input['paypalmeid'] ) ) {
		$valid['paypalmeid'] = sanitize_text_field( ltrim( strip_hackers( $input['paypalmeid'] ) ) );
	}
	if ( isset( $input['bitcoinaddress'] ) ) {
	    // hex weg
	    $input['bitcoinaddress'] = strip_hackers( $input['bitcoinaddress'] );
	    // only alphanumeric (a-z, A-Z, 0-9)
	    // is valid for older (1..., 3...) and newer (bc1...) adresses
	    $valid['bitcoinaddress'] = preg_replace( '/[^a-zA-Z0-9]/', '', $input['bitcoinaddress'] );
	}	
	if ( isset( $input['rssfeed'] ) ) {
		$valid['rssfeed'] = esc_url_raw( strip_hackers( $input['rssfeed'] ) );
	}
	if ( isset( $input['default_pinterest'] ) ) {
		$valid['default_pinterest'] = sanitize_text_field( strip_hackers( $input['default_pinterest'] ) );
	}
	if ( isset( $input['hide_whatsapp'] ) ) {
		$valid['hide_whatsapp'] = isset( $input['hide_whatsapp'] ) ? 1 : 0;
	}
	if ( isset( $input['shortcodeprio'] ) ) {
		$valid['shortcodeprio'] = absint( $input['shortcodeprio'] );
	}
	if ( isset( $input['disable_metabox'] ) ) {
		$valid['disable_metabox'] = isset( $input['disable_metabox'] ) ? 1 : 0;
	}

	// Remove empty elements.
	$valid = array_filter( $valid );

	return $valid;
}

/**
 * Sanitizes input from the statistic settings page.
 *
 * @param array $input Input from settings page to sanitize.
 *
 * @return array Sanitized array with settings.
 */
function shariff3uu_statistic_sanitize( $input ) {
	// Creates array.
	$valid = array();

	if ( isset( $input['backend'] ) ) {
	  $valid['backend'] = isset( $input['backend'] ) ? 1 : 0;
	}
	if ( isset( $input['sharecounts'] ) ) {
	  $valid['sharecounts'] = isset( $input['sharecounts'] ) ? 1 : 0;
	}
	if ( isset( $input['hidezero'] ) ) {
	  $valid['hidezero'] = isset( $input['hidezero'] ) ? 1 : 0;
	}
	if ( isset( $input['ranking'] ) ) {
          $valid['ranking'] = absint( $input['ranking'] );
	}
	if ( isset( $input['automaticcache'] ) ) {
          $valid['automaticcache'] = absint( $input['automaticcache'] );
	}
	if ( isset( $input['fb_id'] ) ) {
	# $valid['fb_id'] = absint( $input['fb_id'] );
          $valid['fb_id'] = preg_replace( '/[^0-9]/', '', $input['fb_id'] );
	}
	if ( isset( $input['fb_secret'] ) ) {
          $input['fb_secret'] = strip_hackers( $input['fb_secret'] );
          $valid['fb_secret'] = preg_replace( '/[^a-zA-Z0-9]/', '', $input['fb_secret'] );
	}
	if ( isset( $input['ttl'] ) ) {
          $valid['ttl'] = absint( $input['ttl'] );
	}
	if ( isset( $input['disable_dynamic_cache'] ) ) {
	  $valid['disable_dynamic_cache'] = isset( $input['disable_dynamic_cache'] ) ? 1 : 0;
	}

	if ( isset( $input['disable'] ) && is_array( $input['disable'] ) ) {
	  $allowed = [ 'facebook', 'pinterest', 'tumblr', 'vk', 'odnoklassniki', 'buffer' ];
          $found = [];
          foreach ( $input['disable'] as $key => $value ) {
            if ( in_array( $key, $allowed, true ) ) {
               $found[$key] = "1"; 
             }
           }
           $valid['disable'] = $found;
         } else {
         $valid['disable'] = [];
        }

	if ( isset( $input['external_host'] ) ) {
		$host = strip_hackers( $input['external_host'] );
		$valid['external_host'] = str_replace( ' ', '', rtrim( esc_url_raw( $input['external_host'], '/' ) ) );
	}
	if ( isset( $input['external_direct'] ) ) {
		$valid['external_direct'] = isset( $input['external_direct'] ) ? 1 : 0;
	}
	if ( isset( $input['subapi'] ) ) {
		$valid['subapi'] = isset( $input['subapi'] ) ? 1 : 0;
	}
	
	// Protect users from themselves.
	if ( isset( $input['ttl'] ) ) {
	  $ttl = absint( $input['ttl'] );
	  if ( $ttl < 60 ) { 
	    $valid['ttl'] = ''; 
          } elseif ( $ttl > 7200 ) {
            $valid['ttl'] = '7200';
          } else {
            $valid['ttl'] = (string) $ttl;
          }
       }
	// Remove empty elements.
	$valid = array_filter( $valid );

	return $valid;
}
