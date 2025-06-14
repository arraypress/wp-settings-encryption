<?php
/**
 * Settings Encryption Utility Functions - Streamlined
 *
 * @package     ArrayPress\WP\SettingsEncryption
 * @copyright   Copyright (c) 2025, ArrayPress Limited
 * @license     GPL2+
 * @version     1.4.0
 * @author      David Sherlock
 */

declare( strict_types=1 );

namespace ArrayPress\WP;

use WP_Error;

defined( 'ABSPATH' ) || exit;

if ( ! function_exists( 'ArrayPress\WP\create_encryption_instance' ) ):
	/**
	 * Create a new encryption instance with specific configuration
	 *
	 * @param string      $prefix         Prefix for options/constants (e.g., 'wc_r2')
	 * @param string|null $key            Optional. Custom encryption key.
	 * @param bool        $auto_intercept Optional. Whether to automatically intercept get_option calls.
	 *
	 * @return SettingsEncryption
	 */
	function create_encryption_instance( string $prefix, ?string $key = null, bool $auto_intercept = true ): SettingsEncryption {
		return new SettingsEncryption( $prefix, $key, $auto_intercept );
	}
endif;

if ( ! function_exists( 'ArrayPress\WP\encrypt_value' ) ):
	/**
	 * Encrypt a value (using default instance)
	 *
	 * @param string $value Value to encrypt
	 *
	 * @return string|WP_Error Encrypted value or WP_Error on failure
	 */
	function encrypt_value( string $value ) {
		static $default_instance;
		if ( ! $default_instance ) {
			$default_instance = new SettingsEncryption( 'wp' );
		}

		return $default_instance->encrypt( $value );
	}
endif;

if ( ! function_exists( 'ArrayPress\WP\decrypt_value' ) ):
	/**
	 * Decrypt a value (using default instance)
	 *
	 * @param string $value Value to decrypt
	 *
	 * @return string|WP_Error Decrypted value or WP_Error on failure
	 */
	function decrypt_value( string $value ) {
		static $default_instance;
		if ( ! $default_instance ) {
			$default_instance = new SettingsEncryption( 'wp' );
		}

		return $default_instance->decrypt( $value );
	}
endif;

if ( ! function_exists( 'ArrayPress\WP\is_value_encrypted' ) ):
	/**
	 * Check if a value is encrypted
	 *
	 * @param string $value Value to check
	 *
	 * @return bool Whether the value is encrypted
	 */
	function is_value_encrypted( string $value ): bool {
		// Simple check - most encryption prefixes start with __
		return str_starts_with( $value, '__' ) && str_contains( $value, '_ENCRYPTED__' );
	}
endif;

if ( ! function_exists( 'ArrayPress\WP\test_encryption' ) ):
	/**
	 * Check if encryption is working properly
	 *
	 * @return bool Whether encryption/decryption is working
	 */
	function test_encryption(): bool {
		$test_value = 'test123';
		$encrypted  = encrypt_value( $test_value );
		if ( is_wp_error( $encrypted ) ) {
			return false;
		}
		$decrypted = decrypt_value( $encrypted );

		return ! is_wp_error( $decrypted ) && $decrypted === $test_value;
	}
endif;

if ( ! function_exists( 'ArrayPress\WP\has_dedicated_encryption_key' ) ):
	/**
	 * Check if a dedicated encryption key is defined
	 *
	 * @return bool Whether WP_ENCRYPTION_KEY constant is defined
	 */
	function has_dedicated_encryption_key(): bool {
		return defined( 'WP_ENCRYPTION_KEY' ) && ! empty( constant( 'WP_ENCRYPTION_KEY' ) );
	}
endif;