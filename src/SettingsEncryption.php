<?php
/**
 * WordPress Settings Encryption
 *
 * @package     ArrayPress\WP\SettingsEncryption
 * @copyright   Copyright (c) 2025, ArrayPress Limited
 * @license     GPL2+
 * @version     1.0.0
 * @author      David Sherlock
 */

declare( strict_types=1 );

namespace ArrayPress\WP;

use Exception;
use RuntimeException;
use WP_Error;

defined( 'ABSPATH' ) || exit;

/**
 * Class SettingsEncryption
 *
 * Simple utility for encrypting and decrypting WordPress options and settings.
 * Provides secure storage for sensitive data like API keys, passwords, and tokens.
 */
class SettingsEncryption {

	/**
	 * Encryption algorithm to use
	 *
	 * @var string
	 */
	private string $algorithm = 'aes-256-cbc';

	/**
	 * Encryption key
	 *
	 * @var string
	 */
	private string $key;

	/**
	 * Prefix for encrypted values
	 *
	 * @var string
	 */
	private string $prefix;

	/**
	 * Constructor
	 *
	 * @param string|null $key    Optional. Custom encryption key. If null, use WordPress salts.
	 * @param string      $prefix Optional. Prefix for encrypted values. Default '__ENCRYPTED__'.
	 *
	 * @throws RuntimeException If OpenSSL extension is not available or the algorithm is not supported.
	 */
	public function __construct( ?string $key = null, string $prefix = '__ENCRYPTED__' ) {
		$this->key    = $key ? hash( 'sha256', $key, true ) : $this->get_wordpress_key();
		$this->prefix = $prefix;
		$this->validate_environment();
	}

	/**
	 * Encrypt a value
	 *
	 * @param string $value Value to encrypt
	 *
	 * @return string|WP_Error Encrypted value with prefix or WP_Error on failure
	 */
	public function encrypt( string $value ) {
		if ( empty( $value ) ) {
			return $value;
		}

		try {
			$iv = random_bytes( openssl_cipher_iv_length( $this->algorithm ) );
		} catch ( Exception $e ) {
			return new WP_Error( 'encryption_error', 'Failed to generate IV: ' . $e->getMessage() );
		}

		$encrypted = openssl_encrypt( $value, $this->algorithm, $this->key, OPENSSL_RAW_DATA, $iv );

		if ( $encrypted === false ) {
			return new WP_Error( 'encryption_error', 'Encryption failed: ' . openssl_error_string() );
		}

		return $this->prefix . base64_encode( $iv . $encrypted );
	}

	/**
	 * Decrypt a value
	 *
	 * @param string $value Value to decrypt (with or without prefix)
	 *
	 * @return string|WP_Error Decrypted value or WP_Error on failure
	 */
	public function decrypt( string $value ) {
		if ( empty( $value ) ) {
			return $value;
		}

		// Check if the value is actually encrypted
		if ( ! $this->is_encrypted( $value ) ) {
			return $value;
		}

		// Remove prefix
		$encrypted_data = substr( $value, strlen( $this->prefix ) );
		$data           = base64_decode( $encrypted_data );

		if ( $data === false ) {
			return new WP_Error( 'decryption_error', 'Invalid encrypted data' );
		}

		$iv_length = openssl_cipher_iv_length( $this->algorithm );
		$iv        = substr( $data, 0, $iv_length );
		$encrypted = substr( $data, $iv_length );

		$decrypted = openssl_decrypt( $encrypted, $this->algorithm, $this->key, OPENSSL_RAW_DATA, $iv );

		if ( $decrypted === false ) {
			return new WP_Error( 'decryption_error', 'Decryption failed: ' . openssl_error_string() );
		}

		return $decrypted;
	}

	/**
	 * Update a WordPress option with an encrypted value
	 *
	 * @param string $option Option name
	 * @param string $value  Value to encrypt and store
	 *
	 * @return bool Whether the option was updated successfully
	 */
	public function update_option( string $option, string $value ): bool {
		$encrypted = $this->encrypt( $value );

		// Handle encryption errors
		if ( is_wp_error( $encrypted ) ) {
			return false;
		}

		return update_option( $option, $encrypted );
	}

	/**
	 * Get and decrypt a WordPress option
	 *
	 * @param string $option  Option name
	 * @param string $default Default value if option doesn't exist
	 *
	 * @return string Decrypted option value or default if error
	 */
	public function get_option( string $option, string $default = '' ): string {
		$value = get_option( $option, $default );

		if ( ! is_string( $value ) ) {
			return $default;
		}

		$decrypted = $this->decrypt( $value );

		// Handle decryption errors
		if ( is_wp_error( $decrypted ) ) {
			return $default;
		}

		return $decrypted;
	}

	/**
	 * Set a WordPress transient with an encrypted value
	 *
	 * @param string $transient  Transient name
	 * @param string $value      Value to encrypt and store
	 * @param int    $expiration Optional. Time until expiration in seconds. Default 0 (no expiration).
	 *
	 * @return bool Whether the transient was set successfully
	 */
	public function set_transient( string $transient, string $value, int $expiration = 0 ): bool {
		$encrypted = $this->encrypt( $value );

		// Handle encryption errors
		if ( is_wp_error( $encrypted ) ) {
			return false;
		}

		return set_transient( $transient, $encrypted, $expiration );
	}

	/**
	 * Get and decrypt a WordPress transient
	 *
	 * @param string $transient Transient name
	 *
	 * @return string|false Decrypted transient value or false if not found
	 */
	public function get_transient( string $transient ) {
		$value = get_transient( $transient );

		if ( $value === false || ! is_string( $value ) ) {
			return false;
		}

		$decrypted = $this->decrypt( $value );

		// Handle decryption errors
		if ( is_wp_error( $decrypted ) ) {
			return false;
		}

		return $decrypted;
	}

	/**
	 * Update user meta with an encrypted value
	 *
	 * @param int    $user_id    User ID
	 * @param string $meta_key   Meta key
	 * @param string $meta_value Meta value to encrypt
	 *
	 * @return int|bool Meta ID on success, false on failure
	 */
	public function update_user_meta( int $user_id, string $meta_key, string $meta_value ) {
		$encrypted = $this->encrypt( $meta_value );

		// Handle encryption errors
		if ( is_wp_error( $encrypted ) ) {
			return false;
		}

		return update_user_meta( $user_id, $meta_key, $encrypted );
	}

	/**
	 * Get and decrypt user meta
	 *
	 * @param int    $user_id  User ID
	 * @param string $meta_key Meta key
	 * @param string $default  Default value if meta doesn't exist
	 *
	 * @return string Decrypted user meta value
	 */
	public function get_user_meta( int $user_id, string $meta_key, string $default = '' ): string {
		$value = get_user_meta( $user_id, $meta_key, true );

		if ( ! is_string( $value ) ) {
			return $default;
		}

		$decrypted = $this->decrypt( $value );

		// Handle decryption errors
		if ( is_wp_error( $decrypted ) ) {
			return $default;
		}

		return $decrypted;
	}

	/**
	 * Update post meta with encrypted value
	 *
	 * @param int    $post_id    Post ID
	 * @param string $meta_key   Meta key
	 * @param string $meta_value Meta value to encrypt
	 *
	 * @return int|bool Meta ID on success, false on failure
	 */
	public function update_post_meta( int $post_id, string $meta_key, string $meta_value ) {
		$encrypted = $this->encrypt( $meta_value );

		// Handle encryption errors
		if ( is_wp_error( $encrypted ) ) {
			return false;
		}

		return update_post_meta( $post_id, $meta_key, $encrypted );
	}

	/**
	 * Get and decrypt post meta
	 *
	 * @param int    $post_id  Post ID
	 * @param string $meta_key Meta key
	 * @param string $default  Default value if meta doesn't exist
	 *
	 * @return string Decrypted post meta value
	 */
	public function get_post_meta( int $post_id, string $meta_key, string $default = '' ): string {
		$value = get_post_meta( $post_id, $meta_key, true );

		if ( ! is_string( $value ) ) {
			return $default;
		}

		$decrypted = $this->decrypt( $value );

		// Handle decryption errors
		if ( is_wp_error( $decrypted ) ) {
			return $default;
		}

		return $decrypted;
	}

	/**
	 * Check if a value is encrypted
	 *
	 * @param string $value Value to check
	 *
	 * @return bool Whether the value is encrypted
	 */
	public function is_encrypted( string $value ): bool {
		return strpos( $value, $this->prefix ) === 0;
	}

	/**
	 * Change the encryption key
	 *
	 * @param string|null $key New encryption key. If null, regenerates from WordPress salts.
	 *
	 * @return void
	 */
	public function change_key( ?string $key = null ): void {
		$this->key = $key ? hash( 'sha256', $key, true ) : $this->get_wordpress_key();
	}

	/**
	 * Get the WordPress-based encryption key
	 *
	 * @return string WordPress-derived encryption key
	 * @throws RuntimeException If WordPress salts are not available
	 */
	private function get_wordpress_key(): string {
		$salts = [
			defined( 'AUTH_KEY' ) ? AUTH_KEY : '',
			defined( 'SECURE_AUTH_KEY' ) ? SECURE_AUTH_KEY : '',
			defined( 'LOGGED_IN_KEY' ) ? LOGGED_IN_KEY : '',
			defined( 'NONCE_KEY' ) ? NONCE_KEY : '',
		];

		$combined = implode( '', $salts );

		// Fallback to wp_salt if no constants defined
		if ( empty( $combined ) && function_exists( 'wp_salt' ) ) {
			$combined = wp_salt( 'auth' ) . wp_salt( 'secure_auth' );
		}

		// Final fallback
		if ( empty( $combined ) ) {
			throw new RuntimeException( 'Cannot generate encryption key: WordPress salts not available' );
		}

		return hash( 'sha256', $combined, true );
	}

	/**
	 * Validate that the environment supports encryption
	 *
	 * @return void
	 * @throws RuntimeException If OpenSSL is not available
	 */
	private function validate_environment(): void {
		if ( ! extension_loaded( 'openssl' ) ) {
			throw new RuntimeException( 'OpenSSL extension is required for encryption' );
		}

		if ( ! in_array( $this->algorithm, openssl_get_cipher_methods(), true ) ) {
			throw new RuntimeException( "Encryption algorithm '{$this->algorithm}' is not supported" );
		}
	}

}