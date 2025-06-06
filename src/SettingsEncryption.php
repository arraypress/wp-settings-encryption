<?php
/**
 * WordPress Settings Encryption with Automatic Option Interception
 *
 * @package     ArrayPress\WP\SettingsEncryption
 * @copyright   Copyright (c) 2025, ArrayPress Limited
 * @license     GPL2+
 * @version     1.3.0
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
 * Automatically checks for WordPress constants before falling back to encrypted database storage.
 * Features auto-interception of get_option() calls to return decrypted values seamlessly.
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
	 * Prefix for option and constant names
	 *
	 * @var string
	 */
	private string $prefix_name;

	/**
	 * Whether to auto-intercept get_option calls
	 *
	 * @var bool
	 */
	private bool $auto_intercept;

	/**
	 * Tracked option names for auto-interception
	 *
	 * @var array
	 */
	private array $tracked_options = [];

	/**
	 * Constructor
	 *
	 * @param string|null $key            Optional. Custom encryption key. If null, use WordPress salts.
	 * @param string      $prefix         Optional. Prefix for encrypted values. Default '__ENCRYPTED__'.
	 * @param string      $prefix_name    Optional. Prefix for option and constant names (e.g., 'wc_r2_'). Default
	 *                                    empty.
	 * @param bool        $auto_intercept Optional. Whether to automatically intercept get_option calls. Default false.
	 *
	 * @throws RuntimeException If OpenSSL extension is not available or the algorithm is not supported.
	 */
	public function __construct( ?string $key = null, string $prefix = '__ENCRYPTED__', string $prefix_name = '', bool $auto_intercept = false ) {
		$this->key            = $key ? hash( 'sha256', $key, true ) : $this->get_wordpress_key();
		$this->prefix         = $prefix;
		$this->prefix_name    = $prefix_name;
		$this->auto_intercept = $auto_intercept;
		$this->validate_environment();

		if ( $this->auto_intercept ) {
			$this->setup_auto_interception();
		}
	}

	/**
	 * Convert option name to full option name with prefix
	 *
	 * @param string $option_name Option name (e.g., 'account_id')
	 *
	 * @return string Full option name (e.g., 'wc_r2_account_id')
	 */
	private function get_full_option_name( string $option_name ): string {
		if ( ! empty( $this->prefix_name ) ) {
			return $this->prefix_name . $option_name;
		}

		return $option_name;
	}

	/**
	 * Convert option name to constant name
	 *
	 * @param string $option_name Option name (e.g., 'account_id')
	 *
	 * @return string Constant name (e.g., 'WC_R2_ACCOUNT_ID')
	 */
	private function option_to_constant( string $option_name ): string {
		$full_option_name = $this->get_full_option_name( $option_name );

		return strtoupper( $full_option_name );
	}

	/**
	 * Check if a constant exists for an option
	 *
	 * @param string $option_name Option name
	 *
	 * @return bool Whether the constant is defined and not empty
	 */
	private function has_constant_for_option( string $option_name ): bool {
		$constant_name = $this->option_to_constant( $option_name );

		return defined( $constant_name ) && ! empty( constant( $constant_name ) );
	}

	/**
	 * Get constant value for an option
	 *
	 * @param string $option_name Option name
	 *
	 * @return string|null Constant value or null if not defined
	 */
	private function get_constant_for_option( string $option_name ): ?string {
		$constant_name = $this->option_to_constant( $option_name );

		if ( defined( $constant_name ) && ! empty( constant( $constant_name ) ) ) {
			return constant( $constant_name );
		}

		return null;
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
	 * Will not update if a constant is defined for this option.
	 *
	 * @param string $option Option name (without prefix)
	 * @param string $value  Value to encrypt and store
	 *
	 * @return bool Whether the option was updated successfully
	 */
	public function update_option( string $option, string $value ): bool {
		// Don't save to database if constant is defined
		if ( $this->has_constant_for_option( $option ) ) {
			return false;
		}

		$encrypted = $this->encrypt( $value );

		// Handle encryption errors
		if ( is_wp_error( $encrypted ) ) {
			return false;
		}

		$full_option_name = $this->get_full_option_name( $option );

		// Track this option for auto-interception if enabled
		if ( $this->auto_intercept ) {
			$this->track_option( $option );
		}

		return update_option( $full_option_name, $encrypted );
	}

	/**
	 * Get and decrypt a WordPress option
	 * Automatically checks for constants first.
	 *
	 * @param string $option  Option name (without prefix)
	 * @param string $default Default value if option doesn't exist
	 *
	 * @return string Decrypted option value or default if error
	 */
	public function get_option( string $option, string $default = '' ): string {
		// Check constant first
		$constant_value = $this->get_constant_for_option( $option );
		if ( $constant_value !== null ) {
			return $constant_value;
		}

		// Fall back to database option
		$full_option_name = $this->get_full_option_name( $option );
		$value            = get_option( $full_option_name, $default );

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
	 * Get option info including source
	 *
	 * @param string $option  Option name (without prefix)
	 * @param string $default Default value
	 *
	 * @return array Array with 'value', 'source', and additional info
	 */
	public function get_option_info( string $option, string $default = '' ): array {
		// Check constant first
		$constant_value = $this->get_constant_for_option( $option );
		if ( $constant_value !== null ) {
			return [
				'value'        => $constant_value,
				'source'       => 'constant',
				'constant'     => $this->option_to_constant( $option ),
				'is_encrypted' => false,
			];
		}

		// Check database option
		$full_option_name = $this->get_full_option_name( $option );
		$option_value     = get_option( $full_option_name, null );
		if ( $option_value !== null ) {
			$decrypted = $this->decrypt( $option_value );
			if ( ! is_wp_error( $decrypted ) ) {
				return [
					'value'        => $decrypted,
					'source'       => 'database',
					'option'       => $full_option_name,
					'is_encrypted' => $this->is_encrypted( $option_value ),
				];
			}
		}

		// Return default
		return [
			'value'        => $default,
			'source'       => 'default',
			'is_encrypted' => false,
		];
	}

	/**
	 * Check if an option is defined as a constant
	 *
	 * @param string $option Option name (without prefix)
	 *
	 * @return bool Whether the option has a constant defined
	 */
	public function is_constant_defined( string $option ): bool {
		return $this->has_constant_for_option( $option );
	}

	/**
	 * Get the constant name for an option
	 *
	 * @param string $option Option name (without prefix)
	 *
	 * @return string Constant name that would be checked
	 */
	public function get_constant_name( string $option ): string {
		return $this->option_to_constant( $option );
	}

	/**
	 * Generate setting description for admin interfaces
	 *
	 * @param string $option    Option name (without prefix)
	 * @param string $base_desc Base description text
	 *
	 * @return string Enhanced description with constant information
	 */
	public function get_setting_description( string $option, string $base_desc ): string {
		if ( $this->is_constant_defined( $option ) ) {
			$constant_name = $this->get_constant_name( $option );

			return $base_desc . sprintf(
					' <strong>%s</strong> <code>%s</code>',
					__( 'Defined as constant:', 'your-textdomain' ),
					$constant_name
				);
		}

		return $base_desc . ' ' . __( '(stored encrypted in database)', 'your-textdomain' );
	}

	/**
	 * Setup automatic interception of get_option calls
	 *
	 * @return void
	 */
	private function setup_auto_interception(): void {
		// This will be called when options are tracked
	}

	/**
	 * Track an option for auto-interception
	 *
	 * @param string $option Option name (without prefix)
	 *
	 * @return void
	 */
	public function track_option( string $option ): void {
		if ( ! in_array( $option, $this->tracked_options, true ) ) {
			$this->tracked_options[] = $option;
			$full_option_name        = $this->get_full_option_name( $option );
			add_filter( "pre_option_{$full_option_name}", [ $this, 'intercept_option_value' ], 10, 1 );
		}
	}

	/**
	 * Intercept option values to return decrypted data
	 *
	 * @param mixed $value The option value
	 *
	 * @return mixed
	 */
	public function intercept_option_value( $value ) {
		// Get the option name from the current filter
		$full_option_name = str_replace( 'pre_option_', '', current_filter() );

		// Extract the base name (remove prefix)
		$base_name = '';
		if ( ! empty( $this->prefix_name ) ) {
			$base_name = str_replace( $this->prefix_name, '', $full_option_name );
		} else {
			$base_name = $full_option_name;
		}

		// Temporarily remove our filter to prevent infinite loop
		remove_filter( current_filter(), [ $this, 'intercept_option_value' ], 10 );

		// Get the decrypted value using our method
		$decrypted_value = $this->get_option( $base_name, '' );

		// Re-add our filter
		add_filter( current_filter(), [ $this, 'intercept_option_value' ], 10, 1 );

		return $decrypted_value;
	}

	/**
	 * Enable auto-interception for existing tracked options
	 *
	 * @return void
	 */
	public function enable_auto_interception(): void {
		$this->auto_intercept = true;

		// Set up filters for already tracked options
		foreach ( $this->tracked_options as $option ) {
			$full_option_name = $this->get_full_option_name( $option );
			add_filter( "pre_option_{$full_option_name}", [ $this, 'intercept_option_value' ], 10, 1 );
		}
	}

	/**
	 * Disable auto-interception
	 *
	 * @return void
	 */
	public function disable_auto_interception(): void {
		$this->auto_intercept = false;

		// Remove filters for tracked options
		foreach ( $this->tracked_options as $option ) {
			$full_option_name = $this->get_full_option_name( $option );
			remove_filter( "pre_option_{$full_option_name}", [ $this, 'intercept_option_value' ], 10 );
		}
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
	 * @throws RuntimeException If no key source is available
	 */
	private function get_wordpress_key(): string {
		// Priority 1: Dedicated encryption key constant (recommended for production)
		if ( defined( 'WP_ENCRYPTION_KEY' ) && ! empty( constant( 'WP_ENCRYPTION_KEY' ) ) ) {
			return hash( 'sha256', constant( 'WP_ENCRYPTION_KEY' ), true );
		}

		// Priority 2: Use WordPress salts (will break if salts change)
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

		// Final check
		if ( empty( $combined ) ) {
			throw new RuntimeException( 'Cannot generate encryption key: WordPress salts not available. Consider defining WP_ENCRYPTION_KEY.' );
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