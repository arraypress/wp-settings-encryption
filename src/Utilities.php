<?php
/**
 * Settings Encryption Utility Functions
 *
 * @package     ArrayPress\WP\SettingsEncryption
 * @copyright   Copyright (c) 2025, ArrayPress Limited
 * @license     GPL2+
 * @version     1.3.0
 * @author      David Sherlock
 */

declare( strict_types=1 );

namespace ArrayPress\WP;

use WP_Error;

defined( 'ABSPATH' ) || exit;

/**
 * Get or create the global encryption instance
 *
 * @param string|null $key            Optional. Custom encryption key. Only used on first call.
 * @param string      $prefix         Optional. Prefix for encrypted values. Only used on first call.
 * @param string      $prefix_name    Optional. Prefix for option and constant names. Only used on first call.
 * @param bool        $auto_intercept Optional. Whether to automatically intercept get_option calls. Only used on first
 *                                    call.
 *
 * @return SettingsEncryption
 */
function get_encryption_instance( ?string $key = null, string $prefix = '__ENCRYPTED__', string $prefix_name = '', bool $auto_intercept = false ): SettingsEncryption {
	global $arraypress_encryption;

	if ( ! $arraypress_encryption instanceof SettingsEncryption ) {
		$arraypress_encryption = new SettingsEncryption( $key, $prefix, $prefix_name, $auto_intercept );
	}

	return $arraypress_encryption;
}

/**
 * Encrypt a value
 *
 * @param string $value Value to encrypt
 *
 * @return string|WP_Error Encrypted value or WP_Error on failure
 */
function encrypt_value( string $value ) {
	return get_encryption_instance()->encrypt( $value );
}

/**
 * Decrypt a value
 *
 * @param string $value Value to decrypt
 *
 * @return string|WP_Error Decrypted value or WP_Error on failure
 */
function decrypt_value( string $value ) {
	return get_encryption_instance()->decrypt( $value );
}

/**
 * Update a WordPress option with an encrypted value
 * Automatically checks for constants and skips database storage if constant is defined.
 *
 * @param string $option Option name (without prefix)
 * @param string $value  Value to encrypt and store
 *
 * @return bool Whether the option was updated successfully
 */
function update_encrypted_option( string $option, string $value ): bool {
	return get_encryption_instance()->update_option( $option, $value );
}

/**
 * Get and decrypt a WordPress option
 * Automatically checks for constants first, then falls back to encrypted database storage.
 *
 * @param string $option  Option name (without prefix)
 * @param string $default Default value if option doesn't exist
 *
 * @return string Decrypted option value
 */
function get_encrypted_option( string $option, string $default = '' ): string {
	return get_encryption_instance()->get_option( $option, $default );
}

/**
 * Get option information including source and encryption status
 *
 * @param string $option  Option name (without prefix)
 * @param string $default Default value
 *
 * @return array Array with 'value', 'source', and additional info
 */
function get_encrypted_option_info( string $option, string $default = '' ): array {
	return get_encryption_instance()->get_option_info( $option, $default );
}

/**
 * Check if an option is defined as a constant
 *
 * @param string $option Option name (without prefix)
 *
 * @return bool Whether the option has a constant defined
 */
function is_option_constant_defined( string $option ): bool {
	return get_encryption_instance()->is_constant_defined( $option );
}

/**
 * Generate setting description for admin interfaces
 *
 * @param string $option    Option name (without prefix)
 * @param string $base_desc Base description text
 *
 * @return string Enhanced description with constant information
 */
function get_encrypted_setting_description( string $option, string $base_desc ): string {
	return get_encryption_instance()->get_setting_description( $option, $base_desc );
}

/**
 * Track an option for auto-interception
 *
 * @param string $option Option name (without prefix)
 *
 * @return void
 */
function track_encrypted_option( string $option ): void {
	get_encryption_instance()->track_option( $option );
}

/**
 * Enable auto-interception for tracked options
 *
 * @return void
 */
function enable_option_auto_interception(): void {
	get_encryption_instance()->enable_auto_interception();
}

/**
 * Disable auto-interception for tracked options
 *
 * @return void
 */
function disable_option_auto_interception(): void {
	get_encryption_instance()->disable_auto_interception();
}

/**
 * Set a WordPress transient with an encrypted value
 *
 * @param string $transient  Transient name
 * @param string $value      Value to encrypt and store
 * @param int    $expiration Optional. Time until expiration in seconds. Default 0.
 *
 * @return bool Whether the transient was set successfully
 */
function set_encrypted_transient( string $transient, string $value, int $expiration = 0 ): bool {
	return get_encryption_instance()->set_transient( $transient, $value, $expiration );
}

/**
 * Get and decrypt a WordPress transient
 *
 * @param string $transient Transient name
 *
 * @return string|false Decrypted transient value or false if not found
 */
function get_encrypted_transient( string $transient ) {
	return get_encryption_instance()->get_transient( $transient );
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
function update_encrypted_user_meta( int $user_id, string $meta_key, string $meta_value ) {
	return get_encryption_instance()->update_user_meta( $user_id, $meta_key, $meta_value );
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
function get_encrypted_user_meta( int $user_id, string $meta_key, string $default = '' ): string {
	return get_encryption_instance()->get_user_meta( $user_id, $meta_key, $default );
}

/**
 * Update post meta with an encrypted value
 *
 * @param int    $post_id    Post ID
 * @param string $meta_key   Meta key
 * @param string $meta_value Meta value to encrypt
 *
 * @return int|bool Meta ID on success, false on failure
 */
function update_encrypted_post_meta( int $post_id, string $meta_key, string $meta_value ) {
	return get_encryption_instance()->update_post_meta( $post_id, $meta_key, $meta_value );
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
function get_encrypted_post_meta( int $post_id, string $meta_key, string $default = '' ): string {
	return get_encryption_instance()->get_post_meta( $post_id, $meta_key, $default );
}

/**
 * Check if a value is encrypted
 *
 * @param string $value Value to check
 *
 * @return bool Whether the value is encrypted
 */
function is_value_encrypted( string $value ): bool {
	return get_encryption_instance()->is_encrypted( $value );
}

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

/**
 * Check if a dedicated encryption key is defined
 *
 * @return bool Whether WP_ENCRYPTION_KEY constant is defined
 */
function has_dedicated_encryption_key(): bool {
	return defined( 'WP_ENCRYPTION_KEY' ) && ! empty( constant( 'WP_ENCRYPTION_KEY' ) );
}

/**
 * Create a new encryption instance with specific configuration
 * Useful when you need multiple instances with different settings.
 *
 * @param string|null $key            Optional. Custom encryption key.
 * @param string      $prefix         Optional. Prefix for encrypted values.
 * @param string      $prefix_name    Optional. Prefix for option and constant names.
 * @param bool        $auto_intercept Optional. Whether to automatically intercept get_option calls.
 *
 * @return SettingsEncryption
 */
function create_encryption_instance( ?string $key = null, string $prefix = '__ENCRYPTED__', string $prefix_name = '', bool $auto_intercept = false ): SettingsEncryption {
	return new SettingsEncryption( $key, $prefix, $prefix_name, $auto_intercept );
}