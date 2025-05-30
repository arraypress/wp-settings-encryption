<?php
/**
 * Settings Encryption Utility Functions
 *
 * @package     ArrayPress\WP\SettingsEncryption
 * @copyright   Copyright (c) 2025, ArrayPress Limited
 * @license     GPL2+
 * @version     1.0.0
 * @author      David Sherlock
 */

declare( strict_types=1 );

namespace ArrayPress\WP;

defined( 'ABSPATH' ) || exit;

/**
 * Get or create the global encryption instance
 *
 * @param string|null $key    Optional. Custom encryption key. Only used on first call.
 * @param string      $prefix Optional. Prefix for encrypted values. Only used on first call.
 *
 * @return SettingsEncryption
 */
function get_encryption_instance( ?string $key = null, string $prefix = '__ENCRYPTED__' ): SettingsEncryption {
	global $arraypress_encryption;

	if ( ! $arraypress_encryption instanceof SettingsEncryption ) {
		$arraypress_encryption = new SettingsEncryption( $key, $prefix );
	}

	return $arraypress_encryption;
}

/**
 * Encrypt a value
 *
 * @param string $value Value to encrypt
 *
 * @return string Encrypted value
 */
function encrypt_value( string $value ): string {
	return get_encryption_instance()->encrypt( $value );
}

/**
 * Decrypt a value
 *
 * @param string $value Value to decrypt
 *
 * @return string Decrypted value
 */
function decrypt_value( string $value ): string {
	return get_encryption_instance()->decrypt( $value );
}

/**
 * Update a WordPress option with an encrypted value
 *
 * @param string $option Option name
 * @param string $value  Value to encrypt and store
 *
 * @return bool Whether the option was updated successfully
 */
function update_encrypted_option( string $option, string $value ): bool {
	return get_encryption_instance()->update_option( $option, $value );
}

/**
 * Get and decrypt a WordPress option
 *
 * @param string $option  Option name
 * @param string $default Default value if option doesn't exist
 *
 * @return string Decrypted option value
 */
function get_encrypted_option( string $option, string $default = '' ): string {
	return get_encryption_instance()->get_option( $option, $default );
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
 * @param int    $user_id User ID
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
 * @param int    $post_id Post ID
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