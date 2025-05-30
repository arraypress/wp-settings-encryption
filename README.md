# WordPress Settings Encryption - Secure Storage for Sensitive Data

A lightweight utility for WordPress that provides secure encryption and decryption of sensitive data stored in options, transients, and meta tables. Perfect for protecting API keys, passwords, and tokens in your WordPress applications.

## Features

* 🔐 **Simple API**: Easy to use with both OOP and functional approaches
* 🛡️ **AES-256 Encryption**: Industry-standard encryption for maximum security
* 🔑 **WordPress Integration**: Seamlessly works with WordPress options, transients, and meta
* 🧩 **Automatic Salt Detection**: Uses WordPress salts for enhanced security
* 🔍 **Prefix Detection**: Automatically detects encrypted values
* 🔄 **Custom Keys**: Support for custom encryption keys

## Requirements

* PHP 7.4 or later
* WordPress 5.0 or later
* OpenSSL PHP extension

## Installation

Install via Composer:

```bash
composer require arraypress/wp-settings-encryption
```

## Basic Usage

You can use either the SettingsEncryption class directly or the utility functions:

```php
// Using the SettingsEncryption class
use ArrayPress\WP\SettingsEncryption;

// Create an instance
$encryption = new SettingsEncryption();

// Encrypt and store a value
$encryption->update_option( 'api_key', 'your-secret-api-key' );

// Retrieve and decrypt a value
$api_key = $encryption->get_option( 'api_key' );

// Or using utility functions
update_encrypted_option( 'api_key', 'your-secret-api-key' );
$api_key = get_encrypted_option( 'api_key' );
```

### Utility Functions

The package provides convenient utility functions for all operations:

```php
// Configure the encryption instance (optional)
get_encryption_instance( 'custom-key', '__CUSTOM_PREFIX__' );

// Encrypt/decrypt values directly
$encrypted = encrypt_value( 'sensitive-data' );
$decrypted = decrypt_value( $encrypted );

// Work with WordPress options
update_encrypted_option( 'api_key', 'secret-value' );
$value = get_encrypted_option( 'api_key', 'default-value' );

// Work with transients
set_encrypted_transient( 'auth_token', 'bearer-token-xyz', 3600 );
$token = get_encrypted_transient( 'auth_token' );

// Work with user meta
update_encrypted_user_meta( $user_id, 'access_key', 'user-specific-key' );
$key = get_encrypted_user_meta( $user_id, 'access_key' );

// Work with post meta
update_encrypted_post_meta( $post_id, 'payment_details', 'confidential-data' );
$details = get_encrypted_post_meta( $post_id, 'payment_details' );

// Check if a value is encrypted
if ( is_value_encrypted( $value ) ) {
    // Value is already encrypted
}
```

## Examples

### Basic Encryption

```php
// Encrypt a value directly
$encrypted = encrypt_value( 'my-secret-api-key' );
echo $encrypted; // Outputs: __ENCRYPTED__BASE64ENCRYPTEDSTRING

// Decrypt a value
$original = decrypt_value( $encrypted );
echo $original; // Outputs: my-secret-api-key

// Automatically detects if already encrypted
$same_value = decrypt_value( 'not-encrypted-value' );
echo $same_value; // Outputs: not-encrypted-value
```

### Working with WordPress Options

```php
// Store an encrypted API key
update_encrypted_option( 'my_plugin_api_key', 'secret-api-key-123' );

// Retrieve the API key (automatically decrypted)
$api_key = get_encrypted_option( 'my_plugin_api_key' );

// Use a default value if option doesn't exist
$api_key = get_encrypted_option( 'my_plugin_api_key', 'default-key' );
```

### Working with Transients

```php
// Store an encrypted token that expires in 1 hour
set_encrypted_transient( 'auth_token', 'bearer-token-xyz', HOUR_IN_SECONDS );

// Retrieve the token (automatically decrypted)
$token = get_encrypted_transient( 'auth_token' );

// Handle expired transients
if ( false === $token ) {
    // Token has expired or doesn't exist, get a new one
    $token = get_new_token_from_api();
    set_encrypted_transient( 'auth_token', $token, HOUR_IN_SECONDS );
}
```

### Working with User Meta

```php
// Store encrypted user-specific API keys
update_encrypted_user_meta( $user_id, 'api_access_key', 'user-specific-key-abc' );

// Retrieve the key (automatically decrypted)
$user_key = get_encrypted_user_meta( $user_id, 'api_access_key' );
```

### Working with Post Meta

```php
// Store encrypted payment details for an order
update_encrypted_post_meta( $order_id, 'payment_details', json_encode($card_details) );

// Retrieve the payment details (automatically decrypted)
$payment_json = get_encrypted_post_meta( $order_id, 'payment_details' );
$payment_details = json_decode( $payment_json, true );
```

### Using Custom Encryption Keys

```php
// Create an instance with a custom key
$encryption = new SettingsEncryption( 'my-custom-encryption-key' );

// Use the custom instance
$encrypted = $encryption->encrypt( 'sensitive-data' );
$decrypted = $encryption->decrypt( $encrypted );

// Or configure the global instance for utility functions
get_encryption_instance( 'my-custom-encryption-key' );

// Now all utility functions will use your custom key
$encrypted = encrypt_value( 'sensitive-data' );
```

### Using Custom Prefix

```php
// Create an instance with a custom prefix
$encryption = new SettingsEncryption( null, '__CUSTOM_PREFIX__' );

// Values will be prefixed with your custom string
$encrypted = $encryption->encrypt( 'sensitive-data' );
// Outputs: __CUSTOM_PREFIX__BASE64ENCRYPTEDSTRING

// Configure the global instance for utility functions
get_encryption_instance( null, '__CUSTOM_PREFIX__' );
```

## Security Considerations

This library:

* Uses industry-standard AES-256-CBC encryption
* Automatically generates secure random IVs for each encryption
* Uses WordPress salts and auth keys for added security
* Validates that the OpenSSL extension is available
* Returns WordPress-style error responses for graceful failure handling

## Error Handling

The library uses standard WordPress error handling:

```php
// Example of error handling
$encrypted = encrypt_value( 'sensitive-data' );
if ( is_wp_error( $encrypted ) ) {
    $error_message = $encrypted->get_error_message();
    // Handle the error appropriately
    error_log( 'Encryption error: ' . $error_message );
    return false;
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

Licensed under the GPLv2 or later license.

## Support

- [Issue Tracker](https://github.com/arraypress/wp-settings-encryption/issues)