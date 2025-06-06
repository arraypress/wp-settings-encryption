<?php
/**
 * Plugin Name: Encryption Test Plugin
 * Description: Simple plugin to test the SettingsEncryption class functionality
 * Version: 1.0.0
 * Author: Test
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Include the encryption classes
require_once plugin_dir_path( __FILE__ ) . 'src/SettingsEncryption.php';
require_once plugin_dir_path( __FILE__ ) . 'src/Utilities.php';

use ArrayPress\WP\SettingsEncryption;

class EncryptionTestPlugin {

	private $encryption;

	public function __construct() {
		add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
		add_action( 'admin_init', array( $this, 'handle_form_submission' ) );

		// Initialize encryption
		try {
			$this->encryption = new SettingsEncryption();
		} catch ( Exception $e ) {
			add_action( 'admin_notices', function () use ( $e ) {
				echo '<div class="notice notice-error"><p>Encryption Error: ' . esc_html( $e->getMessage() ) . '</p></div>';
			} );
		}
	}

	public function add_admin_menu() {
		add_management_page(
			'Encryption Test',
			'Encryption Test',
			'manage_options',
			'encryption-test',
			array( $this, 'admin_page' )
		);
	}

	public function handle_form_submission() {
		if ( ! isset( $_POST['encryption_test_nonce'] ) ||
		     ! wp_verify_nonce( $_POST['encryption_test_nonce'], 'encryption_test_action' ) ) {
			return;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		if ( isset( $_POST['save_encrypted_data'] ) ) {
			$api_key      = sanitize_text_field( $_POST['api_key'] );
			$secret_token = sanitize_text_field( $_POST['secret_token'] );

			// Save encrypted data
			$this->encryption->update_option( 'test_api_key', $api_key );
			$this->encryption->update_option( 'test_secret_token', $secret_token );

			// Also test transient
			$this->encryption->set_transient( 'test_temp_data', $api_key, 3600 );

			add_action( 'admin_notices', function () {
				echo '<div class="notice notice-success"><p>Encrypted data saved successfully!</p></div>';
			} );
		}

		if ( isset( $_POST['clear_data'] ) ) {
			delete_option( 'test_api_key' );
			delete_option( 'test_secret_token' );
			delete_transient( 'test_temp_data' );

			add_action( 'admin_notices', function () {
				echo '<div class="notice notice-success"><p>All test data cleared!</p></div>';
			} );
		}
	}

	public function admin_page() {
		// Get current encrypted values
		$api_key      = $this->encryption->get_option( 'test_api_key', '' );
		$secret_token = $this->encryption->get_option( 'test_secret_token', '' );
		$temp_data    = $this->encryption->get_transient( 'test_temp_data' );

		// Get raw encrypted values from database for debugging
		$raw_api_key      = get_option( 'test_api_key', '' );
		$raw_secret_token = get_option( 'test_secret_token', '' );
		$raw_temp_data    = get_transient( 'test_temp_data' );

		?>
        <div class="wrap">
            <h1>Encryption Test Plugin</h1>

            <div class="card">
                <h2>Test Encrypted Storage</h2>
                <form method="post" action="">
					<?php wp_nonce_field( 'encryption_test_action', 'encryption_test_nonce' ); ?>

                    <table class="form-table">
                        <tr>
                            <th scope="row">
                                <label for="api_key">API Key</label>
                            </th>
                            <td>
                                <input type="text"
                                       id="api_key"
                                       name="api_key"
                                       value="<?php echo esc_attr( $api_key ); ?>"
                                       class="regular-text"
                                       placeholder="Enter API key to encrypt"/>
                                <p class="description">This will be encrypted when saved.</p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="secret_token">Secret Token</label>
                            </th>
                            <td>
                                <input type="text"
                                       id="secret_token"
                                       name="secret_token"
                                       value="<?php echo esc_attr( $secret_token ); ?>"
                                       class="regular-text"
                                       placeholder="Enter secret token to encrypt"/>
                                <p class="description">This will also be encrypted when saved.</p>
                            </td>
                        </tr>
                    </table>

                    <p class="submit">
                        <input type="submit"
                               name="save_encrypted_data"
                               class="button-primary"
                               value="Save Encrypted Data"/>
                        <input type="submit"
                               name="clear_data"
                               class="button-secondary"
                               value="Clear All Data"/>
                    </p>
                </form>
            </div>

			<?php if ( ! empty( $raw_api_key ) || ! empty( $raw_secret_token ) ): ?>
                <div class="card">
                    <h2>Encryption Status & Debug Info</h2>

                    <h3>Decrypted Values (what you see in the form above)</h3>
                    <table class="widefat striped">
                        <tr>
                            <td><strong>API Key:</strong></td>
                            <td><?php echo esc_html( $api_key ?: '(empty)' ); ?></td>
                        </tr>
                        <tr>
                            <td><strong>Secret Token:</strong></td>
                            <td><?php echo esc_html( $secret_token ?: '(empty)' ); ?></td>
                        </tr>
                        <tr>
                            <td><strong>Transient Data:</strong></td>
                            <td><?php echo esc_html( $temp_data ?: '(empty or expired)' ); ?></td>
                        </tr>
                    </table>

                    <h3>Raw Encrypted Values (stored in database)</h3>
                    <table class="widefat striped">
                        <tr>
                            <td><strong>Raw API Key:</strong></td>
                            <td>
                                <code><?php echo esc_html( $raw_api_key ?: '(empty)' ); ?></code>
								<?php if ( $this->encryption->is_encrypted( $raw_api_key ) ): ?>
                                    <span style="color: green;">✓ Encrypted</span>
								<?php else: ?>
                                    <span style="color: red;">✗ Not Encrypted</span>
								<?php endif; ?>
                            </td>
                        </tr>
                        <tr>
                            <td><strong>Raw Secret Token:</strong></td>
                            <td>
                                <code><?php echo esc_html( $raw_secret_token ?: '(empty)' ); ?></code>
								<?php if ( $this->encryption->is_encrypted( $raw_secret_token ) ): ?>
                                    <span style="color: green;">✓ Encrypted</span>
								<?php else: ?>
                                    <span style="color: red;">✗ Not Encrypted</span>
								<?php endif; ?>
                            </td>
                        </tr>
                        <tr>
                            <td><strong>Raw Transient:</strong></td>
                            <td>
                                <code><?php echo esc_html( $raw_temp_data ?: '(empty or expired)' ); ?></code>
								<?php if ( $raw_temp_data && $this->encryption->is_encrypted( $raw_temp_data ) ): ?>
                                    <span style="color: green;">✓ Encrypted</span>
								<?php else: ?>
                                    <span style="color: red;">✗ Not Encrypted</span>
								<?php endif; ?>
                            </td>
                        </tr>
                    </table>

                    <h3>Encryption Test</h3>
					<?php
					$test_value     = "Hello World Test!";
					$encrypted_test = $this->encryption->encrypt( $test_value );
					$decrypted_test = '';

					if ( ! is_wp_error( $encrypted_test ) ) {
						$decrypted_test = $this->encryption->decrypt( $encrypted_test );
					}
					?>
                    <table class="widefat striped">
                        <tr>
                            <td><strong>Original:</strong></td>
                            <td><?php echo esc_html( $test_value ); ?></td>
                        </tr>
                        <tr>
                            <td><strong>Encrypted:</strong></td>
                            <td>
								<?php if ( is_wp_error( $encrypted_test ) ): ?>
                                    <span style="color: red;">ERROR: <?php echo esc_html( $encrypted_test->get_error_message() ); ?></span>
								<?php else: ?>
                                    <code><?php echo esc_html( $encrypted_test ); ?></code>
								<?php endif; ?>
                            </td>
                        </tr>
                        <tr>
                            <td><strong>Decrypted:</strong></td>
                            <td>
								<?php if ( is_wp_error( $decrypted_test ) ): ?>
                                    <span style="color: red;">ERROR: <?php echo esc_html( $decrypted_test->get_error_message() ); ?></span>
								<?php else: ?>
									<?php echo esc_html( $decrypted_test ); ?>
									<?php if ( $decrypted_test === $test_value ): ?>
                                        <span style="color: green;">✓ Match!</span>
									<?php else: ?>
                                        <span style="color: red;">✗ No Match</span>
									<?php endif; ?>
								<?php endif; ?>
                            </td>
                        </tr>
                    </table>
                </div>
			<?php endif; ?>

            <div class="card">
                <h2>Instructions</h2>
                <ol>
                    <li>Enter some test data in the fields above and click "Save Encrypted Data"</li>
                    <li>Check the "Raw Encrypted Values" section to see the actual encrypted data stored in the
                        database
                    </li>
                    <li>The form fields should show the decrypted, readable values</li>
                    <li>The encryption test at the bottom should show that encryption/decryption is working</li>
                    <li>Use "Clear All Data" to remove test data when done</li>
                </ol>
            </div>
        </div>

        <style>
            .card {
                background: #fff;
                border: 1px solid #ccd0d4;
                border-radius: 4px;
                padding: 20px;
                margin: 20px 0;
            }

            .card h2 {
                margin-top: 0;
            }

            code {
                background: #f1f1f1;
                padding: 2px 4px;
                border-radius: 3px;
                font-family: monospace;
                word-break: break-all;
            }
        </style>
		<?php
	}
}

// Initialize the plugin
new EncryptionTestPlugin();