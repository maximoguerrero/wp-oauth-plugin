<?php
/*
Plugin Name: WP OAuth2.0 SSO Client
Description: A plugin to enable OAuth2 Single Sign-On for WordPress using the PHP League's OAuth2 Client. Any generic OAuth2 provider can be used.
Version: 1.0
Author: Maximo Guerrero
*/

// Exit if accessed directly.
if (!defined('ABSPATH')) {
    exit;
}


// Define constants.
define('OAUTH2_SSO_PLUGIN_URL', plugin_dir_url(__FILE__));
define('OAUTH2_SSO_PLUGIN_DIR', plugin_dir_path(__FILE__));

// Include required files.
require_once OAUTH2_SSO_PLUGIN_DIR . 'vendor/autoload.php';
require_once OAUTH2_SSO_PLUGIN_DIR . 'includes/functions.php';
require_once OAUTH2_SSO_PLUGIN_DIR . 'includes/settings.php';

// Add hooks.
add_action('wp_loaded', 'require_authentication');
add_action('init', 'oauth2_sso_init');
add_action('admin_menu', 'oauth2_sso_admin_menu');



include_once(ABSPATH . 'wp-admin/includes/plugin.php');

// Initialize plugin.
function oauth2_sso_init()
{


    if (is_plugin_active(plugin_basename(OAUTH2_SSO_PLUGIN_DIR . 'oauth2-sso.php'))) {

        // Check if the user is attempting to log in via OAuth2.
        if (isset($_GET['oauth2_sso']) || isset($_GET['code']) || isset($_GET['error'])) {
            
            // set no cache headers
            header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
            header("Cache-Control: post-check=0, pre-check=0", false);
            header("Pragma: no-cache");

            // Handle the login process.
            oauth2_sso_handle_login();
        }else if (isset($_GET['finalurl']) && $_GET['finalurl'] == 'oauth2redirect') {
            
            // set no cache headers
            header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
            header("Cache-Control: post-check=0, pre-check=0", false);
            header("Pragma: no-cache");
            
            // Redirect to the login page.
            $redirect_to = isset($_COOKIE['oauth2redirect']) ? $_COOKIE['oauth2redirect'] : home_url();
            setcookie('oauth2redirect', '', time() - 3600, '/');
            $current_user = wp_get_current_user();
            if ($current_user->exists()) {
                $name = $current_user->display_name;
            } else {
                $name = 'Guest';
            }
            //wp_redirect($redirect_to);
            ?>
                <html>
                    <head>
                       
                    </head>
                    <body>
                        <p style="text-align: center;">
                            You have been logged in (<?php echo $name?>).   Redirecting to <a href="<?php echo $redirect_to; ?>"><?php echo $redirect_to; ?></a>
                        </p>
                        <script>
                            setTimeout(function() {
                                window.location.href = "<?php echo $redirect_to; ?>";
                            }, 1000);
                        </script>
                    </body>
                </html>
            <?php

            exit;
        }

    }

}

function require_authentication() {
    if ( ! is_user_logged_in() ) {
        // redirecto to touchstone directly.
        $redirect_uri = get_option( 'oauth2_sso_redirect_uri' );
        if ( $redirect_uri && ! empty( $redirect_uri ) ) {
            header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
            header("Cache-Control: post-check=0, pre-check=0", false);
            header("Pragma: no-cache");
            wp_redirect( $redirect_uri . '?oauth2_sso=true&redirect_uri=' . esc_url( get_current_url() ) );
            exit;
        }
        wp_redirect( wp_login_url( get_current_url() ) );
        exit;
    }
}
function get_current_url() {
    return ( isset( $_SERVER['HTTPS'] ) && 'on' === $_SERVER['HTTPS'] ? 'https' : 'http' )
    . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
}  

// Add a button to the login form.
function oauth2_sso_add_login_button() {
    
    // Start a session if one doesn't exist.
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }
    // Save the 'redirect_to' query string to a variable if it exists.
    $redirect_to = isset($_GET['redirect_to']) ? "&redirect_uri=". esc_url($_GET['redirect_to']) : '';

    
    $login_text = get_option('oauth2_sso_oauth_login_text');
    if (empty($login_text)) {
        $login_text = 'Login with OAuth2';
    }

    // Add a button to the login form.
    $button_html = '<div id="oauth2SSO" style="margin:20px; clear:both; text-align:center;"><a href="?oauth2_sso='.uniqid().$redirect_to.'" class="button button button-large">'. $login_text .'</a></div>';
    echo $button_html;
}

// Add the login button to the login form.
add_action('login_form', 'oauth2_sso_add_login_button');


// Add custom JavaScript to the login page.
function oauth2_sso_login_js() {
    // Add the JavaScript to move the button to the form.
    echo '
    <script type="text/javascript">
        window.onload = function() {
            var button = document.getElementById("oauth2SSO");
            var form = document.getElementById("loginform");
            form.appendChild(button);
        }
    </script>';
}
// Add the custom JavaScript to the login page.
add_action('login_enqueue_scripts', 'oauth2_sso_login_js');

// Add plugin settings page to the admin menu.
function oauth2_sso_admin_menu()
{
    add_options_page(
        'OAuth2 SSO Settings',
        'OAuth2 SSO',
        'manage_options',
        'oauth2-sso',
        'oauth2_sso_settings_page'
    );
}

// Clear cookie on logout.
function oauth2_sso_clear_cookie() {
    setcookie('oauth2state', '', time() - 3600, '/');
}
// Clear the cookie on logout.
add_action('wp_logout', 'oauth2_sso_clear_cookie');