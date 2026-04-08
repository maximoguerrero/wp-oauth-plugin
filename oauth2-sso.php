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

// Exit if running via WP-CLI.
if (defined('WP_CLI') && WP_CLI) {
    return;
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
register_activation_hook(__FILE__, 'oauth2_sso_activate');
register_deactivation_hook(__FILE__, 'oauth2_sso_deactivate');

/**
 * On activation: clean up any legacy orphaned options and schedule
 * the periodic expired-transient purge via WP-Cron.
 */
function oauth2_sso_activate()
{
    oauth2_sso_cleanup_orphaned_options();
    if (!wp_next_scheduled('oauth2_sso_purge_expired_options')) {
        wp_schedule_event(time(), 'hourly', 'oauth2_sso_purge_expired_options');
    }
}

/**
 * On deactivation: remove the scheduled cron event.
 */
function oauth2_sso_deactivate()
{
    $timestamp = wp_next_scheduled('oauth2_sso_purge_expired_options');
    if ($timestamp) {
        wp_unschedule_event($timestamp, 'oauth2_sso_purge_expired_options');
    }
    // Also unschedule legacy hook name from previous versions.
    $legacy = wp_next_scheduled('oauth2_sso_purge_transients');
    if ($legacy) {
        wp_unschedule_event($legacy, 'oauth2_sso_purge_transients');
    }
}

// For already-active installs: run the legacy options cleanup once and
// register the cron if it hasn't been scheduled yet.
add_action('admin_init', function () {
    if (!get_option('oauth2_sso_orphan_cleanup_done')) {
        oauth2_sso_cleanup_orphaned_options();
        update_option('oauth2_sso_orphan_cleanup_done', true, false); // autoload=false
    }
    if (!wp_next_scheduled('oauth2_sso_purge_expired_options')) {
        wp_schedule_event(time(), 'hourly', 'oauth2_sso_purge_expired_options');
    }
    // Remove legacy cron hook from transient era.
    $legacy = wp_next_scheduled('oauth2_sso_purge_transients');
    if ($legacy) {
        wp_unschedule_event($legacy, 'oauth2_sso_purge_transients');
    }
});

// Bind the cron event to the purge function.
add_action('oauth2_sso_purge_expired_options', 'oauth2_sso_delete_expired_options');

/**
 * Delete any leftover oauth2 transient rows from wp_options
 * that accumulated before the switch to direct options.
 */
function oauth2_sso_cleanup_orphaned_options()
{
    global $wpdb;
    $wpdb->query(
        "DELETE FROM {$wpdb->options}
         WHERE option_name LIKE '_transient_oauth2state\_%'
            OR option_name LIKE '_transient_timeout_oauth2state\_%'
            OR option_name LIKE '_transient_oauth2redirect\_%'
            OR option_name LIKE '_transient_timeout_oauth2redirect\_%'"
    );
}

/**
 * Delete expired oauth2state_* and oauth2redirect_* options from wp_options.
 *
 * Each oauth2state_{id} option stores a serialised array with an 'expires'
 * timestamp. Options past their expiry (and the matching redirect option)
 * are removed.
 */
function oauth2_sso_delete_expired_options()
{
    global $wpdb;

    // Fetch all oauth2state_ options.
    $rows = $wpdb->get_results(
        "SELECT option_name, option_value
         FROM {$wpdb->options}
         WHERE option_name LIKE 'oauth2state\_%'"
    );

    $now = time();
    foreach ($rows as $row) {
        $data = maybe_unserialize($row->option_value);
        $expires = is_array($data) && isset($data['expires']) ? (int) $data['expires'] : 0;

        // Delete if expired or if the data is not in the expected format
        // (legacy plain-string values from before the migration).
        if ($expires < $now) {
            $session_id = str_replace('oauth2state_', '', $row->option_name);
            delete_option('oauth2state_' . $session_id);
            delete_option('oauth2redirect_' . $session_id);
        }
    }
}



include_once(ABSPATH . 'wp-admin/includes/plugin.php');

// Initialize plugin.
function oauth2_sso_init()
{
    // Allow cron requests to pass through without any processing
    if ((defined('DOING_CRON') && DOING_CRON) || (isset($_SERVER['REQUEST_URI']) && strpos($_SERVER['REQUEST_URI'], 'wp-cron.php') !== false)) {
        return;
    }

    if (is_plugin_active(plugin_basename(OAUTH2_SSO_PLUGIN_DIR . 'oauth2-sso.php'))) {
        // Check if the user is attempting to log in via OAuth2.
        if (isset($_GET['oauth2_sso']) || isset($_GET['code']) || isset($_GET['error'])) {

            // set no cache headers
            header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
            header("Cache-Control: post-check=0, pre-check=0", false);
            header("Pragma: no-cache");

            // Handle the login process.
            oauth2_sso_handle_login();
        }

        if (is_front_page() || is_home()) {
            // Set no cache headers for the root website.
            header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
            header("Cache-Control: post-check=0, pre-check=0", false);
            header("Pragma: no-cache");
        }
    }
}

function require_authentication()
{
    // Allow cron requests to pass through without forcing authentication.
    if ((defined('DOING_CRON') && DOING_CRON) || (isset($_SERVER['REQUEST_URI']) && strpos($_SERVER['REQUEST_URI'], 'wp-cron.php') !== false)) {
        return;
    }

    // Allow AJAX / REST requests through.
    if (defined('DOING_AJAX') && DOING_AJAX) {
        return;
    }
    if (defined('REST_REQUEST') && REST_REQUEST) {
        return;
    }

    // Never redirect if this is already an OAuth callback or login flow;
    // oauth2_sso_init() on 'init' handles these — we must not re-redirect.
    if (isset($_GET['oauth2_sso']) || isset($_GET['code']) || isset($_GET['error']) || isset($_GET['state'])) {
        return;
    }

    // Let the standard wp-login.php page load normally.
    if (strpos($_SERVER['REQUEST_URI'], 'wp-login.php') !== false) {
        return;
    }

    if (! is_user_logged_in()) {

        // Redirect to OAuth provider directly.
        $redirect_uri = get_option('oauth2_sso_redirect_uri');
        if ($redirect_uri && ! empty($redirect_uri)) {
            header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
            header("Cache-Control: post-check=0, pre-check=0", false);
            header("Pragma: no-cache");
            wp_redirect($redirect_uri . '?oauth2_sso=true&redirect_uri=' . esc_url(get_current_url()));
            exit;
        }
        wp_redirect(wp_login_url(get_current_url()));
        exit;
    }
}
function get_current_url()
{
    $url = (isset($_SERVER['HTTPS']) && 'on' === $_SERVER['HTTPS'] ? 'https' : 'http')
        . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
    $url = strtok($url, '?');

    // Add query parameters if they exist.
    if (!empty($_GET)) {
        $query_params = http_build_query($_GET);
        $url .= '?' . $query_params;
    }


    return $url;
}

// Add a button to the login form.
function oauth2_sso_add_login_button()
{


    // Save the 'redirect_to' query string to a variable if it exists.
    $redirect_to = isset($_GET['redirect_to']) ? "&redirect_uri=" . esc_url($_GET['redirect_to']) : '';


    $login_text = get_option('oauth2_sso_oauth_login_text');
    if (empty($login_text)) {
        $login_text = 'Login with OAuth2';
    }

    // Add a button to the login form.
    $button_html = '<div id="oauth2SSO" style="margin:20px; clear:both; text-align:center;"><a href="?oauth2_sso=' . uniqid() . $redirect_to . '" class="button button button-large">' . $login_text . '</a></div>';
    echo $button_html;
}

// Add the login button to the login form.
add_action('login_form', 'oauth2_sso_add_login_button');


// Add custom JavaScript to the login page.
function oauth2_sso_login_js()
{
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
    add_submenu_page(
        'options-general.php',
        'OAuth2 SSO Sessions',
        'OAuth2 Sessions',
        'manage_options',
        'oauth2-sso-sessions',
        'oauth2_sso_sessions_page'
    );
}

// Handle the manual purge form submission.
add_action('admin_post_oauth2_sso_purge_transients', 'oauth2_sso_handle_purge');
function oauth2_sso_handle_purge()
{
    check_admin_referer('oauth2_sso_purge_transients');
    if (!current_user_can('manage_options')) {
        wp_die('Unauthorized', 403);
    }
    oauth2_sso_delete_expired_options();
    wp_redirect(add_query_arg(
        ['page' => 'oauth2-sso-sessions', 'purged' => '1'],
        admin_url('options-general.php')
    ));
    exit;
}

// Clear cookie on logout.
function oauth2_sso_clear_cookie()
{
    $unique_id = get_oauth_user_cookie();
    delete_option('oauth2state_' . $unique_id);
    delete_option('oauth2redirect_' . $unique_id);
    clear_oauth_user_cookie();
}
// Clear the cookie on logout.
add_action('wp_logout', 'oauth2_sso_clear_cookie');
