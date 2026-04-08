<?php

// Register settings.
add_action('admin_init', 'oauth2_sso_register_settings');

function oauth2_sso_sessions_page()
{
    global $wpdb;

    if (!current_user_can('manage_options')) {
        wp_die('Unauthorized');
    }

    // Fetch all oauth2state_ options (each stores ['state'=>..., 'expires'=>...]).
    $rows = $wpdb->get_results(
        "SELECT
            REPLACE(option_name, 'oauth2state_', '') AS session_id,
            option_value
         FROM {$wpdb->options}
         WHERE option_name LIKE 'oauth2state\_%'
         ORDER BY option_id DESC"
    );

    $now = time();
    $expired_count = 0;
    // Enrich rows with parsed expiry.
    foreach ($rows as $row) {
        $data = maybe_unserialize($row->option_value);
        $row->expires_at = is_array($data) && isset($data['expires']) ? (int) $data['expires'] : 0;
        if ($row->expires_at < $now) {
            $expired_count++;
        }
    }
?>
    <div class="wrap">
        <h1>OAuth2 SSO &mdash; Active Sessions</h1>

        <?php if (isset($_GET['purged'])) : ?>
            <div class="notice notice-success is-dismissible">
                <p>Expired options purged successfully.</p>
            </div>
        <?php endif; ?>

        <p>
            These are pending OAuth2 login flows (state options still present in the database).
            Each row represents a browser that started the login process but has not yet completed or timed out.
            Options expire after <strong>10 minutes</strong>; expired rows are cleaned up
            by the hourly cron or by clicking <em>Purge Expired</em> below.
        </p>

        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin-bottom:16px;">
            <input type="hidden" name="action" value="oauth2_sso_purge_transients">
            <?php wp_nonce_field('oauth2_sso_purge_transients'); ?>
            <?php submit_button(
                sprintf('Purge Expired (%d)', $expired_count),
                $expired_count > 0 ? 'secondary' : 'secondary',
                'submit',
                false,
                $expired_count === 0 ? ['disabled' => 'disabled'] : []
            ); ?>
        </form>

        <?php if (empty($rows)) : ?>
            <p><em>No pending session options found.</em></p>
        <?php else : ?>
            <table class="widefat striped" style="max-width:900px;">
                <thead>
                    <tr>
                        <th>Session ID (cookie)</th>
                        <th>Has Redirect Target</th>
                        <th>Expires At</th>
                        <th>TTL / Status</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($rows as $row) :
                        $ttl        = $row->expires_at - $now;
                        $expired    = $ttl <= 0;
                        $has_redirect = (bool) $wpdb->get_var(
                            $wpdb->prepare(
                                "SELECT COUNT(*) FROM {$wpdb->options}
                                 WHERE option_name = %s",
                                'oauth2redirect_' . $row->session_id
                            )
                        );

                        if ($expired) {
                            $ttl_label = '<span style="color:#b32d2e;">Expired ' . human_time_diff($row->expires_at, $now) . ' ago</span>';
                            $row_style = 'opacity:.65;';
                        } else {
                            $mins = floor($ttl / 60);
                            $secs = $ttl % 60;
                            $ttl_label = '<span style="color:#0a6b1e;">Active &mdash; ' . $mins . 'm ' . $secs . 's remaining</span>';
                            $row_style = '';
                        }
                    ?>
                        <tr style="<?php echo $row_style; ?>">
                            <td><code><?php echo esc_html(substr($row->session_id, 0, 12) . '&hellip;'); ?></code></td>
                            <td><?php echo $has_redirect ? '<span style="color:#0a6b1e;">&#10003; Yes</span>' : '<span style="color:#888;">&#8212; No</span>'; ?></td>
                            <td><?php echo esc_html(date('Y-m-d H:i:s', $row->expires_at)); ?></td>
                            <td><?php echo $ttl_label; ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <p style="color:#888;font-size:12px;">
                Showing <?php echo count($rows); ?> session(s) &mdash;
                <?php echo $expired_count; ?> expired,
                <?php echo count($rows) - $expired_count; ?> active.
            </p>
        <?php endif; ?>
    </div>
<?php
}

// Add settings page to the admin menu.
function oauth2_sso_register_settings()
{
    register_setting('oauth2_sso_settings', 'oauth2_sso_client_id');
    register_setting('oauth2_sso_settings', 'oauth2_sso_client_secret');
    register_setting('oauth2_sso_settings', 'oauth2_sso_redirect_uri');
    register_setting('oauth2_sso_settings', 'oauth2_sso_authorization_endpoint');
    register_setting('oauth2_sso_settings', 'oauth2_sso_token_endpoint');
    register_setting('oauth2_sso_settings', 'oauth2_sso_user_info_endpoint');
    register_setting('oauth2_sso_settings', 'oauth2_sso_wp_attributes', 'oauth2_sso_sanitize_attributes');
    register_setting('oauth2_sso_settings', 'oauth2_sso_oauth_attributes', 'oauth2_sso_sanitize_attributes');
    register_setting('oauth2_sso_settings', 'oauth2_sso_oauth_login_text');
}
function oauth2_sso_sanitize_attributes($attributes)
{
    // Remove empty attributes
    return array_filter($attributes, function ($attribute) {
        return !empty($attribute);
    });
}
function oauth2_sso_settings_page()
{
    // Get the settings.
    $client_id = get_option('oauth2_sso_client_id');
    $redirect_uri = get_option('oauth2_sso_redirect_uri');
    $authorization_endpoint = get_option('oauth2_sso_authorization_endpoint');


    // Get the attribute mapping.
    $oauth2_sso_wp_attributes = get_option('oauth2_sso_wp_attributes') ?: [];
    $oauth2_sso_oauth_attributes = get_option('oauth2_sso_oauth_attributes') ?: [];
    $attributes = array_map(function ($wp_attribute, $oauth_attribute) {
        return ['wp_attribute' => $wp_attribute, 'oauth_attribute' => $oauth_attribute];
    }, $oauth2_sso_wp_attributes, $oauth2_sso_oauth_attributes);

    // Generate a login URL for testing.
    $login_url = '';
    if ($client_id && $redirect_uri && $authorization_endpoint) {
        $login_url =  $redirect_uri . "?oauth2_sso=";
    }
?>
    <div class="wrap">
        <h1>OAuth2 SSO Settings</h1>
        <p>
            Users will be mapped to role <code>subscriber</code> by default.
        </p>
        <form method="post" action="options.php">
            <?php settings_fields('oauth2_sso_settings'); ?>
            <?php do_settings_sections('oauth2_sso_settings'); ?>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row">Client ID *</th>
                    <td><input required type="text" name="oauth2_sso_client_id" value="<?php echo esc_attr(get_option('oauth2_sso_client_id')); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Client Secret *</th>
                    <td><input required type="password" name="oauth2_sso_client_secret" value="<?php echo esc_attr(get_option('oauth2_sso_client_secret')); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Redirect URI *</th>
                    <td><input required type="text" name="oauth2_sso_redirect_uri" value="<?php echo esc_attr(get_option('oauth2_sso_redirect_uri')); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Authorization Endpoint *</th>
                    <td><input required type="text" name="oauth2_sso_authorization_endpoint" value="<?php echo esc_attr(get_option('oauth2_sso_authorization_endpoint')); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Token Endpoint *</th>
                    <td><input required type="text" name="oauth2_sso_token_endpoint" value="<?php echo esc_attr(get_option('oauth2_sso_token_endpoint')); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">User Info Endpoint *</th>
                    <td><input required type="text" name="oauth2_sso_user_info_endpoint" value="<?php echo esc_attr(get_option('oauth2_sso_user_info_endpoint')); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Login Button Text</th>
                    <td><input  type="text" name="oauth2_sso_oauth_login_text" value="<?php echo esc_attr(get_option('oauth2_sso_oauth_login_text')); ?>" /></td>
                </tr>
            </table>
            <h2>Scope</h2>
            <p>
                Default scope is <code>openid profile email</code>.
                <br>
                These are the permissions that the OAuth provider will request from the user.
            </p>
            <h2>Attribute Mapping</h2>
            <p>Map user attributes from the OAuth provider to WordPress user attributes.</p>
            <table class="form-table" id="attribute-mapping-table">
                <?php foreach ($attributes as $attribute) : ?>
                    <tr valign="top" class="attribute-mapping">
                        <th scope="row">WordPress Attribute:</th>
                        <td><input type="text" name="oauth2_sso_wp_attributes[]" value="<?php echo esc_attr($attribute['wp_attribute']); ?>" /></td>
                    </tr>
                    <tr valign="top" class="attribute-mapping">
                        <th scope="row">OAuth Provider Attribute:</th>
                        <td><input type="text" name="oauth2_sso_oauth_attributes[]" value="<?php echo esc_attr($attribute['oauth_attribute']); ?>" /></td>
                        <td><button type="button" class="remove-attribute-button">Remove</button></td>
                    </tr>
                <?php endforeach; ?>
            </table>
            <button type="button" id="add-attribute-button">Add Attribute</button>
            <br><br>
            <?php submit_button(); ?>
        </form>
        <script>
            // Add a new attribute mapping row.
            document.getElementById('add-attribute-button').addEventListener('click', function() {
                var table = document.getElementById('attribute-mapping-table');
                var row1 = document.createElement('tr');
                row1.innerHTML = '<th scope="row">WordPress Attribute:</th><td><input type="text" name="oauth2_sso_wp_attributes[]" value="" /></td>';
                var row2 = document.createElement('tr');
                row2.innerHTML = '<th scope="row">OAuth Provider Attribute:</th><td><input type="text" name="oauth2_sso_oauth_attributes[]" value="" /></td>';
                table.appendChild(row1);
                table.appendChild(row2);
            });

            // Remove an attribute mapping row.
            document.getElementById('attribute-mapping-table').addEventListener('click', function(e) {
                if (e.target && e.target.matches('.remove-attribute-button')) {
                    var row = e.target.closest('.attribute-mapping');
                    row.previousElementSibling.remove();
                    row.remove();
                }
            });
        </script>
        <?php if ($login_url) : ?>
            <hr>
            <h3>Test Login Request URL</h2>
                <p><a href="<?php echo esc_url($login_url); ?>" target="_blank"><?php echo esc_html($login_url); ?></a></p>
            <?php endif; ?>
    </div>
<?php
}
?>