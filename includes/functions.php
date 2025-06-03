<?php

use League\OAuth2\Client\Provider\GenericProvider;


function get_auth_cookie_name()
{
    return 'wordpress_oauth2_sso_user';
}
function set_oauth_user_cookie()
{
    
    if (!isset($_COOKIE[get_auth_cookie_name()])) {
        // Generate a new unique ID and set the cookie if it doesn't exist.
        $unique_id = bin2hex(random_bytes(16));
        setcookie(get_auth_cookie_name(), $unique_id, time() + (86400 * 30), '/');
        $_COOKIE[get_auth_cookie_name()] = $unique_id; // Make immediately available
        return $unique_id;
    }
    return $_COOKIE[get_auth_cookie_name()]; // Return existing cookie value
}

function clear_oauth_user_cookie()
{
    if (isset($_COOKIE[get_auth_cookie_name()])) {
        setcookie(get_auth_cookie_name(), '', time() - 3600); // Expire the cookie
    }
}

function get_oauth_user_cookie()
{
    if (!isset($_COOKIE[get_auth_cookie_name()])) {
        return set_oauth_user_cookie(); // Set cookie if it doesn't exist
    }
    return $_COOKIE[get_auth_cookie_name()]; // Return existing cookie
}

function oauth2_sso_handle_login()
{
    
    // Clean up old redirect options periodically
    if (rand(1, 10) === 1) { // 10% chance to run cleanup
        cleanup_old_oauth_redirect_options();
    }
    
    // Generate a unique identifier for the visitor.
    $unique_id = get_oauth_user_cookie();

    // OAuth2 credentials.
    $client_id = get_option('oauth2_sso_client_id');
    $client_secret = get_option('oauth2_sso_client_secret');
    $redirect_uri = get_option('oauth2_sso_redirect_uri');
    $authorization_endpoint = get_option('oauth2_sso_authorization_endpoint');
    $token_endpoint = get_option('oauth2_sso_token_endpoint');
    $user_info_endpoint = get_option('oauth2_sso_user_info_endpoint');

    $oauth2_sso_wp_attributes = get_option('oauth2_sso_wp_attributes') ?: [];
    $oauth2_sso_oauth_attributes = get_option('oauth2_sso_oauth_attributes') ?: [];
    $attributes = array_map(function ($wp_attribute, $oauth_attribute) {
        return ['wp_attribute' => $wp_attribute, 'oauth_attribute' => $oauth_attribute];
    }, $oauth2_sso_wp_attributes, $oauth2_sso_oauth_attributes);

    $provider = new GenericProvider([
        'clientId'                => $client_id,
        'clientSecret'            => $client_secret,
        'redirectUri'             => $redirect_uri,
        'urlAuthorize'            => $authorization_endpoint,
        'urlAccessToken'          => $token_endpoint,
        'urlResourceOwnerDetails' => $user_info_endpoint
    ]);

    if (!isset($_GET['code']) && !isset($_GET['error'])) {

        
        
        if (isset($_GET['redirect_uri'])) {
            update_option('oauth2redirect_' . $unique_id, $_GET['redirect_uri']);
        }
        // Step 1: Redirect to the OAuth2 server.
        $scopes = ['openid', 'profile', 'email']; // Update scopes here
        $authorizationUrl = $provider->getAuthorizationUrl() . '&scope=' . implode(' ', $scopes);

        update_option('oauth2state_' . $unique_id, $provider->getState());
        //wp_redirect($authorizationUrl);
        header('Location: ' . $authorizationUrl, true, 302);
        exit;
    } elseif (empty($_GET['state']) || get_option('oauth2state_' . $unique_id) !== $_GET['state']) {
        ?>
        <div style="font-family: Arial, sans-serif; margin: 20px; padding: 20px; border: 1px solid #f00; background-color: #fee;">
            <h2 style="color: #f00;">Error: Invalid State</h2>
            <p><strong>Unique ID:</strong> <?php echo htmlspecialchars($unique_id); ?></p>
            <p><strong>Expected State:</strong> <?php echo htmlspecialchars(get_option('oauth2state_' . $unique_id)); ?></p>
            <p><strong>Returned State:</strong> <?php echo htmlspecialchars($_GET['state']); ?></p>
            <pre><?php print_r(getallheaders()); ?></pre>
            <pre><?php print_r($_COOKIE)?></pre>
        </div>
        <?php
        wp_die();
    } elseif (isset($_GET['error'])) {
        wp_die($_GET['error']);
    } else {
        try {
            // Step 2: Exchange the authorization code for an access token.
            $accessToken = $provider->getAccessToken('authorization_code', [
                'code' => $_GET['code']
            ]);

            // Step 3: Retrieve user information.
            $resourceOwner = $provider->getResourceOwner($accessToken);
            $user_info = $resourceOwner->toArray();

            // Step 4: Map user information to WordPress fields.
            $email = $user_info['email'];

            // Step 5: Log the user in or create a new user.
            $user = get_user_by('email', $email);
            if (!$user) {
                // Create a new user if one doesn't exist.
                $username = sanitize_user($user_info['preferred_username'] ?? $email);
                $password = wp_generate_password();
                $user_id = wp_create_user($username, $password, $email);

                if (is_wp_error($user_id)) {
                    wp_die('Failed to create a new user.');
                }
                $user = get_user_by('id', $user_id);

                // Update user meta with additional information.
                $wp_user_info = [
                    'ID' => $user->ID,
                    'role' => 'subscriber' // Set the role to 'subscriber'
                ];
                wp_update_user($wp_user_info);
            }

            foreach ($attributes as $attribute) {
                if (!empty($user_info[$attribute['oauth_attribute']])) {
                    // Update the user meta with the attribute value.
                    update_user_meta($user->ID, $attribute['wp_attribute'], $user_info[$attribute['oauth_attribute']]);
                }
            }

            wp_set_current_user($user->ID);
            wp_set_auth_cookie($user->ID);
            $redirect_uri = get_option('oauth2redirect_' . $unique_id);

            # clean up login state and redirect
            delete_option('oauth2redirect_' . $unique_id);
            delete_option('oauth2state_' . $unique_id);
            // Check if the redirect URI already has query parameters.
            if (strpos($redirect_uri, '?') !== false) {
                // Append the nonce as an additional query parameter.
                $redirect_uri .= '&nonce=' . wp_create_nonce('oauth2redirect');
            } else {
                // Add the nonce as the first query parameter.
                $redirect_uri .= '?nonce=' . wp_create_nonce('oauth2redirect');
            }
            wp_redirect($redirect_uri);
            exit;
        } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
            // retry login
            $scopes = ['openid', 'profile', 'email']; // Update scopes here
            $authorizationUrl = $provider->getAuthorizationUrl() . '&scope=' . implode(' ', $scopes);
            header('Refresh: 5; Location: ' . $authorizationUrl, true);
            wp_die('Retrying Login - Error retrieving access token: ' . $e->getMessage());
        }
    }
}

// Hook into the user profile process.
add_action('show_user_profile', 'oauth2_sso_show_extra_profile_fields');
add_action('edit_user_profile', 'oauth2_sso_show_extra_profile_fields');

// Display additional profile fields.
function oauth2_sso_show_extra_profile_fields($user)
{
    // Get the list of attributes to display.
    $wp_attributes = get_option('oauth2_sso_wp_attributes') ?: [];
?>
    <h3>oAuth Profile attributes</h3>
    <?php
    // Display the attributes.
    foreach ($wp_attributes as $wp_attribute) {
        $value = get_user_meta($user->ID, $wp_attribute, true);
    ?>
        <table class="form-table">
            <tr>
                <th><label for="<?php echo esc_attr($wp_attribute); ?>"><?php echo esc_html($wp_attribute); ?></label></th>
                <td>
                    <input type="text" name="<?php echo esc_attr($wp_attribute); ?>" id="<?php echo esc_attr($wp_attribute); ?>" value="<?php echo esc_attr($value); ?>" class="regular-text" readonly />
                </td>
            </tr>
        </table>
<?php
    }
}

function cleanup_old_oauth_redirect_options()
{
    global $wpdb;
    
    // Query all oauth2redirect_ options, ordered by option_id (creation order)
    $results = $wpdb->get_results(
        "SELECT option_name FROM {$wpdb->options} 
         WHERE option_name LIKE 'oauth2redirect_%' 
         ORDER BY option_id DESC",
        ARRAY_A
    );
    
    // If we have more than 10 options, delete the oldest ones
    if (count($results) > 10) {
        // Keep the first 10 (most recent), delete the rest
        $options_to_delete = array_slice($results, 10);
        
        foreach ($options_to_delete as $option) {
            delete_option($option['option_name']);
        }
        
        return count($options_to_delete); // Return number of deleted options
    }
    
    return 0; // No options deleted
}
