<?php

use League\OAuth2\Client\Provider\GenericProvider;

function oauth2_sso_handle_login()
{
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

    $oauth2state = isset($_SESSION['oauth2state']) ? $_SESSION['oauth2state'] : null;
    if (!isset($_GET['code']) && !isset($_GET['error'])) {
        // Step 1: Redirect to the OAuth2 server.
        $scopes = ['openid', 'profile',  'email']; // Update scopes here
        $authorizationUrl = $provider->getAuthorizationUrl() . '&scope=' . implode(' ', $scopes);
        //$_SESSION['oauth2state'] = $provider->getState(); // Store the state in the session
        //session_write_close(); // Save the session data
        setcookie('oauth2state', $provider->getState(), time() + 3600, '/');

        //wp_redirect($authorizationUrl);
        header('Location: ' . $authorizationUrl, true, 302);
        exit;
        
    }elseif(empty($_GET['state'])  && $_COOKIE['oauth2state'] !== $_GET['state']){

        $old_state = $_COOKIE['oauth2state'];
        wp_die('Invalid state.-->' . $old_state . '---' . $_GET['state']);

    }elseif (isset($_GET['error'])) {

        wp_die($_GET['error'] . ': ' . $_GET['error_description']);

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
            }

            // Update user meta with additional information.
            $wp_user_info = [
                'ID' => $user->ID,
                'role' => 'subscriber' // Set the role to 'subscriber'
            ];
            wp_update_user($wp_user_info);

            foreach ($attributes as $attribute) {
                //($attribute);
                if (!empty($user_info[$attribute['oauth_attribute']])) {

                    // Update the user meta with the attribute value.
                    update_user_meta($user->ID, $attribute['wp_attribute'],  $user_info[$attribute['oauth_attribute']]);
                    //echo "<p>" . $attribute['oauth_attribute'] . ": " .  $user_info[$attribute['oauth_attribute']] . "</p>";
                }
            }

            //print_r($user);
           // print_r($user_info);
        // die();

            wp_set_current_user($user->ID);
            wp_set_auth_cookie($user->ID);
            wp_redirect(home_url());
            exit;
        } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
            wp_die('Error retrieving access token: ' . $e->getMessage());
        }
    }
    $oauth2state = isset($_SESSION['oauth2state']) ? $_SESSION['oauth2state'] : (isset($_COOKIE['oauth2state']) ? $_COOKIE['oauth2state'] : null);
    if (!isset($_GET['code']) && !isset($_GET['error'])) {
        //unset($_SESSION['oauth2state']); // Clear the state
        // Step 1: Redirect to the OAuth2 server.
        $scopes = ['openid', 'profile',  'email']; // Update scopes here
        $authorizationUrl = $provider->getAuthorizationUrl() . '&scope=' . implode(' ', $scopes);
        $_SESSION['oauth2state'] = $provider->getState(); // Store the state in the session
        // Save the same oauth state to a cookie
        setcookie('oauth2state', $_SESSION['oauth2state'], time() + 3600, '/');
        session_write_close(); // Save the session data
        wp_redirect($authorizationUrl);
        header('Location: ' . $authorizationUrl, true, 302);
        exit;
    } elseif (empty($_GET['state']) || $oauth2state !== $_GET['state']) {
        $old_state = $oauth2state;
        // Invalid state, prevent CSRF attack.
        unset($_SESSION['oauth2state']); // Clear the state
        unset($_COOKIE['oauth2state']);
        wp_die('Invalid state.-->' . $old_state . '---' . $_GET['state']);
    } elseif (isset($_GET['error'])) {
        wp_die($_GET['error'] . ': ' . $_GET['error_description']);
    } else {
        try {

            $oauth2_sso_wp_attributes = get_option('oauth2_sso_wp_attributes') ?: [];
            $oauth2_sso_oauth_attributes = get_option('oauth2_sso_oauth_attributes') ?: [];
            $attributes = array_map(function ($wp_attribute, $oauth_attribute) {
                return ['wp_attribute' => $wp_attribute, 'oauth_attribute' => $oauth_attribute];
            }, $oauth2_sso_wp_attributes, $oauth2_sso_oauth_attributes);


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

                //print_r($user_id);
                if (is_wp_error($user_id)) {
                    
                    wp_die('Failed to create a new user.');
                }
                // Get the user by ID.
                $user = get_user_by('id', $user_id);
            }

            // Update user meta with additional information.
            $wp_user_info = [
                'ID' => $user->ID,
                'role' => 'subscriber' // Set the role to 'subscriber'
            ];
            wp_update_user($wp_user_info);

            // Update user meta with additional information.
            foreach ($attributes as $attribute) {
                if (!empty($user_info[$attribute['oauth_attribute']])) {
                    // Update the user meta with the attribute value.
                    update_user_meta($user->ID, $attribute['wp_attribute'],  $user_info[$attribute['oauth_attribute']]);
                }
            }

            // Log the user in.
            wp_set_current_user($user->ID);
            wp_set_auth_cookie($user->ID);
            wp_redirect(home_url());
            exit;
        } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
            wp_die('Error retrieving access token: ' . $e->getMessage());
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
