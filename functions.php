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


    $final_redirect =  home_url() . "?final=". isset($_COOKIE['oauth2redirect']) ? $_COOKIE['oauth2redirect'] : '';


    $provider = new GenericProvider([
        'clientId'                => $client_id,
        'clientSecret'            => $client_secret,
        'redirectUri'             => $redirect_uri,
        'urlAuthorize'            => $authorization_endpoint,
        'urlAccessToken'          => $token_endpoint,
        'urlResourceOwnerDetails' => $user_info_endpoint
    ]);

    if (!isset($_GET['code']) && !isset($_GET['error'])) {
        // Step 1: Redirect to the OAuth2 server.
        $scopes = ['openid', 'profile',  'email']; // Update scopes here
        $authorizationUrl = $provider->getAuthorizationUrl() . '&scope=' . implode(' ', $scopes);
        setcookie('oauth2state', $provider->getState(), time() + 3600, '/');
        
        if (isset($_GET['redirect_uri'])){
            $redirect_uri = $_GET['redirect_uri'];
            setcookie('oauth2redirect',  $redirect_uri , time() + 3600, '/');
        }

        //wp_redirect($authorizationUrl);
        header('Location: ' . $authorizationUrl, true, 302);
        exit;
    } elseif (empty($_GET['state'])  && $_COOKIE['oauth2state'] !== $_GET['state']) {

        wp_die('Invalid state');
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
                //($attribute);
                if (!empty($user_info[$attribute['oauth_attribute']])) {

                    // Update the user meta with the attribute value.
                    update_user_meta($user->ID, $attribute['wp_attribute'],  $user_info[$attribute['oauth_attribute']]);
                }
            }

            wp_set_current_user($user->ID);
            wp_set_auth_cookie($user->ID);
            

            //setcookie('oauth2redirect', '', time() - 3600, '/');

            header('Location: ' . $final_redirect, true, 302);
            exit;
        } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
            // retry login 
            header('Refresh:5; Location: ' . $authorizationUrl, true);
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
