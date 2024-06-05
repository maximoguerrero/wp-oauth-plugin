# OAuth2 SSO Settings

This document provides instructions on how to fill in the OAuth2 SSO settings in your WordPress admin panel.

## Fields

### Client ID

This is the client ID provided by your OAuth2 provider. It is a unique identifier for your application.

Example: `1234567890abcdef`

### Client Secret

This is the client secret provided by your OAuth2 provider. It is a secret known only to your application and the authorization server.

Example: `abcdef1234567890`

### Redirect URI

This is the URL where the user will be redirected after they authorize your application. This must match exactly the redirect URI you registered with your OAuth2 provider.

Example: `https://yourwebsite.com/`

## Steps

1. Navigate to the OAuth2 SSO settings page in your WordPress admin panel.
2. Fill in the "Client ID" field with your client ID.
3. Fill in the "Client Secret" field with your client secret.
4. Fill in the "Redirect URI" field with your redirect URI.
5. Click "Save Changes" to save your settings.

Please note that all fields are required. If any field is left empty, you will not be able to save your settings.




## Testing

After you have saved your settings, you can test the OAuth2 SSO by navigating to the login URL generated on the settings page. If everything is set up correctly, you should be redirected to your OAuth2 provider's authorization page.


## Attribute Mapping
In addition to filling in the OAuth2 SSO settings, you may also need to map attributes between your WordPress user profile and the attributes provided by your OAuth2 provider. This allows you to synchronize user data between the two systems.

To map attributes, follow these steps:

1. Navigate to the "Attribute Mapping" section on the OAuth2 SSO settings page in your WordPress admin panel.
2. You will see a list of available attributes provided by your OAuth2 provider.
3. For each attribute, select the corresponding WordPress user profile field from the dropdown menu.
4. Click "Save Changes" to save your attribute mapping settings.

Please note that attribute mapping is optional. If you do not need to synchronize user data, you can skip this step.

After mapping attributes, the corresponding user data from your OAuth2 provider will be automatically populated in the mapped fields of the WordPress user profile.

You can test the attribute mapping by logging in with an OAuth2 user and checking if the mapped fields in the WordPress user profile are populated with the correct data.