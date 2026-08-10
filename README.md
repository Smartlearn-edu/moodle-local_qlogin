# Moodle Quick Mobile Login (local_qlogin)

The **Quick Mobile Login (`local_qlogin`)** is a Moodle local plugin designed to streamline the authentication and registration process for students by offering a mobile-first, phone-number-based login and registration system. 

It provides an intuitive interface with phone number validation and optionally supports Google OAuth integration, significantly reducing friction in user onboarding.

## Features

- **Phone-Based Registration**: Users can register using just their phone number (acting as their username), full name, and password. Email is optional.
- **Flexible Login Options**: Users can choose to log in using their registered Phone Number or a standard Moodle Username.
- **International Phone Validation**: Integrates the `intl-tel-input` library to format and validate mobile numbers (defaulting to Saudi Arabia and Egypt).
- **Google OAuth Support**: Automatically detects and displays a "Sign in with Google" button if Moodle's core OAuth2 Google authentication is configured and enabled.
- **Anti-Bot Honeypot**: Implements a hidden `username` field honeypot to trap and block automated bot submissions.
- **Auto Email Generation**: If a user registers without an email, a placeholder email (`[phone]@users.nomail.com`) is automatically generated to satisfy Moodle's core requirements.
- **Password Recovery**: Includes a "Forgot Password" link pointing to the plugin's custom `forgot_password.php`.

## Technical Details

### Architecture & Moodle Integration
- **Plugin Type**: Local plugin (`local`)
- **Component**: `local_qlogin`
- **Moodle Version Requirements**: Built for Moodle 4.1+ (Requires `2022112800`).
- **Context & Layout**: Uses `context_system::instance()` and `login` page layout to integrate seamlessly with the site's theme.
- **Auth Method**: Users created via this plugin are assigned the `manual` authentication method (`$user->auth = 'manual'`).

### Data Flow & Security
1. **Sanitization**: All user inputs are sanitized using Moodle's built-in `clean_param()` (e.g., `PARAM_NOTAGS`, `PARAM_EMAIL`, `PARAM_TEXT`).
2. **Phone Normalization**: Phone numbers are stripped of all non-numeric characters (`preg_replace('/[^0-9]/', '', $phone)`) before being stored as the Moodle `username`.
3. **Honeypot Validation**: The form submission is immediately rejected with a "Traffic verification failed" message if the visually-hidden honeypot field is filled.
4. **Moodle API Usage**:
    - `user_create_user()`: Safely creates the Moodle user account.
    - `validate_internal_user_password()`: Securely checks password hashes.
    - `complete_user_login()`: Handles the session instantiation after successful authentication.
    - `$DB->get_record_select()` and `$DB->record_exists()`: Used for safe database queries.

### Frontend Technologies
- **HTML/CSS/JS**: Vanilla JS and custom CSS (`qlogin_styles.css`).
- **External Dependencies**:
    - `intl-tel-input` (v18.2.1) loaded via jsDelivr CDN for country code dropdown and JS validation.

## File Structure

- `index.php`: The main entry point. Handles the UI tabs (Login/Register), form submissions, database lookups, and session instantiation.
- `version.php`: Plugin metadata, versioning, and Moodle core requirements.
- `forgot_password.php`: Handles password recovery flow.
- `qlogin_styles.css`: Scoped CSS styles for the login card, tabs, buttons, and inputs.
- `lang/en/local_qlogin.php`: English language strings for localization.

## Installation

1. Clone or extract the plugin into the `/local/qlogin` directory of your Moodle installation.
2. Log in as a Site Administrator.
3. Complete the standard Moodle plugin installation and upgrade process via the Notifications page.
4. (Optional) To utilize the Google Login button, ensure Google OAuth2 is configured in **Site administration > Server > OAuth 2 services**.

## Usage

Direct users to `[moodle-url]/local/qlogin/index.php`. For the best experience, you can set your Moodle site's "Alternate login URL" (in Site Administration > Security > Site policies) to this path to override the default Moodle login page.
