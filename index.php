<?php
// This file is part of Moodle - https://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <https://www.gnu.org/licenses/>.

require_once('../../config.php');
require_once($CFG->libdir . '/authlib.php');
require_once($CFG->dirroot . '/user/lib.php');

$context = context_system::instance();
$PAGE->set_context($context);
$PAGE->set_url(new moodle_url('/local/qlogin/index.php'));
$PAGE->set_pagelayout('login'); // Use login layout, keeps basic Moodle structure
$PAGE->set_title(get_string('pluginname', 'local_qlogin'));

// Include the plugin's scoped CSS
$PAGE->requires->css('/local/qlogin/qlogin_styles.css');

if (isloggedin() && !isguestuser()) {
    redirect($CFG->wwwroot . '/my/');
}

$action = optional_param('action', 'login', PARAM_ALPHA);
$error_msg = '';

if ($data = data_submitted()) {
    // --- HONEYPOT TRAP ---
    $trap = isset($data->username) ? $data->username : '';
    if (!empty($trap)) {
        redirect($CFG->wwwroot, 'Traffic verification failed.', 3);
        die();
    }

    // --- REAL INPUTS ---
    $phone = isset($data->mobile_num) ? clean_param($data->mobile_num, PARAM_NOTAGS) : '';

    // Remove leading '+' if present (standardize to digits)
    $clean_phone = preg_replace('/[^0-9]/', '', $phone);

    $password = isset($data->password) ? $data->password : '';
    $form_action = isset($data->form_action) ? $data->form_action : 'login';

    // Validate based on method
    $valid_input = true;
    if ($form_action === 'login') {
        // Check if username was provided instead of phone
        if (empty($clean_phone) && empty($data->login_username)) {
            $valid_input = false;
        }
    } else {
        if (empty($clean_phone)) {
            $valid_input = false;
        }
    }

    if (!$valid_input || empty($password)) {
        $error_msg = get_string('error_phone_required', 'local_qlogin');
    } else {
        if ($form_action === 'login') {
            // LOGIC: DETERMINE LOGIN SOURCE (Phone or Username)
            $login_input = '';

            // Check if user typed in "Username" field
            if (isset($data->login_username) && !empty($data->login_username)) {
                $login_input = clean_param($data->login_username, PARAM_RAW); // Allow letters/mixed
            }
            // Else fallback to Phone field
            else if (!empty($clean_phone)) {
                $login_input = $clean_phone; // Numbers only
            }

            // Search DB by username
            $user = $DB->get_record_select('user', "username = :u AND deleted = 0 AND suspended = 0", ['u' => $login_input]);

            if ($user && validate_internal_user_password($user, $password)) {
                complete_user_login($user);
                redirect($CFG->wwwroot . '/my/');
            } else {
                $error_msg = get_string('error_auth_failed', 'local_qlogin');
            }
        } else if ($form_action === 'register') {
            // Check duplicate
            if ($DB->record_exists('user', ['username' => $clean_phone, 'deleted' => 0])) {
                $error_msg = get_string('error_user_exists', 'local_qlogin');
            } else {
                $name = isset($data->fullname) ? clean_param($data->fullname, PARAM_TEXT) : 'Student';
                $email = isset($data->email) && !empty($data->email) ? clean_param($data->email, PARAM_EMAIL) : '';

                if (empty($email)) {
                    $email = $clean_phone . '@users.nomail.com';
                }

                $parts = explode(' ', $name, 2);
                $firstname = $parts[0];
                $lastname = isset($parts[1]) ? $parts[1] : '-';

                $newuser = new stdClass();
                $newuser->username = $clean_phone; // Store as Digits (e.g. 96650...)
                $newuser->password = hash_internal_user_password($password);
                $newuser->email = $email;
                $newuser->firstname = $firstname;
                $newuser->lastname = $lastname;
                $newuser->confirmed = 1;
                $newuser->auth = 'manual';
                $newuser->mnethostid = $CFG->mnet_localhost_id;
                $newuser->lang = $CFG->lang;

                try {
                    $newuser->id = user_create_user($newuser, false, false);
                    $user_record = $DB->get_record('user', ['id' => $newuser->id]);
                    complete_user_login($user_record);
                    redirect($CFG->wwwroot . '/my/');
                } catch (Exception $e) {
                    $error_msg = 'Error: ' . $e->getMessage();
                }
            }
        }
    }
}

// Get site logo URL (if configured in Moodle)
$logourl = $OUTPUT->get_logo_url();
$sitename = format_string($SITE->fullname);

echo $OUTPUT->header();
?>

<!-- Phone Library CDN -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/intl-tel-input@18.2.1/build/css/intlTelInput.css">
<script src="https://cdn.jsdelivr.net/npm/intl-tel-input@18.2.1/build/js/intlTelInput.min.js"></script>

<div id="qlogin-wrapper">
    <div class="qlogin-card">

        <!-- Site Logo / Name -->
        <div class="qlogin-logo">
            <?php if ($logourl) : ?>
                <img src="<?php echo $logourl; ?>" alt="<?php echo $sitename; ?>">
            <?php else : ?>
                <div class="site-name"><?php echo $sitename; ?></div>
            <?php endif; ?>
        </div>

        <!-- Tabs: Login / Register -->
        <div class="auth-tabs">
            <button class="tab-btn active" onclick="switchTab('login')" id="btn-login">Login</button>
            <button class="tab-btn" onclick="switchTab('register')" id="btn-register">Register</button>
        </div>

        <h2 class="form-title" id="form-title">Welcome Back</h2>
        <p class="form-subtitle" id="form-subtitle">Access your courses.</p>

        <?php if ($error_msg) : ?>
            <div class="alert alert-danger"><?php echo $error_msg; ?></div>
        <?php endif; ?>

        <form method="post" action="index.php" id="qlogin-form">
            <input type="hidden" name="form_action" id="form_action" value="login">

            <!-- HONEYPOT -->
            <div class="hp-field">
                <label>Username</label>
                <input type="text" name="username" tabindex="-1" autocomplete="off">
            </div>

            <!-- LOGIN METHOD TOGGLE (Only visible in Login Tab) -->
            <div id="login-method-toggle">
                <label style="margin-bottom:5px; display:block; font-size:0.85rem; color: #444;">Login Using:</label>
                <div class="method-switch">
                    <label class="method-option selected" id="opt-phone">
                        <input type="radio" name="login_method" value="phone" onclick="toggleLoginInput('phone')" checked>
                        Phone Number
                    </label>
                    <label class="method-option" id="opt-user">
                        <input type="radio" name="login_method" value="user" onclick="toggleLoginInput('user')">
                        Username
                    </label>
                </div>
            </div>

            <!-- REAL PHONE INPUT -->
            <div class="form-group" id="group-phone">
                <label>Phone Number</label>
                <input type="tel" id="mobile_num_visible" class="form-control" style="padding-left: 90px;">
                <input type="hidden" name="mobile_num" id="mobile_num_hidden">
            </div>

            <!-- USERNAME INPUT (Hidden by default) -->
            <div class="form-group hidden" id="group-user">
                <label>Username</label>
                <input type="text" name="login_username" class="form-control" placeholder="e.g. ahmed_student">
            </div>

            <!-- NAME & EMAIL (Register Only) -->
            <div class="form-group hidden" id="field-name">
                <label>Full Name</label>
                <input type="text" name="fullname" class="form-control" placeholder="Ali Ahmed">
            </div>

            <div class="form-group hidden" id="field-email">
                <label>Email (Optional)</label>
                <input type="email" name="email" class="form-control" placeholder="ali@example.com">
            </div>

            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" class="form-control" placeholder="••••••••" required>
                <div id="forgot-password-link" style="text-align: right; margin-top: 5px;">
                    <a href="forgot_password.php" style="font-size: 0.85rem; color: #666;">Forgot Password?</a>
                </div>
            </div>

            <button type="submit" class="btn-primary" id="submit-btn" onclick="prepareSubmit(event)">Start Learning</button>
        </form>

        <!-- GOOGLE OAUTH BUTTON -->
        <?php
        $oauth_plugin_enabled = get_config('auth_oauth2', 'disabled') === '0';
        if (!$oauth_plugin_enabled) {
            $oauth_plugin_enabled = file_exists($CFG->dirroot . '/auth/oauth2/lib.php');
        }

        $google_issuer = false;

        if ($oauth_plugin_enabled && class_exists('\core\oauth2\api')) {
            try {
                $issuers = \core\oauth2\api::get_all_issuers();
                foreach ($issuers as $issuer) {
                    if ($issuer->get('enabled') && stripos($issuer->get('name'), 'google') !== false) {
                        $google_issuer = $issuer;
                        break;
                    }
                }
            } catch (Exception $e) {
            }
        }

        if ($google_issuer) :
            $login_url = new moodle_url('/auth/oauth2/login.php', [
                'id' => $google_issuer->get('id'),
                'sesskey' => sesskey(),
                'wantsurl' => $CFG->wwwroot . '/my/',
            ]);
        ?>
            <div class="divider"><span>OR</span></div>

            <a href="<?php echo $login_url; ?>" class="btn-google">
                <svg width="18" height="18" viewBox="0 0 18 18" xmlns="http://www.w3.org/2000/svg">
                    <path d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844c-.209 1.125-.843 2.078-1.796 2.717v2.258h2.908c1.702-1.567 2.684-3.874 2.684-6.615z" fill="#4285F4" />
                    <path d="M9 18c2.43 0 4.467-.806 5.956-2.18L12.048 13.56c-.806.54-1.836.86-3.048.86-2.344 0-4.328-1.584-5.036-3.716H.957v2.332A8.997 8.997 0 0 0 9 18z" fill="#34A853" />
                    <path d="M3.964 10.71A5.41 5.41 0 0 1 3.682 9c0-.593.102-1.17.282-1.71V4.958H.957A8.996 8.996 0 0 0 0 9c0 1.452.348 2.827.957 4.042l3.007-2.332z" fill="#FBBC05" />
                    <path d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 0 0 .957 4.958L3.964 7.29C4.672 5.157 6.656 3.58 9 3.58z" fill="#EA4335" />
                </svg>
                Sign in with Google
            </a>
        <?php endif; ?>
    </div>
</div>

<!-- JAVASCRIPT LOGIC -->
<script>
    // Initialize Phone Input
    const phoneInput = document.querySelector("#mobile_num_visible");
    const hiddenInput = document.querySelector("#mobile_num_hidden");

    // SETUP: Saudi First, then Egypt
    const iti = window.intlTelInput(phoneInput, {
        preferredCountries: ['sa', 'eg'],
        utilsScript: "https://cdn.jsdelivr.net/npm/intl-tel-input@18.2.1/build/js/utils.js",
        separateDialCode: true,
        allowDropdown: true
    });

    function prepareSubmit(e) {
        const groupPhone = document.getElementById('group-phone');

        // STRICT VALIDATION: Check number if Phone Field is Visible
        if (!groupPhone.classList.contains('hidden')) {
            if (iti.isValidNumber()) {
                // Number is VALID: Store full number and let form submit
                hiddenInput.value = iti.getNumber();
            } else {
                // Number is INVALID or TOO SHORT: Stop Button Click
                e.preventDefault();

                // Show Error Feedback
                alert("Please enter a correct mobile number (incomplete/invalid).");
                phoneInput.focus();
                return false;
            }
        }
        // If Username mode, proceed safely
    }

    function toggleLoginInput(method) {
        const groupPhone = document.getElementById('group-phone');
        const groupUser = document.getElementById('group-user');
        const optPhone = document.getElementById('opt-phone');
        const optUser = document.getElementById('opt-user');
        const phoneField = document.querySelector("#mobile_num_visible");
        const userField = groupUser.querySelector('input');

        if (method === 'phone') {
            groupPhone.classList.remove('hidden');
            groupUser.classList.add('hidden');
            optPhone.classList.add('selected');
            optUser.classList.remove('selected');

            phoneField.setAttribute('required', 'required');
            userField.removeAttribute('required');
        } else {
            groupPhone.classList.add('hidden');
            groupUser.classList.remove('hidden');
            optUser.classList.add('selected');
            optPhone.classList.remove('selected');

            userField.setAttribute('required', 'required');
            phoneField.removeAttribute('required');
        }
    }

    function switchTab(tab) {
        const btnLogin = document.getElementById('btn-login');
        const btnReg = document.getElementById('btn-register');
        const actionInput = document.getElementById('form_action');
        const submitBtn = document.getElementById('submit-btn');
        const loginMethodToggle = document.getElementById('login-method-toggle');

        const groupPhone = document.getElementById('group-phone');
        const groupUser = document.getElementById('group-user');
        const fieldName = document.getElementById('field-name');
        const fieldEmail = document.getElementById('field-email');
        const title = document.getElementById('form-title');
        const subtitle = document.getElementById('form-subtitle');

        const phoneField = document.querySelector("#mobile_num_visible");
        const userField = groupUser.querySelector('input');

        if (tab === 'login') {
            btnLogin.classList.add('active');
            btnReg.classList.remove('active');
            actionInput.value = 'login';
            loginMethodToggle.classList.remove('hidden');
            document.getElementById('forgot-password-link').classList.remove('hidden');

            toggleLoginInput('phone');

            fieldName.classList.add('hidden');
            fieldEmail.classList.add('hidden');

            title.textContent = 'Welcome Back';
            subtitle.textContent = 'Use your username or phone to login.';
            submitBtn.textContent = 'Start Learning';
        } else {
            btnReg.classList.add('active');
            btnLogin.classList.remove('active');
            actionInput.value = 'register';
            loginMethodToggle.classList.add('hidden');
            document.getElementById('forgot-password-link').classList.add('hidden');

            groupPhone.classList.remove('hidden');
            groupUser.classList.add('hidden');

            phoneField.setAttribute('required', 'required');
            userField.removeAttribute('required');

            fieldName.classList.remove('hidden');
            fieldEmail.classList.remove('hidden');

            title.textContent = 'Create Account';
            subtitle.textContent = 'Start your journey.';
            submitBtn.textContent = 'Create Account';
            fieldName.querySelector('input').setAttribute('required', 'required');
        }
    }
</script>

<?php
echo $OUTPUT->footer();
?>