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

/**
 * Quick login and registration page.
 *
 * @package    local_qlogin
 * @copyright  2025 Mohammad Nabil <mohammad@smartlearn.education>
 * @license    https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

// phpcs:disable moodle.Files.RequireLogin.Missing
require_once('../../config.php');
require_once($CFG->libdir . '/authlib.php');
require_once($CFG->dirroot . '/user/lib.php');

$context = context_system::instance();
$PAGE->set_context($context);
$PAGE->set_url(new moodle_url('/local/qlogin/index.php'));
$PAGE->set_pagelayout('login');

// Determine language for the page.
$qloginlang = optional_param('lang', '', PARAM_LANG);
if (empty($qloginlang)) {
    $qloginlang = !empty($SESSION->qlogin_lang) ? $SESSION->qlogin_lang : 'ar';
}
$SESSION->qlogin_lang = $qloginlang;
$isrtl = ($qloginlang === 'ar');

$PAGE->set_title(get_string('pluginname', 'local_qlogin', null, $qloginlang));

// Include the plugin scoped CSS.
$PAGE->requires->css('/local/qlogin/qlogin_styles.css');

if (isloggedin() && !isguestuser()) {
    redirect($CFG->wwwroot . '/my/');
}

$action = optional_param('action', 'login', PARAM_ALPHA);
$errormsg = '';

if ($data = data_submitted()) {
    // Honeypot trap verification.
    $trap = isset($data->username) ? $data->username : '';
    if (!empty($trap)) {
        redirect($CFG->wwwroot, 'Traffic verification failed.', 3);
        die();
    }

    // Process submitted inputs.
    $phone = isset($data->mobile_num) ? clean_param($data->mobile_num, PARAM_NOTAGS) : '';
    $cleanphone = preg_replace('/[^0-9]/', '', $phone);

    $password = isset($data->password) ? $data->password : '';
    $formaction = isset($data->form_action) ? $data->form_action : 'login';

    // Validate inputs based on action.
    $validinput = true;
    if ($formaction === 'login') {
        if (empty($cleanphone) && empty($data->login_username)) {
            $validinput = false;
        }
    } else {
        if (empty($cleanphone)) {
            $validinput = false;
        }
    }

    if (!$validinput || empty($password)) {
        $errormsg = get_string('error_phone_required', 'local_qlogin', null, $qloginlang);
    } else {
        if ($formaction === 'login') {
            // Determine login source (Phone or Username).
            $logininput = '';

            if (isset($data->login_username) && !empty($data->login_username)) {
                $logininput = clean_param($data->login_username, PARAM_RAW);
            } else if (!empty($cleanphone)) {
                $logininput = $cleanphone;
            }

            // Search user record by username.
            $user = $DB->get_record_select(
                'user',
                "username = :u AND deleted = 0 AND suspended = 0",
                ['u' => $logininput]
            );

            if ($user && validate_internal_user_password($user, $password)) {
                complete_user_login($user);
                redirect($CFG->wwwroot . '/my/');
            } else {
                $errormsg = get_string('error_auth_failed', 'local_qlogin', null, $qloginlang);
            }
        } else if ($formaction === 'register') {
            // Check for duplicate account.
            if ($DB->record_exists('user', ['username' => $cleanphone, 'deleted' => 0])) {
                $errormsg = get_string('error_user_exists', 'local_qlogin', null, $qloginlang);
            } else {
                $name = isset($data->fullname) ? clean_param($data->fullname, PARAM_TEXT) : 'Student';
                $email = isset($data->email) && !empty($data->email) ? clean_param($data->email, PARAM_EMAIL) : '';

                if (empty($email)) {
                    $email = $cleanphone . '@users.nomail.com';
                }

                $parts = explode(' ', $name, 2);
                $firstname = $parts[0];
                $lastname = isset($parts[1]) ? $parts[1] : '-';

                $newuser = new stdClass();
                $newuser->username = $cleanphone;
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
                    $userrecord = $DB->get_record('user', ['id' => $newuser->id]);
                    complete_user_login($userrecord);
                    redirect($CFG->wwwroot . '/my/');
                } catch (Exception $e) {
                    $errormsg = 'Error: ' . $e->getMessage();
                }
            }
        }
    }
}

$logourl = $OUTPUT->get_logo_url();
$sitename = format_string($SITE->fullname);

echo $OUTPUT->header();

echo '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/intl-tel-input@18.2.1/build/css/intlTelInput.css">';
echo '<script src="https://cdn.jsdelivr.net/npm/intl-tel-input@18.2.1/build/js/intlTelInput.min.js"></script>';

echo '<div id="qlogin-wrapper">';
echo '<div class="qlogin-card">';

// Language Switcher.
$alignswitch = $isrtl ? 'left' : 'right';
echo '<div class="lang-switch" style="text-align: ' . $alignswitch . '; margin-bottom: 10px;">';
if ($qloginlang === 'ar') {
    echo '<a href="?lang=en" style="text-decoration: none; font-size: 0.9em; color: #666;">English 🇬🇧</a>';
} else {
    echo '<a href="?lang=ar" style="text-decoration: none; font-size: 0.9em; color: #666;">عربي 🇸🇦</a>';
}
echo '</div>';

// Site Logo / Name.
echo '<div class="qlogin-logo">';
if ($logourl) {
    echo '<img src="' . $logourl . '" alt="' . s($sitename) . '">';
} else {
    echo '<div class="site-name">' . s($sitename) . '</div>';
}
echo '</div>';

// Tabs: Login / Register.
echo '<div class="auth-tabs">';
echo '<button class="tab-btn active" onclick="switchTab(\'login\')" id="btn-login">';
echo get_string('login', 'local_qlogin', null, $qloginlang);
echo '</button>';
echo '<button class="tab-btn" onclick="switchTab(\'register\')" id="btn-register">';
echo get_string('register', 'local_qlogin', null, $qloginlang);
echo '</button>';
echo '</div>';

echo '<h2 class="form-title" id="form-title">' . get_string('welcome_back', 'local_qlogin', null, $qloginlang) . '</h2>';
echo '<p class="form-subtitle" id="form-subtitle">' . get_string('access_courses', 'local_qlogin', null, $qloginlang) . '</p>';

if ($errormsg) {
    echo '<div class="alert alert-danger">' . s($errormsg) . '</div>';
}

echo '<form method="post" action="index.php" id="qlogin-form">';
echo '<input type="hidden" name="form_action" id="form_action" value="login">';

// Honeypot field.
echo '<div class="hp-field">';
echo '<label>' . get_string('login_username', 'local_qlogin', null, $qloginlang) . '</label>';
echo '<input type="text" name="username" tabindex="-1" autocomplete="off">';
echo '</div>';

// Login Method Toggle.
echo '<div id="login-method-toggle">';
echo '<label style="margin-bottom:5px; display:block; font-size:0.85rem; color: #444;">';
echo get_string('login_using', 'local_qlogin', null, $qloginlang);
echo '</label>';
echo '<div class="method-switch">';
echo '<label class="method-option selected" id="opt-phone">';
echo '<input type="radio" name="login_method" value="phone" onclick="toggleLoginInput(\'phone\')" checked>';
echo ' ' . get_string('login_phone', 'local_qlogin', null, $qloginlang);
echo '</label>';
echo '<label class="method-option" id="opt-user">';
echo '<input type="radio" name="login_method" value="user" onclick="toggleLoginInput(\'user\')">';
echo ' ' . get_string('login_username', 'local_qlogin', null, $qloginlang);
echo '</label>';
echo '</div>';
echo '</div>';

// Real Phone Input.
$paddingleft = $isrtl ? '10px' : '90px';
$paddingright = $isrtl ? '90px' : '10px';
echo '<div class="form-group" id="group-phone">';
echo '<label>' . get_string('login_phone', 'local_qlogin', null, $qloginlang) . '</label>';
echo '<input type="tel" id="mobile_num_visible" class="form-control" ';
echo 'style="padding-left: ' . $paddingleft . '; padding-right: ' . $paddingright . ';">';
echo '<input type="hidden" name="mobile_num" id="mobile_num_hidden">';
echo '</div>';

// Username Input.
echo '<div class="form-group hidden" id="group-user">';
echo '<label>' . get_string('login_username', 'local_qlogin', null, $qloginlang) . '</label>';
echo '<input type="text" name="login_username" class="form-control" placeholder="e.g. ahmed_student">';
echo '</div>';

// Name and Email (Register Only).
echo '<div class="form-group hidden" id="field-name">';
echo '<label>' . get_string('fullname', 'local_qlogin', null, $qloginlang) . '</label>';
echo '<input type="text" name="fullname" class="form-control" placeholder="Ali Ahmed">';
echo '</div>';

echo '<div class="form-group hidden" id="field-email">';
echo '<label>' . get_string('email', 'local_qlogin', null, $qloginlang) . '</label>';
echo '<input type="email" name="email" class="form-control" placeholder="ali@example.com">';
echo '</div>';

echo '<div class="form-group">';
echo '<label>' . get_string('password', 'local_qlogin', null, $qloginlang) . '</label>';
echo '<input type="password" name="password" class="form-control" placeholder="••••••••" required>';
$alignforgot = $isrtl ? 'left' : 'right';
echo '<div id="forgot-password-link" style="text-align: ' . $alignforgot . '; margin-top: 5px;">';
echo '<a href="forgot_password.php" style="font-size: 0.85rem; color: #666;">';
echo get_string('forgot_password', 'local_qlogin', null, $qloginlang);
echo '</a>';
echo '</div>';
echo '</div>';

echo '<button type="submit" class="btn-primary" id="submit-btn" onclick="prepareSubmit(event)">';
echo get_string('submit_login', 'local_qlogin', null, $qloginlang);
echo '</button>';
echo '</form>';

// Google OAuth Button.
$oauthpluginenabled = get_config('auth_oauth2', 'disabled') === '0';
if (!$oauthpluginenabled) {
    $oauthpluginenabled = file_exists($CFG->dirroot . '/auth/oauth2/lib.php');
}

$googleissuer = false;

if ($oauthpluginenabled && class_exists('\core\oauth2\api')) {
    try {
        $issuers = \core\oauth2\api::get_all_issuers();
        foreach ($issuers as $issuer) {
            if ($issuer->get('enabled') && stripos($issuer->get('name'), 'google') !== false) {
                $googleissuer = $issuer;
                break;
            }
        }
    } catch (Exception $e) {
        // Ignore oauth issuer fetching exceptions.
        unset($e);
    }
}

if ($googleissuer) {
    $loginurl = new moodle_url('/auth/oauth2/login.php', [
        'id' => $googleissuer->get('id'),
        'sesskey' => sesskey(),
        'wantsurl' => $CFG->wwwroot . '/my/',
    ]);

    echo '<div class="divider"><span>' . get_string('or_text', 'local_qlogin', null, $qloginlang) . '</span></div>';
    echo '<a href="' . $loginurl . '" class="btn-google">';
    echo '<svg width="18" height="18" viewBox="0 0 18 18" xmlns="http://www.w3.org/2000/svg">';
    echo '<path d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844c-.209 1.125-.843" fill="#4285F4"/>';
    echo '<path d="M9 18c2.43 0 4.467-.806 5.956-2.18L12.048 13.56c-.806.54-1.836.86-3.048.86" fill="#34A853"/>';
    echo '<path d="M3.964 10.71A5.41 5.41 0 0 1 3.682 9c0-.593.102-1.17.282-1.71V4.958H.957" fill="#FBBC05"/>';
    echo '<path d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997" fill="#EA4335"/>';
    echo '</svg>';
    echo ' ' . get_string('signin_google', 'local_qlogin', null, $qloginlang);
    echo '</a>';
}

echo '</div>';
echo '</div>';

echo '<script>';
echo 'const phoneInput = document.querySelector("#mobile_num_visible");';
echo 'const hiddenInput = document.querySelector("#mobile_num_hidden");';
echo 'const iti = window.intlTelInput(phoneInput, {';
echo '    preferredCountries: ["sa", "eg"],';
echo '    utilsScript: "https://cdn.jsdelivr.net/npm/intl-tel-input@18.2.1/build/js/utils.js",';
echo '    separateDialCode: true,';
echo '    allowDropdown: true';
echo '});';
echo 'function prepareSubmit(e) {';
echo '    const groupPhone = document.getElementById("group-phone");';
echo '    if (!groupPhone.classList.contains("hidden")) {';
echo '        if (iti.isValidNumber()) {';
echo '            hiddenInput.value = iti.getNumber();';
echo '        } else {';
echo '            e.preventDefault();';
echo '            alert("' . get_string('invalid_phone_msg', 'local_qlogin', null, $qloginlang) . '");';
echo '            phoneInput.focus();';
echo '            return false;';
echo '        }';
echo '    }';
echo '}';
echo 'function toggleLoginInput(method) {';
echo '    const groupPhone = document.getElementById("group-phone");';
echo '    const groupUser = document.getElementById("group-user");';
echo '    const optPhone = document.getElementById("opt-phone");';
echo '    const optUser = document.getElementById("opt-user");';
echo '    const phoneField = document.querySelector("#mobile_num_visible");';
echo '    const userField = groupUser.querySelector("input");';
echo '    if (method === "phone") {';
echo '        groupPhone.classList.remove("hidden");';
echo '        groupUser.classList.add("hidden");';
echo '        optPhone.classList.add("selected");';
echo '        optUser.classList.remove("selected");';
echo '        phoneField.setAttribute("required", "required");';
echo '        userField.removeAttribute("required");';
echo '    } else {';
echo '        groupPhone.classList.add("hidden");';
echo '        groupUser.classList.remove("hidden");';
echo '        optUser.classList.add("selected");';
echo '        optPhone.classList.remove("selected");';
echo '        userField.setAttribute("required", "required");';
echo '        phoneField.removeAttribute("required");';
echo '    }';
echo '}';
echo 'function switchTab(tab) {';
echo '    const btnLogin = document.getElementById("btn-login");';
echo '    const btnReg = document.getElementById("btn-register");';
echo '    const actionInput = document.getElementById("form_action");';
echo '    const submitBtn = document.getElementById("submit-btn");';
echo '    const loginMethodToggle = document.getElementById("login-method-toggle");';
echo '    const groupPhone = document.getElementById("group-phone");';
echo '    const groupUser = document.getElementById("group-user");';
echo '    const fieldName = document.getElementById("field-name");';
echo '    const fieldEmail = document.getElementById("field-email");';
echo '    const title = document.getElementById("form-title");';
echo '    const subtitle = document.getElementById("form-subtitle");';
echo '    const phoneField = document.querySelector("#mobile_num_visible");';
echo '    const userField = groupUser.querySelector("input");';
echo '    if (tab === "login") {';
echo '        btnLogin.classList.add("active");';
echo '        btnReg.classList.remove("active");';
echo '        actionInput.value = "login";';
echo '        loginMethodToggle.classList.remove("hidden");';
echo '        document.getElementById("forgot-password-link").classList.remove("hidden");';
echo '        toggleLoginInput("phone");';
echo '        fieldName.classList.add("hidden");';
echo '        fieldEmail.classList.add("hidden");';
echo '        title.textContent = "' . get_string('welcome_back', 'local_qlogin', null, $qloginlang) . '";';
echo '        subtitle.textContent = "' . get_string('use_username_or_phone', 'local_qlogin', null, $qloginlang) . '";';
echo '        submitBtn.textContent = "' . get_string('submit_login', 'local_qlogin', null, $qloginlang) . '";';
echo '    } else {';
echo '        btnReg.classList.add("active");';
echo '        btnLogin.classList.remove("active");';
echo '        actionInput.value = "register";';
echo '        loginMethodToggle.classList.add("hidden");';
echo '        document.getElementById("forgot-password-link").classList.add("hidden");';
echo '        groupPhone.classList.remove("hidden");';
echo '        groupUser.classList.add("hidden");';
echo '        phoneField.setAttribute("required", "required");';
echo '        userField.removeAttribute("required");';
echo '        fieldName.classList.remove("hidden");';
echo '        fieldEmail.classList.remove("hidden");';
echo '        title.textContent = "' . get_string('create_account_title', 'local_qlogin', null, $qloginlang) . '";';
echo '        subtitle.textContent = "' . get_string('start_journey', 'local_qlogin', null, $qloginlang) . '";';
echo '        submitBtn.textContent = "' . get_string('submit_register', 'local_qlogin', null, $qloginlang) . '";';
echo '        fieldName.querySelector("input").setAttribute("required", "required");';
echo '    }';
echo '}';
echo '</script>';

echo $OUTPUT->footer();
