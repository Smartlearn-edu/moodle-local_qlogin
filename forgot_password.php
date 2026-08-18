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
 * Password recovery page via phone OTP.
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
$PAGE->set_url(new moodle_url('/local/qlogin/forgot_password.php'));
$PAGE->set_pagelayout('login');
$PAGE->set_title(get_string('pluginname', 'local_qlogin') . ' - ' . get_string('forgot_password', 'local_qlogin'));

// Plugin dependency check.
if (!class_exists('\local_verify_phone\otp')) {
    throw new moodle_exception('The local_verify_phone plugin is required but missing.');
}

$PAGE->requires->css('/local/qlogin/qlogin_styles.css');

$step = optional_param('step', 'phone', PARAM_ALPHA);
$errormsg = '';
$successmsg = '';

$phonesessionkey = 'qlogin_forgot_password';

if ($data = data_submitted()) {
    // Step 1: Submit phone number.
    if ($step === 'phone') {
        $phone = isset($data->mobile_num) ? clean_param($data->mobile_num, PARAM_NOTAGS) : '';
        $cleanphone = preg_replace('/[^0-9]/', '', $phone);

        if (empty($cleanphone)) {
            $errormsg = 'Please enter a valid phone number.';
        } else {
            // Check if user exists with this username (phone).
            $user = $DB->get_record('user', ['username' => $cleanphone, 'deleted' => 0, 'suspended' => 0]);

            if (!$user) {
                // Fallback check on phone1 field.
                $user = $DB->get_record('user', ['phone1' => $cleanphone, 'deleted' => 0, 'suspended' => 0]);
            }

            if ($user) {
                // Send OTP.
                $otpdata = \local_verify_phone\otp::send($cleanphone, $user);

                if ($otpdata) {
                    $SESSION->$phonesessionkey = [
                        'phone' => $cleanphone,
                        'userid' => $user->id,
                        'otp_data' => $otpdata,
                        'timestamp' => time(),
                    ];
                    $step = 'otp';
                } else {
                    $errormsg = 'Failed to send OTP. Please try again later.';
                }
            } else {
                $errormsg = 'No account found with this phone number.';
            }
        }
    } else if ($step === 'otp') {
        // Step 2: Verify OTP.
        $enteredotp = isset($data->otp_code) ? clean_param($data->otp_code, PARAM_NOTAGS) : '';

        if (empty($SESSION->$phonesessionkey)) {
            redirect(new moodle_url('/local/qlogin/forgot_password.php'), 'Session expired. Please try again.', 3);
        }

        $sessiondata = $SESSION->$phonesessionkey;
        $user = $DB->get_record('user', ['id' => $sessiondata['userid']]);

        // Validate OTP.
        if ($user && \local_verify_phone\otp::validate($sessiondata['otp_data'], $enteredotp, $user)) {
            // Generate new password meeting complexity requirements.
            $newpassword = 'U' . strtolower(generate_password(6)) . mt_rand(1, 9) . '#';

            // Update user password.
            $userauth = get_auth_plugin($user->auth);
            if ($userauth->can_change_password()) {
                $userauth->user_update_password($user, $newpassword);

                // Send SMS notification.
                $msg = "Password Reset: Your new password is {$newpassword} . Please log in and change it.";
                \local_verify_phone\otp::send_custom_message($sessiondata['phone'], $msg);

                // Clear session.
                unset($SESSION->$phonesessionkey);

                $step = 'finish';
                $successmsg = 'Password has been reset and sent to your phone.';
            } else {
                $errormsg = 'Cannot reset password for this account type (Auth: ' . $user->auth . ').';
            }
        } else {
            $errormsg = 'Invalid OTP or expired. Please try again.';
            $step = 'otp';
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

echo '<div class="qlogin-logo">';
if ($logourl) {
    echo '<img src="' . $logourl . '" alt="' . s($sitename) . '">';
} else {
    echo '<div class="site-name">' . s($sitename) . '</div>';
}
echo '</div>';

echo '<h2 class="form-title">' . get_string('forgot_password', 'local_qlogin') . '</h2>';

if ($errormsg) {
    echo '<div class="alert alert-danger">' . s($errormsg) . '</div>';
}

if ($successmsg) {
    echo '<div class="alert alert-success">' . s($successmsg) . '</div>';
    echo '<a href="index.php" class="btn btn-primary btn-block">' . get_string('login', 'local_qlogin') . '</a>';
} else if ($step === 'finish') {
    echo '<a href="index.php" class="btn btn-primary btn-block">' . get_string('login', 'local_qlogin') . '</a>';
} else if ($step === 'otp') {
    $targetphone = isset($SESSION->$phonesessionkey['phone']) ? $SESSION->$phonesessionkey['phone'] : '';
    echo '<p class="form-subtitle">Enter the 6-digit code sent to ' . s($targetphone) . '.</p>';
    echo '<form method="post" action="forgot_password.php">';
    echo '<input type="hidden" name="step" value="otp">';
    echo '<div class="form-group">';
    echo '<label>Verification Code (OTP)</label>';
    echo '<input type="text" name="otp_code" class="form-control" placeholder="123456" required autocomplete="off">';
    echo '</div>';
    echo '<button type="submit" class="btn-primary">Verify & Reset</button>';
    echo '</form>';
} else {
    echo '<p class="form-subtitle">Enter your registered mobile number to receive a temporary password.</p>';
    echo '<form method="post" action="forgot_password.php" id="reset-form">';
    echo '<input type="hidden" name="step" value="phone">';
    echo '<div class="form-group">';
    echo '<label>' . get_string('phone', 'local_qlogin') . '</label>';
    echo '<input type="tel" id="mobile_num_visible" class="form-control" style="padding-left: 90px;">';
    echo '<input type="hidden" name="mobile_num" id="mobile_num_hidden">';
    echo '</div>';
    echo '<button type="submit" class="btn-primary" onclick="prepareSubmit(event)">Send Code</button>';
    echo '<div class="mt-3 text-center">';
    echo '<a href="index.php" style="color: #666; text-decoration: none;">Cancel</a>';
    echo '</div>';
    echo '</form>';

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
    echo '    if (iti.isValidNumber()) {';
    echo '        hiddenInput.value = iti.getNumber();';
    echo '    } else {';
    echo '        e.preventDefault();';
    echo '        alert("' . get_string('invalid_phone_msg', 'local_qlogin') . '");';
    echo '        phoneInput.focus();';
    echo '        return false;';
    echo '    }';
    echo '}';
    echo '</script>';
}

echo '</div>';
echo '</div>';

echo $OUTPUT->footer();
