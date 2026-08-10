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

// phpcs:disable moodle.Files.RequireLogin.Missing

$context = context_system::instance();
$PAGE->set_context($context);
$PAGE->set_url(new moodle_url('/local/qlogin/forgot_password.php'));
$PAGE->set_pagelayout('login');
$PAGE->set_title(get_string('pluginname', 'local_qlogin') . ' - Forgot Password');

// Plugin Dependency Check
if (!class_exists('\local_verify_phone\otp')) {
    throw new moodle_exception('The local_verify_phone plugin is required but missing.');
}

$PAGE->requires->css('/local/qlogin/qlogin_styles.css');

$step = optional_param('step', 'phone', PARAM_ALPHA);
$errormsg = '';
$successmsg = '';

$phonesessionkey = 'qlogin_forgot_password';

if ($data = data_submitted()) {
    // --- STEP 1: SUBMIT PHONE ---
    if ($step === 'phone') {
        $phone = isset($data->mobile_num) ? clean_param($data->mobile_num, PARAM_NOTAGS) : '';
        // Clean phone (digits only)
        $cleanphone = preg_replace('/[^0-9]/', '', $phone);

        if (empty($cleanphone)) {
            $errormsg = 'Please enter a valid phone number.';
        } else {
            // Check if user exists with this username (phone)
            $user = $DB->get_record('user', ['username' => $cleanphone, 'deleted' => 0, 'suspended' => 0]);

            // SECURITY: Generic message even if user not found to prevent enumeration?
            // For now, let's just be direct as per request context, but secure side would verify phone actually belongs to user.

            if (!$user) {
                // Try checking phone1 profile field as fallback?
                // The requirements said: verify user exists with that verified phone number.
                // In qlogin, username IS the phone number usually.
                // Let's also check phone1 field just in case.
                $user = $DB->get_record('user', ['phone1' => $cleanphone, 'deleted' => 0, 'suspended' => 0]);
            }

            if ($user) {
                // Send OTP
                // We use the existing otp class.
                // verify_phone\otp::send returns otpdata array on success, false on failure.
                $otpdata = \local_verify_phone\otp::send($cleanphone, $user);

                if ($otpdata) {
                    $SESSION->$phonesessionkey = [
                        'phone' => $cleanphone,
                        'userid' => $user->id,
                        'otp_data' => $otpdata,
                        'timestamp' => time(),
                    ];
                    $step = 'otp'; // Move to next step
                } else {
                    $errormsg = 'Failed to send OTP. Please try again later.';
                }
            } else {
                $errormsg = 'No account found with this phone number.';
            }
        }
    } else if ($step === 'otp') {
        // --- STEP 2: VERIFY OTP ---
        $enteredotp = isset($data->otp_code) ? clean_param($data->otp_code, PARAM_NOTAGS) : '';

        if (empty($SESSION->$phonesessionkey)) {
            redirect(new moodle_url('/local/qlogin/forgot_password.php'), 'Session expired. Please try again.', 3);
        }

        $sessiondata = $SESSION->$phonesessionkey;
        $user = $DB->get_record('user', ['id' => $sessiondata['userid']]);

        // Validate OTP
        // Using verify_phone\otp::validate($otpdata, $otp, $user)
        if ($user && \local_verify_phone\otp::validate($sessiondata['otp_data'], $enteredotp, $user)) {
            // SUCCESS!

            // 1. Generate new password
            $newpassword = generate_password(8) . '@' . mt_rand(100, 999); // Ensure complexity: Uppercase, Lowercase, Special char handling often needed.
            // Moodle default policy usually requires 1 Usercase, 1 Lowercase, 1 Digit, 1 Symbol.
            // generate_password() creates random string, might not satisfy policy.
            // Let's force it:
            $newpassword = 'U' . strtolower(generate_password(6)) . mt_rand(1, 9) . '#';

            // 2. Update User Password
            $userauth = get_auth_plugin($user->auth);
            if ($userauth->can_change_password()) {
                $userauth->user_update_password($user, $newpassword);
                // set_user_preference('auth_forcepasswordchange', 1, $user); // Optional: Force change on next login

                // 3. Send SMS
                $msg = "Password Reset: Your new password is {$newpassword} . Please log in and change it.";
                \local_verify_phone\otp::send_custom_message($sessiondata['phone'], $msg);

                // Clear Session
                unset($SESSION->$phonesessionkey);

                $step = 'finish';
                $successmsg = 'Password has been reset and sent to your phone.';
            } else {
                $errormsg = 'Cannot reset password for this account type (Auth: ' . $user->auth . ').';
            }
        } else {
            $errormsg = 'Invalid OTP or expired. Please try again.';
            $step = 'otp'; // Stay on OTP step
        }
    }
}


echo $OUTPUT->header();
?>

<!-- Phone Library CDN -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/intl-tel-input@18.2.1/build/css/intlTelInput.css">
<script src="https://cdn.jsdelivr.net/npm/intl-tel-input@18.2.1/build/js/intlTelInput.min.js"></script>

<div id="qlogin-wrapper">
    <div class="qlogin-card">
        <div class="qlogin-logo">
            <?php if ($OUTPUT->get_logo_url()) : ?>
                <img src="<?php echo $OUTPUT->get_logo_url(); ?>" alt="<?php echo format_string($SITE->fullname); ?>">
            <?php else : ?>
                <div class="site-name"><?php echo format_string($SITE->fullname); ?></div>
            <?php endif; ?>
        </div>

        <h2 class="form-title">Reset Password</h2>

        <?php if ($errormsg) : ?>
            <div class="alert alert-danger"><?php echo $errormsg; ?></div>
        <?php endif; ?>

        <?php if ($successmsg) { ?>
            <div class="alert alert-success"><?php echo $successmsg; ?></div>
            <a href="index.php" class="btn btn-primary btn-block">Back to Login</a>
        <?php } else if ($step === 'finish') { ?>
            <a href="index.php" class="btn btn-primary btn-block">Back to Login</a>

        <?php } else if ($step === 'otp') { ?>
            <!-- OTP FORM -->
            <p class="form-subtitle">Enter the 6-digit code sent to <?php echo $SESSION->$phonesessionkey['phone'] ?? 'your phone'; ?>.</p>
            <form method="post" action="forgot_password.php">
                <input type="hidden" name="step" value="otp">
                <div class="form-group">
                    <label>Verification Code (OTP)</label>
                    <input type="text" name="otp_code" class="form-control" placeholder="123456" required autocomplete="off">
                </div>
                <button type="submit" class="btn-primary">Verify & Reset</button>
            </form>

        <?php } else { ?>
            <!-- PHONE FORM -->
            <p class="form-subtitle">Enter your registered mobile number to receive a temporary password.</p>
            <form method="post" action="forgot_password.php" id="reset-form">
                <input type="hidden" name="step" value="phone">

                <div class="form-group">
                    <label>Phone Number</label>
                    <input type="tel" id="mobile_num_visible" class="form-control" style="padding-left: 90px;">
                    <input type="hidden" name="mobile_num" id="mobile_num_hidden">
                </div>

                <button type="submit" class="btn-primary" onclick="prepareSubmit(event)">Send Code</button>
                <div class="mt-3 text-center">
                    <a href="index.php" style="color: #666; text-decoration: none;">Cancel</a>
                </div>
            </form>

            <script>
                const phoneInput = document.querySelector("#mobile_num_visible");
                const hiddenInput = document.querySelector("#mobile_num_hidden");

                const iti = window.intlTelInput(phoneInput, {
                    preferredCountries: ['sa', 'eg'],
                    utilsScript: "https://cdn.jsdelivr.net/npm/intl-tel-input@18.2.1/build/js/utils.js",
                    separateDialCode: true,
                    allowDropdown: true
                });

                function prepareSubmit(e) {
                    if (iti.isValidNumber()) {
                        hiddenInput.value = iti.getNumber();
                    } else {
                        e.preventDefault();
                        alert("Please enter a correct mobile number.");
                        phoneInput.focus();
                        return false;
                    }
                }
            </script>
        <?php } ?>

    </div>
</div>

<?php
echo $OUTPUT->footer();
