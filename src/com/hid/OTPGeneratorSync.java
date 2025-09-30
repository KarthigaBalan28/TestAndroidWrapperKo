package com.hid;

import com.hidglobal.ia.service.beans.Parameter;
import com.hidglobal.ia.service.exception.AuthenticationException;
import com.hidglobal.ia.service.exception.FingerprintAuthenticationRequiredException;
import com.hidglobal.ia.service.exception.FingerprintNotEnrolledException;
import com.hidglobal.ia.service.exception.InternalException;
import com.hidglobal.ia.service.exception.InvalidParameterException;
import com.hidglobal.ia.service.exception.InvalidPasswordException;
import com.hidglobal.ia.service.exception.LostCredentialsException;
import com.hidglobal.ia.service.exception.PasswordExpiredException;
import com.hidglobal.ia.service.exception.PasswordRequiredException;
import com.hidglobal.ia.service.exception.UnsupportedDeviceException;
import com.hidglobal.ia.service.manager.SDKConstants;
import com.hidglobal.ia.service.otp.OTPGenerator;
import com.hidglobal.ia.service.otp.SyncOTPGenerator;
import com.hidglobal.ia.service.protectionpolicy.ProtectionPolicy;
import com.hidglobal.ia.service.transaction.Container;
import com.hidglobal.ia.service.transaction.Key;
import com.konylabs.vm.Function;
import android.content.Context;
import android.util.Log;
import androidx.fragment.app.FragmentActivity;
@SuppressWarnings({"java:S3776"})
public class OTPGeneratorSync implements Runnable {
	protected static final String LOG_TAG = ApproveSDKConstants.HID_LOG_TAG;
	private FragmentActivity activity;
	private String password;
	private boolean isBiometricEnabled;
	private Function otpSuccessCallback;
	private Function otpFailureCallback;
	private FingerprintHandler.BiometricEventListener biometricEventListener;
	private String otpLabel;
	private Container container;

	public OTPGeneratorSync(FragmentActivity activity, String password, boolean isBiometricEnabled,
			Function otpSuccessCallback, Function otpFailureCallback, Container container, String otpLabel)
			throws InternalException {
		this.activity = activity;
		this.password = password;
		this.isBiometricEnabled = isBiometricEnabled;
		this.otpSuccessCallback = otpSuccessCallback;
		this.otpFailureCallback = otpFailureCallback;
		this.container = container;
		this.otpLabel = otpLabel;
	}

	public void setBiometricEventListener(FingerprintHandler.BiometricEventListener biometricEventListener) {
		this.biometricEventListener = biometricEventListener;
	}

	@Override
	public void run() {
		char[] nextOtp;
		try {
			ProtectionPolicy otpKeyPolicy = null;
			OTPGenerator otpGenerator = null;
			Parameter[] filter;
			filter = new Parameter[]{new Parameter(SDKConstants.KEY_PROPERTY_USAGE, SDKConstants.KEY_PROPERTY_USAGE_OTP)};
			
			Key[] keys = container.findKeys(filter);
			
			Key otpKey = keys[0];
			
			Log.d(LOG_TAG, "HID:generateOTP Key Length is " + keys.length);
			if (keys == null || keys.length == 0) {
				Log.d(LOG_TAG, "HID:generateOTP - No OTP key found");
				otpFailureCallback("No OTP key found", "No OTP key found with label: " + otpLabel, otpFailureCallback);
				return;
			}
			if (keys.length > 1) {
				Log.d(LOG_TAG, "HID:generateOTP More than one OTP key found");
				for (Key key : keys) {
					Log.d(LOG_TAG, "HID:generateOTP - Key: " + key);
					Log.d(LOG_TAG, "HID:generateOTP - Key found with label: " + new String(key.getProperty(SDKConstants.KEY_PROPERTY_LABEL)));
					String keyLabel = new String(key.getProperty(SDKConstants.KEY_PROPERTY_LABEL));
					Log.d(LOG_TAG, "HID:generateOTP - Key label: " + keyLabel);

					if (keyLabel != null && keyLabel.contains(otpLabel)) {
					    otpKey = key;
					    Log.d(LOG_TAG, "HID:generateOTP - Using OTP key with label: " + otpLabel);
					    break;
					}

				}
			}
			// Get protection policy of the OTP key
			otpKeyPolicy = otpKey.getProtectionPolicy();
			// Algorithm will indicate the otp algorithm for which the key is registered : HOTP / TOTP / OCRA
            String algorithm = otpKey.getAlgorithm();
            Log.d(LOG_TAG, "HID:generateOTP - OTP key Algorithm: " + algorithm);
            // the label the key is registered with.
            char[] label = otpKey.getProperty(SDKConstants.KEY_PROPERTY_LABEL);
            Log.d(LOG_TAG, "HID:generateOTP - OTP key Label: " + new String(label));
            
            //Lock Policy Type
            String lockPolicyType = otpKeyPolicy.getLockPolicy().getType();
            Log.d(LOG_TAG, "HID:generateOTP - OTP key Lock Policy Type: " + lockPolicyType);

			otpGenerator = otpKey.getDefaultOTPGenerator();
			Log.d(LOG_TAG, "HID:generateOTP - OTP key has been selected.");
			if (isBiometricEnabled) {
				BiometricAuthService bioAuthService = new BiometricAuthService();
				bioAuthService.setBiometricPrompt(activity, "", container.getProtectionPolicy(),
						biometricEventListener);
				nextOtp = ((SyncOTPGenerator) otpGenerator).getOTP(null);
				String otp = String.valueOf(nextOtp);
				Log.d(LOG_TAG, "HID:generateOTP - Finished otp generation, OTP: " + otp);
				Object[] params = new Object[1];
				params[0] = otp;
				otpSuccessCallback.execute(params);
			} else {
				nextOtp = ((SyncOTPGenerator) otpGenerator).getOTP(password.toCharArray());
				String otp = String.valueOf(nextOtp);
				Log.d(LOG_TAG, "HID:generateOTP - Finished otp generation, OTP: " + otp);
				Object[] params = new Object[1];
				params[0] = otp;
				otpSuccessCallback.execute(params);
			}
		} catch (UnsupportedDeviceException e) {
			otpFailureCallback("UnsupportedDeviceException", e.getMessage(), otpFailureCallback);
			Log.d(LOG_TAG, "HID:generateOTP - UnsupportedDeviceException : " + e.getStackTrace());
		} catch (LostCredentialsException e) {
			otpFailureCallback("LostCredentialsException", e.getMessage(), otpFailureCallback);
			Log.d(LOG_TAG, "HID:generateOTP - LostCredentialsException : " + e.getStackTrace());
		} catch (InternalException e) {
			otpFailureCallback("InternalException", e.getMessage(), otpFailureCallback);
			Log.d(LOG_TAG, "HID:generateOTP - InternalException : " + e.getStackTrace());
		} catch (InvalidParameterException e) {
			otpFailureCallback("InvalidParameterException", e.getMessage(), otpFailureCallback);
			Log.d(LOG_TAG, "HID:generateOTP - InvalidParameterException : " + e.getStackTrace());
		} catch (AuthenticationException e) {
			otpFailureCallback("AuthenticationException", e.getMessage(), otpFailureCallback);
			Log.d(LOG_TAG, "HID:generateOTP - AuthenticationException : " + e.getStackTrace());
		} catch (PasswordExpiredException e) {
			otpFailureCallback("PasswordExpiredException", e.getMessage(), otpFailureCallback);
			Log.d(LOG_TAG, "HID:generateOTP - PasswordExpiredException : " + e.getStackTrace());
		} catch (InvalidPasswordException e) {
			otpFailureCallback("InvalidPasswordException", e.getMessage(), otpFailureCallback);
			Log.d(LOG_TAG, "HID:generateOTP - InvalidPasswordException : " + e.getStackTrace());
		} catch (FingerprintAuthenticationRequiredException e) {
			otpFailureCallback("FingerprintAuthenticationRequiredException", e.getMessage(), otpFailureCallback);
			Log.d(LOG_TAG, "HID:generateOTP - FingerprintAuthenticationRequiredException : " + e.getStackTrace());
		} catch (FingerprintNotEnrolledException e) {
			otpFailureCallback("FingerprintNotEnrolledException", e.getMessage(), otpFailureCallback);
			Log.d(LOG_TAG, "HID:generateOTP - FingerprintNotEnrolledException : " + e.getStackTrace());
		} catch (PasswordRequiredException e) {
			otpFailureCallback("PasswordRequiredException", e.getMessage(), otpFailureCallback);
			Log.d(LOG_TAG, "HID:generateOTP - PasswordRequiredException : " + e.getStackTrace());
		} catch (Exception e) {
			otpFailureCallback("Exception", e.getMessage(), otpFailureCallback);
			Log.d(LOG_TAG, "HID:generateOTP - Unhandled Exception : " + e.getStackTrace());
			e.printStackTrace();
		}
	}

	private void otpFailureCallback(String exceptionType, String message, Function callback) {
		Object[] params = new Object[2];
		params[0] = exceptionType;
		params[1] = message;
		try {
			callback.execute(params);
		} catch (Exception e) {
			Log.d(LOG_TAG, "HID:generateOTP - Unhandled Exception : " + e.getStackTrace());
			e.printStackTrace();
		}
	}
}
