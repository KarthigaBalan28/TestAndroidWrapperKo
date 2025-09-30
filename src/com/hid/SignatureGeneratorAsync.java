package com.hid;

import java.util.Arrays;

import com.hidglobal.ia.service.beans.Parameter;
import com.hidglobal.ia.service.exception.AuthenticationException;
import com.hidglobal.ia.service.exception.FingerprintAuthenticationRequiredException;
import com.hidglobal.ia.service.exception.FingerprintNotEnrolledException;
import com.hidglobal.ia.service.exception.InternalException;
import com.hidglobal.ia.service.exception.InvalidChallengeException;
import com.hidglobal.ia.service.exception.InvalidParameterException;
import com.hidglobal.ia.service.exception.InvalidPasswordException;
import com.hidglobal.ia.service.exception.LostCredentialsException;
import com.hidglobal.ia.service.exception.PasswordExpiredException;
import com.hidglobal.ia.service.exception.PasswordRequiredException;
import com.hidglobal.ia.service.exception.UnsupportedDeviceException;
import com.hidglobal.ia.service.manager.SDKConstants;
import com.hidglobal.ia.service.otp.AsyncOTPGenerator;
import com.hidglobal.ia.service.otp.parameters.InputOCRAParameters;
import com.hidglobal.ia.service.protectionpolicy.ProtectionPolicy;
import com.hidglobal.ia.service.transaction.Container;
import com.hidglobal.ia.service.transaction.Key;
import com.konylabs.vm.Function;

import android.content.Context;
import android.util.Log;
import androidx.fragment.app.FragmentActivity;
@SuppressWarnings({"java:S1068", "java:S107", "java:S3776", "java:S1172",
 "java:S4143","java:S1602","java:S1144"})
public class SignatureGeneratorAsync implements Runnable {
	private String inputString;
	private Container container;
	private Context appContext;
	private boolean isBioEnabled;
	private FragmentActivity activity;
	private Function pwdPromptCB;
	private Function signTransactionSuccessCallback;
	private Function signTransactionFailureCallback;
	private WaitNotifyMonitor monitor;
	private String otpLabel;
	private static final String LOG_TAG = ApproveSDKConstants.HID_LOG_TAG;
	private static final String MSG_OTP = "HID:signTransaction OTP is ";
	private static final String MSG_INVALID_PARAM = "HID:signTransaction InvalidParameterException";
	private static final String MSG_LOST_CREDENTIALS = "HID:signTransaction LostCredentialsException";
	private static final String MSG_INTERNAL = "HID:signTransaction InternalException";
	private static final String MSG_AUTH_EXCEPTION = "HID:signTransaction AuthenticationException";
	private static final String MSG_UNSUPPORTED_DEVICE = "HID:signTransaction UnsupportedDeviceException";
	private static final String MSG_FP_AUTH_REQUIRED = "HID:signTransaction FingerprintAuthenticationRequiredException";
	private static final String MSG_FP_NOT_ENROLLED = "HID:signTransaction FingerprintNotEnrolledException";
	private static final String MSG_PWD_REQUIRED = "HID:signTransaction PasswordRequiredException";
	private static final String MSG_PWD_EXPIRED = "HID:signTransaction PasswordExpiredException";
	private static final String MSG_GENERIC_EXCEPTION = "HID:signTransaction Exception";
	private static final String INVALID_PARAMETER_EXCEPTION = "InvalidParameterException";
	private static final String LOST_CREDENTIALS_EXCEPTION = "LostCredentialsException";
	private static final String INTERNAL_EXCEPTION = "InternalException";
	private static final String AUTHENTICATION_EXCEPTION = "AuthenticationException";
	private static final String UNSUPPORTED_DEVICE_EXCEPTION = "UnsupportedDeviceException";
	private static final String FINGERPRINT_AUTHENTICATION_REQUIRED_EXCEPTION = "FingerprintAuthenticationRequiredException";
	private static final String FINGERPRINT_NOT_ENROLLED_EXCEPTION = "FingerprintNotEnrolledException";

	public SignatureGeneratorAsync(String inputString, Container container, boolean isBioEnabled, Function pwdPrompCB,
			Function signTransactionSuccessCallback, Function signTransactionFailureCallback, Context appContext, FragmentActivity activity,
			WaitNotifyMonitor monitor, String otpLabel) {
		this.inputString = inputString;
		this.container = container;
		this.isBioEnabled = isBioEnabled;
		this.activity = activity;
		this.pwdPromptCB = pwdPrompCB;
		this.signTransactionSuccessCallback = signTransactionSuccessCallback;
		this.signTransactionFailureCallback = signTransactionFailureCallback;
		this.monitor = monitor;
		this.otpLabel = otpLabel;
	}

	public void run() {
		Parameter[] filter = new Parameter[]{new Parameter(SDKConstants.KEY_PROPERTY_USAGE, SDKConstants.KEY_PROPERTY_USAGE_OTP)};
		try {
			Key[] keys = container.findKeys(filter);
			if (keys == null || keys.length == 0) {
				Log.d(LOG_TAG, "HID:signTransaction - No OTP key found with label: " + otpLabel);
				signTransactionFailureCallback.execute(new Object[] {"No OTP key found", "No OTP key found with label: " + otpLabel});
				return;
			}
			
			Key otpKey = keys[0];
			Log.d(LOG_TAG, "HID:signTransaction - OTP key found with label: " + new String(otpKey.getProperty(SDKConstants.KEY_PROPERTY_LABEL)));
			
			if (keys.length > 1) {
				Log.d(LOG_TAG, "HID:signTransaction - Multiple OTP keys found");
				for (Key key : keys) {
					Log.d(LOG_TAG, "HID:signTransaction - Key: " + key);
					Log.d(LOG_TAG, "HID:signTransaction - Key found with label: " + new String(key.getProperty(SDKConstants.KEY_PROPERTY_LABEL)));
					String keyLabel = new String(key.getProperty(SDKConstants.KEY_PROPERTY_LABEL));
					Log.d(LOG_TAG, "HID:signTransaction - Key label: " + keyLabel);

					if (keyLabel != null && keyLabel.contains(otpLabel)) {
					    otpKey = key;
					    Log.d(LOG_TAG, "HID:signTransaction - Using OTP key with label: " + otpLabel);
					    break;
					}

				}
			}
			
			// Algorithm will indicate the opt algorithm for which the key is registered : HOTP / TOTP / OCRA
            String algorithm = otpKey.getAlgorithm();
            Log.d(LOG_TAG, "HID:signTransaction - OTP key Algorithm: " + algorithm);
            // the label the key is registered with.
            char[] label = otpKey.getProperty(SDKConstants.KEY_PROPERTY_LABEL);
            Log.d(LOG_TAG, "HID:signTransaction - OTP key Label: " + new String(label));
            
          // Get protection policy of the OTP key
            ProtectionPolicy otpKeyPolicy = otpKey.getProtectionPolicy();
          //Lock Policy Type
            String lockPolicyType = otpKeyPolicy.getLockPolicy().getType();
            Log.d(LOG_TAG, "HID:signTransaction - OTP key Lock Policy Type: " + lockPolicyType);
			
			AsyncOTPGenerator asyncOTPGenerator = (AsyncOTPGenerator) otpKey.getDefaultOTPGenerator();
			String[] details = inputString.split(ApproveSDKConstants.HID_TS_VALUES_SEPERATOR);
			Log.d(LOG_TAG,"HID:signTransaction "+ Arrays.toString(details));
			int len = details.length;
			char[][] tsDetailsArray = new char[len][];
			for (int i = 0; i < len; i++) {
				tsDetailsArray[i] = new char[details[i].length()];
				tsDetailsArray[i] = details[i].toCharArray();
				Log.d(LOG_TAG,"HID:signTransaction " + String.valueOf(tsDetailsArray[i]) + " " + i);
			}
			char[] challenge = asyncOTPGenerator.formatSignatureChallenge(tsDetailsArray);
			InputOCRAParameters inputOcraParameters = new InputOCRAParameters(null, null);
			if (isBioEnabled) {
				BiometricAuthService bioAuthService = new BiometricAuthService();
				bioAuthService.setBiometricPrompt(activity, ApproveSDKConstants.HID_BIO_PROMPT_TITLE_TS_FLOW,
						container.getProtectionPolicy(), new FingerprintHandler.BiometricEventListener() {

							@Override
							public void onAuthSuccess() {
								Log.d(LOG_TAG, "HID:signTransaction setBiometricPrompt onAuthSuccess");
							}

							@Override
							public void onAuthFailed() {
								Log.d(LOG_TAG, "HID:signTransaction setBiometricPrompt onAuthFailed");
							}

							@Override
							public void onAuthError() {
								new Thread(() -> {
									invokePasswordAuth(asyncOTPGenerator, challenge, inputOcraParameters,
											ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_TYPE,
											ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_CODE);
								}).start();
								Log.d(LOG_TAG, "HID:signTransaction setBiometricPrompt onAuthError");
							}
						});
				char[] otp = asyncOTPGenerator.computeSignature(null, challenge, null, inputOcraParameters);
				String otpStr = String.valueOf(otp);
				signTransactionSuccessCallback.execute(new Object[] { otpStr });
				Log.d(LOG_TAG, MSG_OTP  + otpStr);
			} else {
				invokePasswordAuth(asyncOTPGenerator, challenge, inputOcraParameters,
						ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_TYPE,
						ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_CODE);
			}

		} catch (InvalidChallengeException e) {
			Log.d(LOG_TAG, "HID:signTransaction InvalidChallengeException" + e.getStackTrace());
			e.printStackTrace();
			executeFailureCallback("InvalidChallengeException", e.getMessage());
		} catch (InvalidParameterException e) {
			Log.d(LOG_TAG, MSG_INVALID_PARAM  + e.getStackTrace());
			e.printStackTrace();
			executeFailureCallback(INVALID_PARAMETER_EXCEPTION, e.getMessage());
		} catch (LostCredentialsException e) {
			Log.d(LOG_TAG, MSG_LOST_CREDENTIALS  + e.getStackTrace());
			e.printStackTrace();
			executeFailureCallback(LOST_CREDENTIALS_EXCEPTION, e.getMessage());
		} catch (InternalException e) {
			Log.d(LOG_TAG, MSG_INTERNAL  + e.getStackTrace());
			e.printStackTrace();
			executeFailureCallback(INTERNAL_EXCEPTION, e.getMessage());
		} catch (AuthenticationException e) {
			Log.d(LOG_TAG, MSG_AUTH_EXCEPTION  + e.getStackTrace());
			e.printStackTrace();
			executeFailureCallback(AUTHENTICATION_EXCEPTION, e.getMessage());
		} catch (UnsupportedDeviceException e) {
			Log.d(LOG_TAG, MSG_UNSUPPORTED_DEVICE + e.getStackTrace());
			e.printStackTrace();
			executeFailureCallback(UNSUPPORTED_DEVICE_EXCEPTION, e.getMessage());
		} catch (FingerprintAuthenticationRequiredException e) {
			Log.d(LOG_TAG, MSG_FP_AUTH_REQUIRED  + e.getStackTrace());
			e.printStackTrace();
			executeFailureCallback(FINGERPRINT_AUTHENTICATION_REQUIRED_EXCEPTION, e.getMessage());
		} catch (FingerprintNotEnrolledException e) {
			Log.d(LOG_TAG, MSG_FP_NOT_ENROLLED  + e.getStackTrace());
			e.printStackTrace();
			executeFailureCallback(FINGERPRINT_NOT_ENROLLED_EXCEPTION, e.getMessage());
		} catch (PasswordRequiredException e) {
			Log.d(LOG_TAG,MSG_PWD_REQUIRED  + e.getStackTrace());
			e.printStackTrace();
			executeFailureCallback("PasswordRequiredException", e.getMessage());
		} catch (PasswordExpiredException e) {
			Log.d(LOG_TAG, MSG_PWD_EXPIRED + e.getStackTrace());
			e.printStackTrace();
			executeFailureCallback("PasswordExpiredException", e.getMessage());
		} catch (Throwable t) {
			Log.d(LOG_TAG, MSG_GENERIC_EXCEPTION  + t.getStackTrace());
			t.printStackTrace();
			executeFailureCallback("Exception", t.getMessage());
		}

	}

	private String showPasswordFlow(String eventType, String eventCode) {
		try {
			pwdPromptCB.execute(new Object[] { eventType, eventCode });
			Log.d(LOG_TAG, "HID:signTransaction Callback Executed with EventType " + eventType);
			synchronized (monitor) {
				monitor.wait();
			}
		} catch (Exception e) {
			Log.e(LOG_TAG, "HID:signTransaction showPasswordFlow Exception" + e.getStackTrace());
			e.printStackTrace();
		}
		return monitor.getMsg();
	}

	private void invokePasswordAuth(AsyncOTPGenerator asyncOTPGenerator, char[] challenge,
			InputOCRAParameters inputOcraParameters, String eventType, String eventCode) {
		String password = showPasswordFlow(eventType, eventCode);
		char[] otp;
		try {
			otp = asyncOTPGenerator.computeSignature(password.toCharArray(), challenge, null, inputOcraParameters);
			String otpStr = String.valueOf(otp);
			signTransactionSuccessCallback.execute(new Object[] { otpStr });
			Log.d(LOG_TAG,MSG_OTP  + otpStr);
		} catch (AuthenticationException e) {
			 executeFailureCallback(AUTHENTICATION_EXCEPTION,e.getMessage());
			Log.d(LOG_TAG, MSG_AUTH_EXCEPTION  + e.getStackTrace());
			e.printStackTrace();
		} catch (PasswordExpiredException e) {
			Log.d(LOG_TAG, MSG_PWD_EXPIRED  + e.getStackTrace());
			invokePasswordAuth(asyncOTPGenerator, challenge, inputOcraParameters,
					ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_TYPE, ApproveSDKConstants.HID_PWD_EXPIRED_PROMPT_EVENT_CODE);
			e.printStackTrace();
		} catch (InvalidPasswordException e) {
			Log.d(LOG_TAG, "HID:signTransaction InvalidPasswordException" + e.getStackTrace());
			executeFailureCallback("InvalidPasswordException", e.getMessage());
			e.printStackTrace();
		} catch (LostCredentialsException e) {
			Log.d(LOG_TAG, MSG_LOST_CREDENTIALS  + e.getStackTrace());
			executeFailureCallback(LOST_CREDENTIALS_EXCEPTION, e.getMessage());
			e.printStackTrace();
		} catch (InternalException e) {
			Log.d(LOG_TAG, MSG_INTERNAL  + e.getStackTrace());
			executeFailureCallback(INTERNAL_EXCEPTION, e.getMessage());
			e.printStackTrace();
		} catch (UnsupportedDeviceException e) {
			Log.d(LOG_TAG, MSG_UNSUPPORTED_DEVICE  + e.getStackTrace());
			executeFailureCallback(UNSUPPORTED_DEVICE_EXCEPTION, e.getMessage());
			e.printStackTrace();
		} catch (FingerprintAuthenticationRequiredException e) {
			Log.d(LOG_TAG, MSG_FP_AUTH_REQUIRED  + e.getStackTrace());
			executeFailureCallback(FINGERPRINT_AUTHENTICATION_REQUIRED_EXCEPTION, e.getMessage());
			e.printStackTrace();
		} catch (FingerprintNotEnrolledException e) {
			Log.d(LOG_TAG, MSG_FP_NOT_ENROLLED  + e.getStackTrace());
			executeFailureCallback(FINGERPRINT_NOT_ENROLLED_EXCEPTION, e.getMessage());
			e.printStackTrace();
		} catch (PasswordRequiredException e) {
			Log.d(LOG_TAG, MSG_PWD_REQUIRED  + e.getStackTrace());
			invokePasswordAuth(asyncOTPGenerator, challenge, inputOcraParameters,
					ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_TYPE, ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
			e.printStackTrace();
		} catch (InvalidParameterException e) {
			Log.d(LOG_TAG, MSG_INVALID_PARAM  + e.getStackTrace());
			executeFailureCallback(INVALID_PARAMETER_EXCEPTION, e.getMessage());
			e.printStackTrace();
		} catch (Exception e) {
			Log.d(LOG_TAG, MSG_GENERIC_EXCEPTION  + e.getStackTrace());
			executeFailureCallback("GenericException", e.getMessage());
			e.printStackTrace();
		}
	}

	private void continueBioAuth(AsyncOTPGenerator asyncOTPGenerator, char[] challenge,
			InputOCRAParameters inputOcraParameters) {
		char[] otp;
		try {
			otp = asyncOTPGenerator.computeSignature(null, challenge, null, inputOcraParameters);
			String otpStr = String.valueOf(otp);
			signTransactionSuccessCallback.execute(new Object[] { otpStr });
			Log.d(LOG_TAG, MSG_OTP  + otpStr);
		} catch (PasswordExpiredException e) {
			Log.d(LOG_TAG, MSG_PWD_EXPIRED  + e.getStackTrace());
			invokePasswordAuth(asyncOTPGenerator, challenge, inputOcraParameters,
					ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_TYPE, ApproveSDKConstants.HID_PWD_EXPIRED_PROMPT_EVENT_CODE);
			e.printStackTrace();
		} catch (InvalidPasswordException e) {
			Log.d(LOG_TAG, "HID:signTransaction InvalidPasswordException" + e.getStackTrace());
			executeFailureCallback("InvalidPasswordException", e.getMessage());
			e.printStackTrace();
		} catch (LostCredentialsException e) {
			Log.d(LOG_TAG, MSG_LOST_CREDENTIALS  + e.getStackTrace());
			executeFailureCallback(LOST_CREDENTIALS_EXCEPTION, e.getMessage());
			e.printStackTrace();
		} catch (InternalException e) {
			Log.d(LOG_TAG, MSG_INTERNAL  + e.getStackTrace());
			executeFailureCallback(INTERNAL_EXCEPTION, e.getMessage());
			e.printStackTrace();
		} catch (AuthenticationException e) {
			Log.d(LOG_TAG, MSG_AUTH_EXCEPTION + e.getStackTrace());
			executeFailureCallback(AUTHENTICATION_EXCEPTION, e.getMessage());
			e.printStackTrace();
		} catch (UnsupportedDeviceException e) {
			Log.d(LOG_TAG, MSG_UNSUPPORTED_DEVICE  + e.getStackTrace());
			executeFailureCallback(UNSUPPORTED_DEVICE_EXCEPTION, e.getMessage());
			e.printStackTrace();
		} catch (FingerprintAuthenticationRequiredException e) {
			Log.d(LOG_TAG, MSG_FP_AUTH_REQUIRED  + e.getStackTrace());
			executeFailureCallback(FINGERPRINT_AUTHENTICATION_REQUIRED_EXCEPTION, e.getMessage());
			e.printStackTrace();
		} catch (FingerprintNotEnrolledException e) {
			Log.d(LOG_TAG,MSG_FP_NOT_ENROLLED  + e.getStackTrace());
			executeFailureCallback(FINGERPRINT_NOT_ENROLLED_EXCEPTION, e.getMessage());
			e.printStackTrace();
		} catch (PasswordRequiredException e) {
			Log.d(LOG_TAG, MSG_PWD_REQUIRED  + e.getStackTrace());
			executeFailureCallback("PasswordRequiredException", e.getMessage());
			e.printStackTrace();
		} catch (InvalidParameterException e) {
			Log.d(LOG_TAG, MSG_INVALID_PARAM  + e.getStackTrace());
			executeFailureCallback(INVALID_PARAMETER_EXCEPTION, e.getMessage());
			e.printStackTrace();
		} catch (Exception e) {
			Log.d(LOG_TAG, MSG_GENERIC_EXCEPTION  + e.getStackTrace());
			executeFailureCallback("GenericException", e.getMessage());
			e.printStackTrace();
		}
	}

	private void executeFailureCallback(String exception, String message) {
		try {
			signTransactionFailureCallback.execute(new Object[] { exception, message });
		} catch (Exception e) {
			Log.d(LOG_TAG, "HID:signTransaction executeFailureCallback Exception" + e.getStackTrace());
			e.printStackTrace();
		}
	}
}
