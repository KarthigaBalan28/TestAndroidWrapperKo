package com.hid;

import android.util.Log;
import androidx.biometric.BiometricPrompt;
@SuppressWarnings({"java:S1068", "java:S3008"})
public class FingerprintHandler extends BiometricPrompt.AuthenticationCallback {
	private static int maxAttempts = 3;
	private static String LOG_TAG = ApproveSDKConstants.HID_LOG_TAG;
	private BiometricEventListener biometricEventListener;

	public FingerprintHandler(BiometricEventListener biometricEventListener) {
		this.biometricEventListener = biometricEventListener;
		Log.d(LOG_TAG, "HID:FingerprintHandler Constructor ---> FingerprintHandler created");
	}

	@Override
	public void onAuthenticationError(int errMsgId, CharSequence errString) {
		Log.d(LOG_TAG, "HID:FingerprintHandler onAuthenticateError ---> Authentication error");
		biometricEventListener.onAuthError();
	}

	@Override
	public void onAuthenticationFailed() {
		Log.d(LOG_TAG, "HID:FingerprintHandler onAuthenticateFailed ---> Authentication failed");
		biometricEventListener.onAuthFailed();
	}

	@Override
	public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
		Log.d(LOG_TAG, "HID:FingerprintHandler onAuthenticateSuccess ---> Authentication success");
		biometricEventListener.onAuthSuccess();
	}

	public interface BiometricEventListener {
		void onAuthFailed();

		void onAuthError();

		void onAuthSuccess();
	}

}
