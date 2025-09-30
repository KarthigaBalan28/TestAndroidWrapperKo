package com.hid;

import com.hidglobal.ia.service.protectionpolicy.BioPasswordPolicy;
import com.hidglobal.ia.service.protectionpolicy.ProtectionPolicy;

import android.util.Log;
import androidx.biometric.BiometricPrompt;
import androidx.fragment.app.FragmentActivity;

public class BiometricAuthService {
	private static final String LOG_TAG = ApproveSDKConstants.HID_LOG_TAG;

	public void setBiometricPrompt(FragmentActivity activity, String mainMessage, ProtectionPolicy protectionPolicy,
			FingerprintHandler.BiometricEventListener bioEventListener) {
		Log.d(LOG_TAG, "HID:setBiometricPrompt SetBioPrompt called for " + mainMessage);
		String message = ApproveSDKConstants.HID_BIOMETRIC_PROMPT_TITLE;
		if (!"".equals(mainMessage)) {
			message = mainMessage;
		}
		Log.d(LOG_TAG, "HID:setBiometricPrompt SetBioPrompt called for " + message);
		try {
			BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder().setTitle(message)
					.setSubtitle(ApproveSDKConstants.HID_BIOMETRIC_PROMPT_SUBTITLE).setNegativeButtonText("cancel").build();
			BioPasswordPolicy policy = (BioPasswordPolicy) protectionPolicy;
			FingerprintHandler fh = new FingerprintHandler(bioEventListener);
			policy.setBiometricPrompt(activity, fh, promptInfo);
			Log.d(LOG_TAG, "HID:setBiometricPrompt BiometricPrompt has been set");
		} catch (Throwable t) {
			t.printStackTrace();
			Log.d(LOG_TAG, "HID:setBiometricPrompt Exception in SetBioPrompt " + t.getMessage());
		}
	}
}