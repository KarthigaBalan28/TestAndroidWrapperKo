package com.hid;

import android.content.Context;
import android.os.Build;
import android.util.Log;
import androidx.biometric.BiometricManager;
@SuppressWarnings("java:S1118")
public class BiometricUtils {
	private static final String LOG_TAG = ApproveSDKConstants.HID_LOG_TAG;

	public static boolean isDeviceFingerPrintEnrolled(Context appContext) {
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
			BiometricManager biometricManager = BiometricManager.from(appContext);
			int state = biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG);
			if (state == BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED) {
				state = biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK);
			}

			switch (state) {
				case BiometricManager.BIOMETRIC_SUCCESS:
					Log.d(LOG_TAG, "HID:isDeviceFingerPrintEnrolled Biometrics enrolled");
					return true;
				case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
					Log.d(LOG_TAG, "HID:isDeviceFingerPrintEnrolled Biometrics not enrolled");
					return false;
				case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
					Log.d(LOG_TAG, "HID:isDeviceFingerPrintEnrolled Biometric hardware unavailable");
					return false;
				case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
					Log.d(LOG_TAG, "HID:isDeviceFingerPrintEnrolled No biometric hardware");
					return false;
				default:
					Log.d(LOG_TAG, "HID:isDeviceFingerPrintEnrolled Unknown biometric error: " + state);
					return false;
				}
			}
		return false;
	}
}
