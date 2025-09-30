package com.hid;

import android.util.Log;

public enum OtpKeyLabel {
	//Keys
	PUSH_KEY_PUBLIC_LABEL("pushkeyPublic"),
	PUSH_KEY_IDP_PUBLIC_LABEL("pushhkeyIDPPublic"),
	SIGN_KEY_PUBLIC_LABEL("signkeyPublic"),
	
	//OTP Keys
	HOTP_KEY_LABEL("OATH_event"), 
	TOTP_KEY_LABEL("OATH_time"),
	
	// For Challenge Response
	OATH_OCRA_HOTP_CR_LABEL("OATH_OCRA_event_CR"), 
	OATH_OCRA_TOTP_CR_LABEL("OATH_OCRA_time_CR"),
	
	// For Signature
	OATH_OCRA_HOTP_SIGN_LABEL("OATH_OCRA_event_SIGN"), 
	OATH_OCRA_TOTP_SIGN_LABEL("OATH_OCRA_time_SIGN"),;

	private final String code;

	OtpKeyLabel(String code) {
		this.code = code;
	}

	public String getCode() {
		Log.d(ApproveSDKConstants.HID_LOG_TAG, "HID:OtpKeyLabel getCode ---> OtpKeyLabel code: " + code);
		return code;
	}
}
