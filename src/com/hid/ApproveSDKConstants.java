package com.hid;

import com.hidglobal.ia.service.exception.FingerprintAuthenticationRequiredException;
import com.hidglobal.ia.service.transaction.CancelationReason;

@SuppressWarnings({"java:S1118"})
public class ApproveSDKConstants {
	public static final int HID_MAX_BIO_ATTEMPTS = 3;
	public static final String HID_BIOMETRIC_PROMPT_TITLE = "Use your fingerprint for fast and easy access to you account";
	public static final String HID_BIOMETRIC_PROMPT_SUBTITLE = "Confirm fingerprint to continue";
	public static final String HID_SIGN_TRANSACTION_FLOW = "SIGN_TRASACTION";
	public static final String HID_NOTIFICATION_FLOW = "NOTIFICATION_FLOW";
	public static final String HID_TS_VALUES_SEPERATOR = "~";
	public static final String HID_LOG_TAG = "ApproveSDKWrapper";
	public static final String HID_PWD_PROMPT_PROGRESS_EVENT_TYPE = "Progress";
	public static final String HID_PWD_PROMPT_ERROR_EVENT_TYPE = "Error";
	public static final String HID_PWD_PROMPT_PROGRESS_EVENT_CODE = "5000";
	public static final String HID_PWD_PROMPT_ERROR_EVENT_CODE = "5001";
	public static final String HID_PWD_EXPIRED_PROMPT_EVENT_CODE = "5002";
	public static final String HID_PWD_EXPIRED_EXCEPTION = "PasswordExpiredException";
	public static final String HID_AUTHENTICATION_EXCEPTION = "AuthenticationException";
	public static final String HID_TRANSACTION_EXPIRED_CODE = "1000";
	public static final String HID_TRANSACTION_EXPIRED_EXCEPTION = "TransactionExpiredException";
	public static final String HID_BIOMETRIC_ERROR = "BiometricError";
	public static final String HID_BIOMETRIC_FAILED = "BiometricFailed";
	public static final String HID_UNSUPPORTED_DEVICE_EXCEPTION = "UnsupportedDeviceException";
    public static final String HID_LOST_CREDENTIALS_EXCEPTION = "LostCredentialsException";
    public static final String HID_INTERNAL_EXCEPTION = "InternalException";
    public static final String HID_INVALID_PARAMETER_EXCEPTION = "InvalidParameterException";
    public static final String HID_UNSUPPORTED_DEVICE_CODE = "200";
    public static final String HID_LOST_CREDENTIALS_CODE = "106";
    public static final String HID_INTERNAL_EXCEPTION_CODE = "0";
    public static final String HID_INVALID_PARAMETER_CODE = "3";
	public static final String HID_BIOMETRIC_ERROR_CODE = "5003";
	public static final String HID_BIOMETRIC_FAILED_CODE = "5004";
	public static final String HID_GENERIC_ERROR_CODE = "6000";
	public static final String HID_NO_EXCEPTION_CODE = "2000";
	public static final String HID_AUTH_EXCEPTION_CODE = "5001";
	public static final String HID_FINGERPRINT_EXCEPTION = "FingerprintException";
	public static final String HID_BIO_AUTH_NOT_ENABLED = "NoBioAuth";
	public static final String HID_SUCCESS_MESSAGE = "success";
	public static final String HID_NO_EXCEPTION = "No Exception";
	public static final String HID_GENERIC_EXCEPTION = "Exception";
	public static final String HID_BIO_PROMPT_TITLE_PUSH_FLOW = "Use your fingerprint to view the transaction";
	public static final String HID_BIO_PROMPT_TITLE_TS_FLOW = "Use your fingerprint to complete the transaction";
	public static final String HID_BIO_PROMPT_DELETE_USER = "Use your fingerprint to delete your profile";
	public static final String HID_BIO_ALREADY_ENROLLED = "because it is enabled by another user in this device";
	public static final String HID_CONTAINER_FLOW_IDENTIFIER = "dty";
	public static final String HID_AC_USERID_KEY = "userid";
	public static final String HID_AC_SERVICE_KEY = "serviceurl";
	public static final String HID_AC_INVITE_CODE_KEY = "invitecode";
	public static final String HID_TOTP_KEY = "totp";
	public static final String HID_DEVICE_ID = "deviceid";
	public static final String HID_CODE_SECURE = "secure";
	public static final String HID_CODE_SIGN = "sign";
	public static final CancelationReason HID_CANCELATION_REASON_CANCEL = CancelationReason.USER_CANCEL;
	public static final CancelationReason HID_CANCELATION_REASON_SUSPICIOUS = CancelationReason.NOTIFY_SUSPICIOUS;
	public static final String HID_TRANSACTION_CANCELED_EXCEPTION = "TransactionCanceledException";

}
	
