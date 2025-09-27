package com.hid;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import com.hid.ApproveSDKConstants;
import com.hid.FingerprintHandler;
import com.hid.WaitNotifyMonitor;
import com.hid.BiometricAuthService;
import com.hidglobal.ia.service.beans.ConnectionConfiguration;
import com.hidglobal.ia.service.beans.Parameter;
import com.hidglobal.ia.service.exception.AuthenticationException;
import com.hidglobal.ia.service.exception.FingerprintAuthenticationRequiredException;
import com.hidglobal.ia.service.exception.InexplicitContainerException;
import com.hidglobal.ia.service.exception.InternalException;
import com.hidglobal.ia.service.exception.InvalidContainerException;
import com.hidglobal.ia.service.exception.InvalidParameterException;
import com.hidglobal.ia.service.exception.LostCredentialsException;
import com.hidglobal.ia.service.exception.PasswordExpiredException;
import com.hidglobal.ia.service.exception.PasswordRequiredException;
import com.hidglobal.ia.service.exception.RemoteException;
import com.hidglobal.ia.service.exception.ServerAuthenticationException;
import com.hidglobal.ia.service.exception.ServerOperationFailedException;
import com.hidglobal.ia.service.exception.ServerVersionException;
import com.hidglobal.ia.service.exception.TransactionExpiredException;
import com.hidglobal.ia.service.exception.UnsafeDeviceException;
import com.hidglobal.ia.service.exception.UnsupportedDeviceException;
import com.hidglobal.ia.service.manager.DeviceFactory;
import com.hidglobal.ia.service.manager.SDKConstants;
import com.hidglobal.ia.service.protectionpolicy.BioPasswordPolicy;
import com.hidglobal.ia.service.protectionpolicy.ProtectionPolicy;
import com.hidglobal.ia.service.transaction.Container;
import com.hidglobal.ia.service.transaction.Device;
import com.hidglobal.ia.service.transaction.ServerActionInfo;
import com.hidglobal.ia.service.transaction.Transaction;
import com.konylabs.vm.Function;
import android.app.Activity;
import android.content.Context;
import android.util.Base64;
import android.util.Log;
import androidx.fragment.app.FragmentActivity;

@SuppressWarnings({"java:S1170", "java:S116", "java:S107", "java:S3776", "java:S125", "java:S1192", "java:S1144", "java:S2259"})
public class ApproveNotificationUpdater implements Runnable {
	private String txId;
	private Context appContext;
	private FragmentActivity activity;
	private boolean isBioEnabled;
	private Function onCompleteCB;
	private Function pwdPromptCallback;
	WaitNotifyMonitor monitor;
	private String consensus;
	private static final String LOG_TAG = ApproveSDKConstants.HID_LOG_TAG;
	private String password = "";
	Transaction transactionObj;
	private boolean isPasswordTimeoutFlow;

	public ApproveNotificationUpdater(String txId, String status, String password, Context appContext,
			FragmentActivity activity, boolean isBioEnabled, Function onCompleteCB, Function pwdPromptCallback,
			WaitNotifyMonitor monitor) {
		this.txId = txId;
		this.activity = activity;
		this.appContext = appContext;
		this.isBioEnabled = isBioEnabled;
		this.onCompleteCB = onCompleteCB;
		this.pwdPromptCallback = pwdPromptCallback;
		this.monitor = monitor;
		this.consensus = status;
		this.isPasswordTimeoutFlow = false;
		if (!"".equals(password)) {
			this.isPasswordTimeoutFlow = true;
		}
		this.password = password;
	}

	@Override
	public void run() {
		Transaction transaction = null;
		ServerActionInfo transactionInfo = null;
		try {
			Device device = DeviceFactory.getDevice(appContext, new ConnectionConfiguration());
			transactionInfo = device.retrieveActionInfo(txId.toCharArray());
			ProtectionPolicy policy = transactionInfo.getProtectionKey().getProtectionPolicy();
			if (policy.getType().equals(ProtectionPolicy.PolicyType.PASSWORD.name())) {
				Log.d(LOG_TAG, "HID:setNotificationStatus Password is Required");
			}
			
			transaction = (Transaction) transactionInfo.getAction(null, new Parameter[0]);

//			// Workaround for TransactionExpiredException
//			try {
//				transaction = (Transaction) transactionInfo.getAction(null, new Parameter[0]);
//			} catch (AuthenticationException | TransactionExpiredException aetee) {
//				Log.d(LOG_TAG, "HID:setNotificationStatus getAction Transaction Expired Exception " + aetee.getMessage());
//				showPasswordFlow(ApproveSDKConstants.TRANSACTION_EXPIRED_EXCEPTION,
//						ApproveSDKConstants.HID_TRANSACTION_EXPIRED_CODE);
//			} catch (Exception e) {
//				Log.d(LOG_TAG, "HID:setNotificationStatus getAction Exception occured " + e.getMessage());
//				showPasswordFlow("getAction Exception", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
//				e.printStackTrace();
//			}
//			//

			transactionObj = transaction;
			if (isPasswordTimeoutFlow) {
				Log.d(LOG_TAG, "HID:setNotificationStatus PasswordTimeoutFlow");
				invokePasswordAuth(transaction, ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_TYPE,
						ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_CODE);
				return;
			}
			Container container = transactionInfo.getContainer();
			if (isBioEnabled) {
				BiometricAuthService bioAuthService = new BiometricAuthService();
				bioAuthService.setBiometricPrompt(activity, ApproveSDKConstants.HID_BIO_PROMPT_TITLE_PUSH_FLOW,
						container.getProtectionPolicy(), new FingerprintHandler.BiometricEventListener() {

							@Override
							public void onAuthSuccess() {
								// Do Nothing
							}

							@Override
							public void onAuthFailed() {
								// Do Nothing

							}

							@Override
							public void onAuthError() {
								// Do Nothing
							}
						});
			}

			boolean result = transaction.setStatus(consensus, null, null, new Parameter[0]);
			onCompleteCB.execute(new Object[] { result });
			Log.d(LOG_TAG, "HID:setNotificationStatus Completed Executing NotificationUpdaterCallback");
			
		} catch (AuthenticationException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus Authentication Required Exception" + e.getStackTrace());
			invokePasswordAuth(transaction, ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_TYPE,
					ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_CODE);
		} catch (FingerprintAuthenticationRequiredException fe) {
			Log.d(LOG_TAG, "HID:setNotificationStatus Fingerprint Required Exception " + fe.getStackTrace());
			showPasswordFlow(ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_TYPE,
					ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_CODE);
		} catch (PasswordRequiredException pe) {
			Log.d(LOG_TAG, "HID:setNotificationStatus Password Required Exception" + pe.getStackTrace());
			invokePasswordAuth(transaction, ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_TYPE,
					ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_CODE);
		} catch (TransactionExpiredException te) {
			Log.d(LOG_TAG, "HID:setNotificationStatus Transaction Expired Exception " + te.getStackTrace());
			showPasswordFlow(ApproveSDKConstants.HID_TRANSACTION_EXPIRED_EXCEPTION,
					ApproveSDKConstants.HID_TRANSACTION_EXPIRED_CODE);
			te.printStackTrace();
		} catch (InternalException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus InternalException" + e.getStackTrace());
			showPasswordFlow("InternalException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (InvalidParameterException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus InvalidParameterException" + e.getStackTrace());
			showPasswordFlow("InvalidParameterException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (UnsupportedDeviceException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus UnsupportedDeviceException" + e.getStackTrace());
			showPasswordFlow("UnsupportedDeviceException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (LostCredentialsException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus LostCredentialsException" + e.getStackTrace());
			showPasswordFlow("LostCredentialsException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (InvalidContainerException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus InvalidContainerException" + e.getStackTrace());
			showPasswordFlow("InvalidContainerException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (InexplicitContainerException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus InexplicitContainerException" + e.getStackTrace());
			showPasswordFlow("InexplicitContainerException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (PasswordExpiredException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus PasswordExpiredException" + e.getStackTrace());
			showPasswordFlow("PasswordExpiredException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (ServerVersionException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus ServerVersionException" + e.getStackTrace());
			showPasswordFlow("ServerVersionException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (RemoteException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus RemoteException" + e.getStackTrace());
			showPasswordFlow("RemoteException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (ServerOperationFailedException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus ServerOperationFailedException" + e.getStackTrace());
			showPasswordFlow("ServerOperationFailedException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (Exception e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus Exception occured" + e.getStackTrace());
			e.printStackTrace();
		}
	}

	private void bioAuth(Transaction transaction, ServerActionInfo transactionInfo) {
		BiometricAuthService bioAuthService = new BiometricAuthService();
		try {
			Container container = transactionInfo.getContainer();
			bioAuthService.setBiometricPrompt(activity, ApproveSDKConstants.HID_BIO_PROMPT_TITLE_PUSH_FLOW,
					container.getProtectionPolicy(), new FingerprintHandler.BiometricEventListener() {

						@Override
						public void onAuthSuccess() {
							Log.d(LOG_TAG, "HID:setNotificationStatus Inside bioAuth Success ");
						}

						@Override
						public void onAuthFailed() {
							// Do Nothing

						}

						@Override
						public void onAuthError() {
							// Do Nothing
						}
					});
		} catch (UnsupportedDeviceException | InternalException | LostCredentialsException e) {
			e.printStackTrace();
			Log.d(LOG_TAG, "HID:setNotificationStatus Exception" + e.getStackTrace());
			invokePasswordAuth(transaction, ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_TYPE,
					ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		}
		Log.d(LOG_TAG, "HID:setNotificationStatus " + Arrays.toString(transaction.getAllowedStatuses()));
		try {
			transaction.setStatus(consensus, null, null, new Parameter[0]);
		} catch (AuthenticationException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus Authentication Required Exception" + e.getStackTrace());
			invokePasswordAuth(transaction, ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_TYPE,
					ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_CODE);
		} catch (FingerprintAuthenticationRequiredException fe) {
			Log.d(LOG_TAG, "HID:setNotificationStatus fingerprint Required Exception " + fe.getStackTrace());
			showPasswordFlow(ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_TYPE,
					ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_CODE);
		} catch (PasswordRequiredException pe) {
			Log.d(LOG_TAG, "HID:setNotificationStatus fingerprint Required Exception" + pe.getStackTrace());
			invokePasswordAuth(transaction, ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_TYPE,
					ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_CODE);
		} catch (TransactionExpiredException te) {
			Log.d(LOG_TAG, "HID:setNotificationStatus Transaction Expired Exception " + te.getStackTrace());
			showPasswordFlow(ApproveSDKConstants.HID_TRANSACTION_EXPIRED_EXCEPTION,
					ApproveSDKConstants.HID_TRANSACTION_EXPIRED_CODE);
			te.printStackTrace();
		} catch (InternalException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus InternalException" + e.getStackTrace());
			showPasswordFlow("InternalException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (InvalidParameterException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus InvalidParameterException" + e.getStackTrace());
			showPasswordFlow("InvalidParameterException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (UnsupportedDeviceException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus UnsupportedDeviceException" + e.getStackTrace());
			showPasswordFlow("UnsupportedDeviceException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (LostCredentialsException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus LostCredentialsException" + e.getStackTrace());
			showPasswordFlow("LostCredentialsException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (PasswordExpiredException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus PasswordExpiredException" + e.getStackTrace());
			showPasswordFlow("PasswordExpiredException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (ServerVersionException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus ServerVersionException" + e.getStackTrace());
			showPasswordFlow("ServerVersionException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (RemoteException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus RemoteException" + e.getStackTrace());
			showPasswordFlow("RemoteException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (ServerOperationFailedException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus ServerOperationFailedException" + e.getStackTrace());
			showPasswordFlow("ServerOperationFailedException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (Exception e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus Exception occured " + e.getStackTrace());
			showPasswordFlow("Exception", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
			e.printStackTrace();
		}
	}

	private void showPasswordFlow(String eventType, String eventCode) {
		try {
			pwdPromptCallback.execute(new Object[] { eventType, eventCode });
			Log.d(LOG_TAG, "HID:setNotificationStatus Callback Executed with EventType " + eventType);
			Log.d(LOG_TAG, "HID:setNotificationStatus Callback Executed with EventCode " + eventCode);
		} catch (Exception e) {
			Log.e(LOG_TAG, "HID:setNotificationStatus showPasswordFow Exception " + e.getStackTrace());
		}
		Log.d(LOG_TAG, "HID:setNotificationStatus Invoke PWD Auth Notified with password");
	}

	private void continueBioAuth(Transaction transaction) {
		try {
			boolean result = transaction.setStatus(consensus, null, null, new Parameter[0]);
			Log.d(LOG_TAG, "HID:setNotificationStatus Completed Result " + result);
			onCompleteCB.execute(new Object[] { result });
		} catch (AuthenticationException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus Authentication Required Exception" + e.getStackTrace());
			invokePasswordAuth(transaction, ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_TYPE,
					ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_CODE);
			e.printStackTrace();
		} catch (FingerprintAuthenticationRequiredException fe) {
			Log.d(LOG_TAG, "HID:setNotificationStatus fingerprint Required Exception " + fe.getStackTrace());
			showPasswordFlow(ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_TYPE,
					ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_CODE);
			fe.printStackTrace();
		} catch (PasswordRequiredException pe) {
			Log.d(LOG_TAG, "HID:setNotificationStatus fingerprint Required Exception" + pe.getStackTrace());
			invokePasswordAuth(transaction, ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_TYPE,
					ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_CODE);
			pe.printStackTrace();
		} catch (TransactionExpiredException te) {
			Log.d(LOG_TAG, "HID:setNotificationStatus Transaction Expired Exception " + te.getStackTrace());
			showPasswordFlow(ApproveSDKConstants.HID_TRANSACTION_EXPIRED_EXCEPTION,
					ApproveSDKConstants.HID_TRANSACTION_EXPIRED_CODE);
			te.printStackTrace();
		} catch (InternalException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus InternalException" + e.getStackTrace());
			showPasswordFlow("InternalException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
			e.printStackTrace();
		} catch (InvalidParameterException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus InvalidParameterException" + e.getStackTrace());
			showPasswordFlow("InvalidParameterException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
			e.printStackTrace();
		} catch (UnsupportedDeviceException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus UnsupportedDeviceException" + e.getStackTrace());
			showPasswordFlow("UnsupportedDeviceException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
			e.printStackTrace();
		} catch (LostCredentialsException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus LostCredentialsException" + e.getStackTrace());
			showPasswordFlow("LostCredentialsException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
			e.printStackTrace();
		} catch (InvalidContainerException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus InvalidContainerException" + e.getStackTrace());
			showPasswordFlow("InvalidContainerException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
			e.printStackTrace();
		} catch (InexplicitContainerException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus InexplicitContainerException" + e.getStackTrace());
			showPasswordFlow("InexplicitContainerException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
			e.printStackTrace();
		} catch (PasswordExpiredException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus PasswordExpiredException" + e.getStackTrace());
			showPasswordFlow("PasswordExpiredException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
			e.printStackTrace();
		} catch (ServerVersionException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus ServerVersionException" + e.getStackTrace());
			showPasswordFlow("ServerVersionException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
			e.printStackTrace();
		} catch (RemoteException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus RemoteException" + e.getStackTrace());
			showPasswordFlow("RemoteException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
			e.printStackTrace();
		} catch (ServerOperationFailedException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus ServerOperationFailedException" + e.getStackTrace());
			showPasswordFlow("ServerOperationFailedException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
			e.printStackTrace();
		} catch (Exception e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus Exception occured " + e.getStackTrace());
			e.printStackTrace();
		}
	}

	private void invokePasswordAuth(Transaction transaction, String eventType, String eventCode) {
		if (!isPasswordTimeoutFlow) {
			showPasswordFlow(eventType, eventCode);
			return;
		}
		try {
			Log.d(LOG_TAG, "HID:setNotificationStatus Password for status is ---> " + password);
			boolean result;
			if (password == null || password.trim().isEmpty()){
				Log.d(LOG_TAG, "HID:setNotificationStatus Password for status is (If)---> " + password);
				Log.d(LOG_TAG, "HID:setNotificationStatus Consensus for status is (If)---> " + consensus);

				result = transaction.setStatus(consensus, null, null, new Parameter[0]);
			} else {
				Log.d(LOG_TAG, "HID:setNotificationStatus Password for status is (else)---> " + password);
				Log.d(LOG_TAG, "HID:setNotificationStatus Consensus for status is (else)---> " + consensus);

				result = transaction.setStatus(consensus, password.toCharArray(), null, new Parameter[0]);
			}
			onCompleteCB.execute(new Object[] { result });
			isPasswordTimeoutFlow = false;
			
		} catch (AuthenticationException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth AuthenticationException" + e.getStackTrace());
			e.printStackTrace();
			showPasswordFlow(ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_TYPE,
					ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (FingerprintAuthenticationRequiredException fe) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth FingerprintAuthenticationRequiredException " + fe.getStackTrace());
			fe.printStackTrace();
			showPasswordFlow(ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_TYPE,
					ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_CODE);
		} catch (PasswordRequiredException pe) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth PasswordRequiredException" + pe.getStackTrace());
			pe.printStackTrace();
			invokePasswordAuth(transaction, ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_TYPE,
					ApproveSDKConstants.HID_PWD_PROMPT_PROGRESS_EVENT_CODE);
		} catch (TransactionExpiredException te) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth TransactionExpiredException" + te.getStackTrace());
			te.printStackTrace();
			showPasswordFlow(ApproveSDKConstants.HID_TRANSACTION_EXPIRED_EXCEPTION,
					ApproveSDKConstants.HID_TRANSACTION_EXPIRED_CODE);
		} catch (PasswordExpiredException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth PasswordExpiredException" + e.getStackTrace());
			e.printStackTrace();
			showPasswordFlow("PasswordExpiredException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (ServerVersionException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth ServerVersionException" + e.getStackTrace());
			e.printStackTrace();
			showPasswordFlow("ServerVersionException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (RemoteException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth RemoteException" + e.getStackTrace());
			e.printStackTrace();
			showPasswordFlow("RemoteException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (LostCredentialsException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth LostCredentialsException" + e.getStackTrace());
			e.printStackTrace();
			showPasswordFlow("LostCredentialsException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (InternalException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth InternalException" + e.getStackTrace());
			e.printStackTrace();
			showPasswordFlow("InternalException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (ServerOperationFailedException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth ServerOperationFailedException" + e.getStackTrace());
			e.printStackTrace();
			showPasswordFlow("ServerOperationFailedException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (InvalidParameterException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth InvalidParameterException" + e.getStackTrace());
			e.printStackTrace();
			showPasswordFlow("InvalidParameterException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (UnsupportedDeviceException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth UnsupportedDeviceException" + e.getStackTrace());
			e.printStackTrace();
			showPasswordFlow("UnsupportedDeviceException", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (Exception e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth Exception occured " + e.getStackTrace());
			e.printStackTrace();
			showPasswordFlow("Exception", ApproveSDKConstants.HID_PWD_PROMPT_ERROR_EVENT_CODE);
		}
	}
}
