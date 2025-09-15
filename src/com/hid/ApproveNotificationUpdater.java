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

public class ApproveNotificationUpdater implements Runnable {
	private String txId;
	private Context appContext;
	private FragmentActivity activity;
	private boolean isBioEnabled;
	private Container container;
	private Function onCompleteCB;
	private Function pwdPromptCallback;
	private WaitNotifyMonitor monitor;
	private String consensus;
	private final String LOG_TAG = ApproveSDKConstants.LOG_TAG;
	private String password = "";
	private Transaction _transaction;
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
//						ApproveSDKConstants.TRANSACTION_EXPIRED_CODE);
//			} catch (Exception e) {
//				Log.d(LOG_TAG, "HID:setNotificationStatus getAction Exception occured " + e.getMessage());
//				showPasswordFlow("getAction Exception", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
//				e.printStackTrace();
//			}
//			//

			_transaction = transaction;
			if (isPasswordTimeoutFlow) {
				Log.d(LOG_TAG, "HID:setNotificationStatus PasswordTimeoutFlow");
				invokePasswordAuth(transaction, ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_TYPE,
						ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_CODE);
				return;
			}
			Container container = transactionInfo.getContainer();
			if (isBioEnabled) {
				// BioPasswordPolicy bioPasswordPolicy = (BioPasswordPolicy)
				// container.getProtectionPolicy();
				// bioPasswordPolicy.resetBiometricPrompt();
				BiometricAuthService bioAuthService = new BiometricAuthService();
				bioAuthService.setBiometricPrompt(activity, ApproveSDKConstants.BIO_PROMPT_TITLE_PUSH_FLOW,
						container.getProtectionPolicy(), new FingerprintHandler.BiometricEventListener() {

							@Override
							public void onAuthSuccess() {
//								new Thread(() -> continueBioAuth(_transaction)).start();
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
			invokePasswordAuth(transaction, ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_TYPE,
					ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_CODE);
		} catch (FingerprintAuthenticationRequiredException fe) {
			Log.d(LOG_TAG, "HID:setNotificationStatus Fingerprint Required Exception " + fe.getStackTrace());
			// BioAuth(transaction,transactionInfo);
			showPasswordFlow(ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_TYPE,
					ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_CODE);
		} catch (PasswordRequiredException pe) {
			Log.d(LOG_TAG, "HID:setNotificationStatus Password Required Exception" + pe.getStackTrace());
			invokePasswordAuth(transaction, ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_TYPE,
					ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_CODE);
		} catch (TransactionExpiredException te) {
			Log.d(LOG_TAG, "HID:setNotificationStatus Transaction Expired Exception " + te.getStackTrace());
			showPasswordFlow(ApproveSDKConstants.TRANSACTION_EXPIRED_EXCEPTION,
					ApproveSDKConstants.TRANSACTION_EXPIRED_CODE);
			te.printStackTrace();
		} catch (InternalException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus InternalException" + e.getStackTrace());
			showPasswordFlow("InternalException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (InvalidParameterException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus InvalidParameterException" + e.getStackTrace());
			showPasswordFlow("InvalidParameterException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (UnsupportedDeviceException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus UnsupportedDeviceException" + e.getStackTrace());
			showPasswordFlow("UnsupportedDeviceException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (LostCredentialsException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus LostCredentialsException" + e.getStackTrace());
			showPasswordFlow("LostCredentialsException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (InvalidContainerException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus InvalidContainerException" + e.getStackTrace());
			showPasswordFlow("InvalidContainerException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (InexplicitContainerException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus InexplicitContainerException" + e.getStackTrace());
			showPasswordFlow("InexplicitContainerException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (PasswordExpiredException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus PasswordExpiredException" + e.getStackTrace());
			showPasswordFlow("PasswordExpiredException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (ServerVersionException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus ServerVersionException" + e.getStackTrace());
			showPasswordFlow("ServerVersionException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (RemoteException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus RemoteException" + e.getStackTrace());
			showPasswordFlow("RemoteException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (ServerOperationFailedException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus ServerOperationFailedException" + e.getStackTrace());
			showPasswordFlow("ServerOperationFailedException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (Exception e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus Exception occured " + e.getStackTrace());
			e.printStackTrace();
		}
	}

	private void BioAuth(Transaction transaction, ServerActionInfo transactionInfo) {
		BiometricAuthService bioAuthService = new BiometricAuthService();
		try {
			Container container = transactionInfo.getContainer();
			bioAuthService.setBiometricPrompt(activity, ApproveSDKConstants.BIO_PROMPT_TITLE_PUSH_FLOW,
					container.getProtectionPolicy(), new FingerprintHandler.BiometricEventListener() {

						@Override
						public void onAuthSuccess() {
//							new Thread(() -> continueBioAuth(transaction)).start();
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
			// TODO Auto-generated catch block
			e.printStackTrace();
			Log.d(LOG_TAG, "HID:setNotificationStatus Exception" + e.getStackTrace());
			invokePasswordAuth(transaction, ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_TYPE,
					ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		}
		Log.d(LOG_TAG, "HID:setNotificationStatus " + Arrays.toString(transaction.getAllowedStatuses()));
		try {
			boolean result = transaction.setStatus(consensus, null, null, new Parameter[0]);
		} catch (AuthenticationException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus Authentication Required Exception" + e.getStackTrace());
			invokePasswordAuth(transaction, ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_TYPE,
					ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_CODE);
		} catch (FingerprintAuthenticationRequiredException fe) {
			Log.d(LOG_TAG, "HID:setNotificationStatus fingerprint Required Exception " + fe.getStackTrace());
			// BioAuth(transaction,transactionInfo);
			showPasswordFlow(ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_TYPE,
					ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_CODE);
		} catch (PasswordRequiredException pe) {
			Log.d(LOG_TAG, "HID:setNotificationStatus fingerprint Required Exception" + pe.getStackTrace());
			invokePasswordAuth(transaction, ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_TYPE,
					ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_CODE);
		} catch (TransactionExpiredException te) {
			Log.d(LOG_TAG, "HID:setNotificationStatus Transaction Expired Exception " + te.getStackTrace());
			showPasswordFlow(ApproveSDKConstants.TRANSACTION_EXPIRED_EXCEPTION,
					ApproveSDKConstants.TRANSACTION_EXPIRED_CODE);
			te.printStackTrace();
		} catch (InternalException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus InternalException" + e.getStackTrace());
			showPasswordFlow("InternalException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (InvalidParameterException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus InvalidParameterException" + e.getStackTrace());
			showPasswordFlow("InvalidParameterException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (UnsupportedDeviceException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus UnsupportedDeviceException" + e.getStackTrace());
			showPasswordFlow("UnsupportedDeviceException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (LostCredentialsException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus LostCredentialsException" + e.getStackTrace());
			showPasswordFlow("LostCredentialsException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (PasswordExpiredException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus PasswordExpiredException" + e.getStackTrace());
			showPasswordFlow("PasswordExpiredException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (ServerVersionException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus ServerVersionException" + e.getStackTrace());
			showPasswordFlow("ServerVersionException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (RemoteException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus RemoteException" + e.getStackTrace());
			showPasswordFlow("RemoteException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (ServerOperationFailedException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus ServerOperationFailedException" + e.getStackTrace());
			showPasswordFlow("ServerOperationFailedException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (Exception e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus Exception occured " + e.getStackTrace());
			showPasswordFlow("Exception", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
			e.printStackTrace();
		}
	}

	private void showPasswordFlow(String eventType, String eventCode) {
		try {
			pwdPromptCallback.execute(new Object[] { eventType, eventCode });
			Log.d(LOG_TAG, "HID:setNotificationStatus Callback Executed with EventType " + eventType);
			Log.d(LOG_TAG, "HID:setNotificationStatus Callback Executed with EventCode " + eventCode);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			Log.e(LOG_TAG, "HID:setNotificationStatus showPasswordFow Exception");
			e.printStackTrace();
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
			invokePasswordAuth(transaction, ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_TYPE,
					ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_CODE);
			e.printStackTrace();
		} catch (FingerprintAuthenticationRequiredException fe) {
			Log.d(LOG_TAG, "HID:setNotificationStatus fingerprint Required Exception " + fe.getStackTrace());
			// BioAuth(transaction,transactionInfo);
			showPasswordFlow(ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_TYPE,
					ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_CODE);
			fe.printStackTrace();
		} catch (PasswordRequiredException pe) {
			Log.d(LOG_TAG, "HID:setNotificationStatus fingerprint Required Exception" + pe.getStackTrace());
			invokePasswordAuth(transaction, ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_TYPE,
					ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_CODE);
			pe.printStackTrace();
		} catch (TransactionExpiredException te) {
			Log.d(LOG_TAG, "HID:setNotificationStatus Transaction Expired Exception " + te.getStackTrace());
			showPasswordFlow(ApproveSDKConstants.TRANSACTION_EXPIRED_EXCEPTION,
					ApproveSDKConstants.TRANSACTION_EXPIRED_CODE);
			te.printStackTrace();
		} catch (InternalException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus InternalException" + e.getStackTrace());
			showPasswordFlow("InternalException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
			e.printStackTrace();
		} catch (InvalidParameterException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus InvalidParameterException" + e.getStackTrace());
			showPasswordFlow("InvalidParameterException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
			e.printStackTrace();
		} catch (UnsupportedDeviceException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus UnsupportedDeviceException" + e.getStackTrace());
			showPasswordFlow("UnsupportedDeviceException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
			e.printStackTrace();
		} catch (LostCredentialsException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus LostCredentialsException" + e.getStackTrace());
			showPasswordFlow("LostCredentialsException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
			e.printStackTrace();
		} catch (InvalidContainerException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus InvalidContainerException" + e.getStackTrace());
			showPasswordFlow("InvalidContainerException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
			e.printStackTrace();
		} catch (InexplicitContainerException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus InexplicitContainerException" + e.getStackTrace());
			showPasswordFlow("InexplicitContainerException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
			e.printStackTrace();
		} catch (PasswordExpiredException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus PasswordExpiredException" + e.getStackTrace());
			showPasswordFlow("PasswordExpiredException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
			e.printStackTrace();
		} catch (ServerVersionException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus ServerVersionException" + e.getStackTrace());
			showPasswordFlow("ServerVersionException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
			e.printStackTrace();
		} catch (RemoteException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus RemoteException" + e.getStackTrace());
			showPasswordFlow("RemoteException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
			e.printStackTrace();
		} catch (ServerOperationFailedException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus ServerOperationFailedException" + e.getStackTrace());
			showPasswordFlow("ServerOperationFailedException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
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
			if (password == null || password == "" || password == " ") {
				Log.d(LOG_TAG, "HID:setNotificationStatus Password for status is (If)---> " + password);
				Log.d(LOG_TAG, "HID:setNotificationStatus Consensus for status is (If)---> " + consensus);

				result = transaction.setStatus(consensus, null, null, new Parameter[0]);
			} else {
				Log.d(LOG_TAG, "HID:setNotificationStatus Password for status is (else)---> " + password);
				Log.d(LOG_TAG, "HID:setNotificationStatus Consensus for status is (else)---> " + consensus);

				result = transaction.setStatus(consensus, password.toCharArray(), null, new Parameter[0]);
			}
			onCompleteCB.execute(new Object[] { result });
			if (isPasswordTimeoutFlow) {
				isPasswordTimeoutFlow = false;
			}
		} catch (AuthenticationException e) {
			// TODO Auto-generated catch block
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth AuthenticationException" + e.getStackTrace());
			e.printStackTrace();
			showPasswordFlow(ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_TYPE,
					ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (FingerprintAuthenticationRequiredException fe) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth FingerprintAuthenticationRequiredException " + fe.getStackTrace());
			fe.printStackTrace();
			showPasswordFlow(ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_TYPE,
					ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_CODE);
		} catch (PasswordRequiredException pe) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth PasswordRequiredException" + pe.getStackTrace());
			pe.printStackTrace();
			invokePasswordAuth(transaction, ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_TYPE,
					ApproveSDKConstants.PWD_PROMPT_PROGRESS_EVENT_CODE);
		} catch (TransactionExpiredException te) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth TransactionExpiredException" + te.getStackTrace());
			te.printStackTrace();
			showPasswordFlow(ApproveSDKConstants.TRANSACTION_EXPIRED_EXCEPTION,
					ApproveSDKConstants.TRANSACTION_EXPIRED_CODE);
		} catch (PasswordExpiredException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth PasswordExpiredException" + e.getStackTrace());
			e.printStackTrace();
			showPasswordFlow("PasswordExpiredException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (ServerVersionException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth ServerVersionException" + e.getStackTrace());
			e.printStackTrace();
			showPasswordFlow("ServerVersionException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (RemoteException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth RemoteException" + e.getStackTrace());
			e.printStackTrace();
			showPasswordFlow("RemoteException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (LostCredentialsException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth LostCredentialsException" + e.getStackTrace());
			e.printStackTrace();
			showPasswordFlow("LostCredentialsException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (InternalException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth InternalException" + e.getStackTrace());
			e.printStackTrace();
			showPasswordFlow("InternalException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (ServerOperationFailedException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth ServerOperationFailedException" + e.getStackTrace());
			e.printStackTrace();
			showPasswordFlow("ServerOperationFailedException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (InvalidParameterException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth InvalidParameterException" + e.getStackTrace());
			e.printStackTrace();
			showPasswordFlow("InvalidParameterException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (UnsupportedDeviceException e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth UnsupportedDeviceException" + e.getStackTrace());
			e.printStackTrace();
			showPasswordFlow("UnsupportedDeviceException", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		} catch (Exception e) {
			Log.d(LOG_TAG, "HID:setNotificationStatus invokePasswordAuth Exception occured " + e.getStackTrace());
			e.printStackTrace();
			showPasswordFlow("Exception", ApproveSDKConstants.PWD_PROMPT_ERROR_EVENT_CODE);
		}
	}
}
