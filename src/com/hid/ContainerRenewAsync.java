package com.hid;

import com.hidglobal.ia.service.beans.ConnectionConfiguration;
import com.hidglobal.ia.service.beans.Parameter;
import com.hidglobal.ia.service.exception.AuthenticationException;
import com.hidglobal.ia.service.exception.CredentialsExpiredException;
import com.hidglobal.ia.service.exception.FingerprintAuthenticationRequiredException;
import com.hidglobal.ia.service.exception.FingerprintNotEnrolledException;
import com.hidglobal.ia.service.exception.GooglePlayServicesObsoleteException;
import com.hidglobal.ia.service.exception.InternalException;
import com.hidglobal.ia.service.exception.InvalidParameterException;
import com.hidglobal.ia.service.exception.InvalidPasswordException;
import com.hidglobal.ia.service.exception.LostCredentialsException;
import com.hidglobal.ia.service.exception.PasswordCancelledException;
import com.hidglobal.ia.service.exception.PasswordExpiredException;
import com.hidglobal.ia.service.exception.PasswordRequiredException;
import com.hidglobal.ia.service.exception.RemoteException;
import com.hidglobal.ia.service.exception.ServerOperationFailedException;
import com.hidglobal.ia.service.exception.ServerProtocolException;
import com.hidglobal.ia.service.exception.ServerUnsupportedOperationException;
import com.hidglobal.ia.service.exception.UnsafeDeviceException;
import com.hidglobal.ia.service.exception.UnsupportedDeviceException;
import com.hidglobal.ia.service.manager.DeviceFactory;
import com.hidglobal.ia.service.protectionpolicy.BioPasswordPolicy;
import com.hidglobal.ia.service.protectionpolicy.ProtectionPolicy;
import com.hidglobal.ia.service.transaction.Container;
import com.hidglobal.ia.service.transaction.ContainerInitialization;
import com.hidglobal.ia.service.transaction.ContainerRenewal;
import com.hidglobal.ia.service.transaction.Device;
import com.konylabs.vm.Function;

import android.content.Context;
import android.util.Log;
import androidx.fragment.app.FragmentActivity;
@SuppressWarnings("java:S3776")
public class ContainerRenewAsync implements Runnable {
	private String password;
	private Context appContext;
	private boolean isBioEnabled;
	private FragmentActivity activity;
	private Function exceptionCallback;
	private Function promptCallback;
	private FingerprintHandler.BiometricEventListener biometricEventListener;
	private WaitNotifyMonitor monitor;
	private Container container;
	private static final String LOG_TAG = ApproveSDKConstants.HID_LOG_TAG;

	public ContainerRenewAsync(String password, Context appContext,FragmentActivity activity,boolean isBioEnabled, Function promptCallback,
			Function exceptionCallback,Container container) {
		this.password = password;
		this.appContext = appContext; 
		this.activity = activity;
		this.isBioEnabled = isBioEnabled;
		this.exceptionCallback = exceptionCallback;
		this.promptCallback = promptCallback;
		this.monitor = monitor;
		this.container = container;
	}

	public void setBiometricEventListener(FingerprintHandler.BiometricEventListener biometricEventListener) {
		this.biometricEventListener = biometricEventListener;
	}
	
	@Override
	public void run() {
		try {
			if (container.isRenewable(null)) {
				if(isBioEnabled && (password == null || password.isEmpty())) {
					BiometricAuthService bioAuthService = new BiometricAuthService();
					bioAuthService.setBiometricPrompt(activity, "",
							container.getProtectionPolicy(), biometricEventListener);	
				ContainerRenewal containerRenewal = new ContainerRenewal();
				EventListenerCallback eventListenerCallback = new EventListenerCallback(appContext, exceptionCallback,
						monitor);
				containerRenewal.password = null;
				container.renew(containerRenewal, null, eventListenerCallback);
				Log.d(LOG_TAG, "HID:renewContainer - Container has been renewed.");
			}else {
				ContainerRenewal containerRenewal = new ContainerRenewal();
				EventListenerCallback eventListenerCallback = new EventListenerCallback(appContext, promptCallback,
						monitor);
				if (password != null) {
					Log.d(LOG_TAG, "HID:renewContainer - Cotainer password exists and renewal in progress");
					containerRenewal.password = password.toCharArray();
				}
				container.renew(containerRenewal, null, eventListenerCallback);
				Log.d(LOG_TAG, "HID:renewContainer - Container has been renewed.");
			}
			Log.d(LOG_TAG, "HID:renewContainer - ContainerID is ---> " + container.getUserId() + " " + container.getName());
			}
			exceptionCallback("No Exception", "success", exceptionCallback);
		} catch (UnsupportedDeviceException e) {
			Log.d(LOG_TAG, "HID:renewContainer - UnsupportedDeviceException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("UnsupportedDeviceException", e.getMessage(), exceptionCallback);
		} catch (AuthenticationException e) {
			Log.d(LOG_TAG, "HID:renewContainer - AuthenticationException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("AuthenticationException", e.getMessage(), exceptionCallback);
		} catch (PasswordExpiredException e) {
			Log.d(LOG_TAG, "HID:renewContainer - PasswordExpiredException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("PasswordExpiredException", e.getMessage(), exceptionCallback);
		} catch (FingerprintAuthenticationRequiredException e) {
			Log.d(LOG_TAG, "HID:renewContainer - FingerprintAuthenticationRequiredException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("FingerprintAuthenticationRequiredException", e.getMessage(), exceptionCallback);
		} catch (FingerprintNotEnrolledException e) {
			Log.d(LOG_TAG, "HID:renewContainer - FingerprintNotEnrolledException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("FingerprintNotEnrolledException", e.getMessage(), exceptionCallback);
		} catch (PasswordRequiredException e) {
			Log.d(LOG_TAG, "HID:renewContainer - PasswordRequiredException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("PasswordRequiredException", e.getMessage(), exceptionCallback);
		} catch (LostCredentialsException e) {
			Log.d(LOG_TAG, "HID:renewContainer - LostCredentialsException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("LostCredentialsException", e.getMessage(), exceptionCallback);
		} catch (InternalException e) {
			Log.d(LOG_TAG, "HID:renewContainer - InternalException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("InternalException", e.getMessage(), exceptionCallback);
		} catch (RemoteException e) {
			Log.d(LOG_TAG, "HID:renewContainer - RemoteException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("RemoteException", e.getMessage(), exceptionCallback);
		} catch (UnsafeDeviceException e) {
			Log.d(LOG_TAG, "HID:renewContainer - UnsafeDeviceException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("UnsafeDeviceException", e.getMessage(), exceptionCallback);
		} catch (ServerProtocolException e) {
			Log.d(LOG_TAG, "HID:renewContainer - ServerProtocolException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("ServerProtocolException", e.getMessage(), exceptionCallback);
		} catch (CredentialsExpiredException e) {
			Log.d(LOG_TAG, "HID:renewContainer - CredentialsExpiredException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("CredentialsExpiredException", e.getMessage(), exceptionCallback);
		} catch (ServerUnsupportedOperationException e) {
			Log.d(LOG_TAG, "HID:renewContainer - ServerUnsupportedOperationException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("ServerUnsupportedOperationException", e.getMessage(), exceptionCallback);
		} catch (GooglePlayServicesObsoleteException e) {
			Log.d(LOG_TAG, "HID:renewContainer - GooglePlayServicesObsoleteException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("GooglePlayServicesObseleteException", e.getMessage(), exceptionCallback);
		} catch (PasswordCancelledException e) {
			Log.d(LOG_TAG, "HID:renewContainer - PasswordCancelledException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("PasswordCancelledException", e.getMessage(), exceptionCallback);
		} catch (ServerOperationFailedException e) {
			Log.d(LOG_TAG, "HID:renewContainer - ServerOperationFailedException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("ServerOperationFailedException", e.getMessage(), exceptionCallback);
		} catch (InvalidParameterException e) {
			Log.d(LOG_TAG, "HID:renewContainer - InvalidParameterException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("InvalidParameterException", e.getMessage(), exceptionCallback);
		} catch (Exception e) {
			Log.d(LOG_TAG, "HID:renewContainer - Unhandled Exception" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("Unhandled Exception", e.getMessage(), exceptionCallback);
		}
	}

	private void exceptionCallback(String exceptionType, String message, Function callback) {
		Object[] params = new Object[2];
		params[0] = exceptionType;
		params[1] = message;
		try {
			callback.execute(params);
		} catch (Exception e) {
			Log.d(LOG_TAG, "HID:renewContainer - Unhandled Exception" + e.getStackTrace());
			e.printStackTrace();
		}
	}

}
