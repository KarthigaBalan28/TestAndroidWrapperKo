package com.hid;

import com.hidglobal.ia.service.beans.ConnectionConfiguration;
import com.hidglobal.ia.service.exception.AuthenticationException;
import com.hidglobal.ia.service.exception.FingerprintAuthenticationRequiredException;
import com.hidglobal.ia.service.exception.FingerprintNotEnrolledException;
import com.hidglobal.ia.service.exception.GooglePlayServicesObsoleteException;
import com.hidglobal.ia.service.exception.InternalException;
import com.hidglobal.ia.service.exception.InvalidParameterException;
import com.hidglobal.ia.service.exception.InvalidPasswordException;
import com.hidglobal.ia.service.exception.LostCredentialsException;
import com.hidglobal.ia.service.exception.PasswordCancelledException;
import com.hidglobal.ia.service.exception.PasswordRequiredException;
import com.hidglobal.ia.service.exception.RemoteException;
import com.hidglobal.ia.service.exception.ServerAuthenticationException;
import com.hidglobal.ia.service.exception.ServerOperationFailedException;
import com.hidglobal.ia.service.exception.ServerProtocolException;
import com.hidglobal.ia.service.exception.UnsafeDeviceException;
import com.hidglobal.ia.service.exception.UnsupportedDeviceException;
import com.hidglobal.ia.service.manager.DeviceFactory;
import com.hidglobal.ia.service.transaction.Container;
import com.hidglobal.ia.service.transaction.ContainerInitialization;
import com.hidglobal.ia.service.transaction.Device;
import com.konylabs.vm.Function;
import org.json.JSONObject;

import android.content.Context;
import android.util.Log;
@SuppressWarnings("java:S3776")
public class ContainerCreatorAsync implements Runnable {
	private String activationCode;
	private String pushId;
	private Context appContext;
	private Function exceptionCallback;
	private Function promptCallback;
	private WaitNotifyMonitor monitor;
	private static final String LOG_TAG = ApproveSDKConstants.HID_LOG_TAG;

	public ContainerCreatorAsync(String activationCode, Context appContext, String pushID, Function promptCallback,
			Function exceptionCallback, WaitNotifyMonitor monitor) {
		this.activationCode = activationCode;
		this.appContext = appContext;
		this.exceptionCallback = exceptionCallback;
		this.promptCallback = promptCallback;
		this.monitor = monitor;
		this.pushId = pushID;
	}

	@Override
	public void run() {
		try {
			Device device = DeviceFactory.getDevice(appContext, new ConnectionConfiguration());
			ContainerInitialization containerInitialization = new ContainerInitialization();
			JSONObject jsonObj = new JSONObject(activationCode);
			String containerCreationFlow = jsonObj.optString(ApproveSDKConstants.HID_CONTAINER_FLOW_IDENTIFIER, "");
			if (containerCreationFlow.isEmpty()) {
				Log.d(LOG_TAG, "HID:createContainer - Manual Activation process is invoked");
				containerInitialization.userId = jsonObj.optString(ApproveSDKConstants.HID_AC_USERID_KEY, "");
				containerInitialization.inviteCode = jsonObj.optString(ApproveSDKConstants.HID_AC_INVITE_CODE_KEY, "").toCharArray();
				containerInitialization.serverUrl = jsonObj.optString(ApproveSDKConstants.HID_AC_SERVICE_KEY, "");
			} else {
				containerInitialization.activationCode = activationCode.toCharArray();
			}
			Log.d(LOG_TAG, "HID:createContainer - PushID while Provising is " + pushId);
			containerInitialization.pushId = pushId;
			EventListenerCallback eventListenerCallback = new EventListenerCallback(appContext, promptCallback,
					monitor);
			Container container = device.createContainer(containerInitialization, null, eventListenerCallback);
			Log.d(LOG_TAG, "HID:createContainer - ContainerID is ---> " + container.getUserId() + " " + container.getName());
			exceptionCallback("No Exception", "success", exceptionCallback);
		} catch (UnsupportedDeviceException e) {
			Log.d(LOG_TAG, "HID:createContainer - UnsupportedDeviceException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("UnsupportedDeviceException", e.getMessage(), exceptionCallback);
		} catch (InternalException e) {
			Log.d(LOG_TAG, "HID:createContainer - InternalException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("InternalException", e.getMessage(), exceptionCallback);
		} catch (InvalidParameterException e) {
			Log.d(LOG_TAG, "HID:createContainer - InvalidParameterException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("InvalidParameterException", e.getMessage(), exceptionCallback);
		} catch (RemoteException e) {
			Log.d(LOG_TAG, "HID:createContainer - RemoteException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("RemoteException", e.getMessage(), exceptionCallback);
		} catch (UnsafeDeviceException e) {
			Log.d(LOG_TAG, "HID:createContainer - UnsafeDeviceException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("UnsafeDeviceException", e.getMessage(), exceptionCallback);
		} catch (FingerprintAuthenticationRequiredException e) {
			Log.d(LOG_TAG, "HID:createContainer - FingerprintAuthenticationRequiredException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("FingerprintAuthenticationRequiredException", e.getMessage(), exceptionCallback);
		} catch (FingerprintNotEnrolledException e) {
			Log.d(LOG_TAG, "HID:createContainer - FingerprintNotEnrolledException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("FingerprintNotEnrolledException", e.getMessage(), exceptionCallback);
		} catch (ServerProtocolException e) {
			Log.d(LOG_TAG, "HID:createContainer - ServerProtocolException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("ServerProtocolException", e.getMessage(), exceptionCallback);
		} catch (ServerAuthenticationException e) {
			Log.d(LOG_TAG, "HID:createContainer - ServerAuthenticationException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("ServerAuthenticationException", e.getMessage(), exceptionCallback);
		} catch (AuthenticationException e) {
			Log.d(LOG_TAG, "HID:createContainer - AuthenticationException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("AuthenticationException", e.getMessage(), exceptionCallback);
		} catch (InvalidPasswordException e) {
			Log.d(LOG_TAG, "HID:createContainer - InvalidPasswordException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("InvalidPasswordException", e.getMessage(), exceptionCallback);
		} catch (PasswordCancelledException e) {
			Log.d(LOG_TAG, "HID:createContainer - PasswordCancelledException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("PasswordCancelledException", e.getMessage(), exceptionCallback);
		} catch (LostCredentialsException e) {
			Log.d(LOG_TAG, "HID:createContainer - LostCredentialsException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("LostCredentialsException", e.getMessage(), exceptionCallback);
		} catch (GooglePlayServicesObsoleteException e) {
			Log.d(LOG_TAG, "HID:createContainer - GooglePlayServicesObsoleteException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("GooglePlayServicesObsoleteException", e.getMessage(), exceptionCallback);
		} catch (ServerOperationFailedException e) {
			Log.d(LOG_TAG, "HID:createContainer - ServerOperationFailedException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("ServerOperationFailedException", e.getMessage(), exceptionCallback);
		}catch (Exception e) {
			Log.d(LOG_TAG, "HID:createContainer - Unhandled Exception" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("Unhandled Exception", e.getMessage(), exceptionCallback);
		}finally {
			Log.d(LOG_TAG, "HID:createContainer - Container Thread completed");
		}
	}

	private void exceptionCallback(String exceptionType, String message, Function callback) {
		Object[] params = new Object[2];
		params[0] = exceptionType;
		params[1] = message;
		try {
			callback.execute(params);
		} catch (Exception e) {
			e.printStackTrace();
			Log.d(LOG_TAG, "HID:createContainer - Unhandled Exception" + e.getStackTrace());
		}
	}

}
