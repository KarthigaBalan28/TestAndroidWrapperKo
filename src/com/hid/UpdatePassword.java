package com.hid;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.hidglobal.ia.service.beans.ConnectionConfiguration;
import com.hidglobal.ia.service.beans.Parameter;
import com.hidglobal.ia.service.exception.AuthenticationException;
import com.hidglobal.ia.service.exception.FingerprintAuthenticationRequiredException;
import com.hidglobal.ia.service.exception.FingerprintNotEnrolledException;
import com.hidglobal.ia.service.exception.InternalException;
import com.hidglobal.ia.service.exception.InvalidParameterException;
import com.hidglobal.ia.service.exception.InvalidPasswordException;
import com.hidglobal.ia.service.exception.LostCredentialsException;
import com.hidglobal.ia.service.exception.PasswordCancelledException;
import com.hidglobal.ia.service.exception.PasswordNotYetUpdatableException;
import com.hidglobal.ia.service.exception.PasswordRequiredException;
import com.hidglobal.ia.service.exception.UnsupportedDeviceException;
import com.hidglobal.ia.service.manager.DeviceFactory;
import com.hidglobal.ia.service.manager.SDKConstants;
import com.hidglobal.ia.service.protectionpolicy.PasswordPolicy;
import com.hidglobal.ia.service.protectionpolicy.ProtectionPolicy;
import com.hidglobal.ia.service.transaction.Container;
import com.hidglobal.ia.service.transaction.ContainerInitialization;
import com.hidglobal.ia.service.transaction.Device;
import com.hidglobal.ia.service.transaction.Key;
import com.konylabs.vm.Function;

import android.content.Context;
import android.util.Log;
@SuppressWarnings({"java:S3776"})
public class UpdatePassword implements Runnable {
	private Context appContext;
	private Function exceptionCallback;
	private String newPassword;
	private String oldPassword;
	private boolean isContainerPolicy;
	private Container container;
	private static final String LOG_TAG = ApproveSDKConstants.HID_LOG_TAG;

	public UpdatePassword(String oldPassword, String newPassword, Context appContext, Function exceptionCallback,
			boolean isContainerPolicy, Container container) {
		this.newPassword = newPassword;
		this.oldPassword = oldPassword;
		this.appContext = appContext;
		this.exceptionCallback = exceptionCallback;
		this.isContainerPolicy = isContainerPolicy;
		this.container = container;
	}

	@Override
	public void run() {
		boolean result = false;
		try {
			Device device = DeviceFactory.getDevice(appContext, null);
			if (isContainerPolicy) {
				PasswordPolicy passwordPolicy = (PasswordPolicy) container.getProtectionPolicy();
				result = passwordPolicy.changePassword(oldPassword.toCharArray(), newPassword.toCharArray());
			} else {
				// Get all the keys in the container
				// Change the password for policy associated with a key,
				Key[] keys = findAllKeys(device);
				// Otherwise, find key by ID as we use different policy for each key
				Set<String> processedPolicies = new HashSet<>();
				for (Key key : keys) {
					ProtectionPolicy policy = key.getProtectionPolicy();
					if ((policy.getType() == ProtectionPolicy.PolicyType.PASSWORD.toString()
							|| policy.getType() == ProtectionPolicy.PolicyType.BIOPASSWORD.toString())
							&& !processedPolicies.contains(policy.getId().getId())) {
						result = ((PasswordPolicy) policy).changePassword(oldPassword.toCharArray(),
								newPassword.toCharArray());
						processedPolicies.add(policy.getId().getId());
					}
				}
			}
			if (result) {
				Log.d(LOG_TAG, "HID:updatePassword - Password has been updated.");
				exceptionCallback("UpdatePassword", "updateSuccess", exceptionCallback);
			} else {
				Log.d(LOG_TAG, "HID:updatePassword - Password update failed.");
				exceptionCallback("UpdatePassword", "updateFailed", exceptionCallback);
			}

		} catch (UnsupportedDeviceException e) {
			Log.d(LOG_TAG, "HID:updatePassword - UnsupportedDeviceException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("UnsupportedDeviceException", e.getMessage(), exceptionCallback);
		} catch (AuthenticationException e) {
			Log.d(LOG_TAG, "HID:updatePassword - AuthenticationException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("AuthenticationException", e.getMessage(), exceptionCallback);
		} catch (InvalidPasswordException e) {
			Log.d(LOG_TAG, "HID:updatePassword - InvalidPasswordException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("InvalidPasswordException", e.getMessage(), exceptionCallback);
		} catch (LostCredentialsException e) {
			Log.d(LOG_TAG, "HID:updatePassword - LostCredentialsException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("LostCredentialsException", e.getMessage(), exceptionCallback);
		} catch (InternalException e) {
			Log.d(LOG_TAG, "HID:updatePassword - InternalException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("InternalException", e.getMessage(), exceptionCallback);
		} catch (PasswordNotYetUpdatableException e) {
			Log.d(LOG_TAG, "HID:updatePassword - PasswordNotYetUpdatableException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("PasswordNotYetUpdatableException", e.getMessage(), exceptionCallback);
		} catch (FingerprintAuthenticationRequiredException e) {
			Log.d(LOG_TAG, "HID:updatePassword - FingerprintAuthenticationRequiredException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("FingerprintAuthenticationRequiredException", e.getMessage(), exceptionCallback);
		} catch (FingerprintNotEnrolledException e) {
			Log.d(LOG_TAG, "HID:updatePassword - FingerprintNotEnrolledException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("FingerprintNotEnrolledException", e.getMessage(), exceptionCallback);
		} catch (PasswordRequiredException e) {
			Log.d(LOG_TAG, "HID:updatePassword - PasswordRequiredException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("PasswordRequiredException", e.getMessage(), exceptionCallback);
		} catch (InvalidParameterException e) {
			Log.d(LOG_TAG, "HID:updatePassword - InvalidParameterException" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("InvalidParameterException", e.getMessage(), exceptionCallback);
		} catch (Exception e) {
			Log.d(LOG_TAG, "HID:updatePassword - Unhandled Exception" + e.getStackTrace());
			e.printStackTrace();
			exceptionCallback("Unhandled Exception", e.getMessage(), exceptionCallback);
		} finally {
			Log.d(LOG_TAG, "HID:updatePassword - UpdatePassword Thread completed");
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
		}
	}

	private static Key[] findAllKeys(Device device) {

		// Find container
		Parameter[] params = new Parameter[0];
		try {
			Container[] containers = device.findContainers(params);
			if (containers != null && containers.length > 0) {

				List<Key> keyList = new ArrayList<>();
				char[][] keyUsageTypes = new char[][] { SDKConstants.KEY_PROPERTY_USAGE_AUTH,
						SDKConstants.KEY_PROPERTY_USAGE_ENCRYPT, SDKConstants.KEY_PROPERTY_USAGE_SIGN,
						SDKConstants.KEY_PROPERTY_USAGE_TXPROTECT, SDKConstants.KEY_PROPERTY_USAGE_OPPRO,
						SDKConstants.KEY_PROPERTY_USAGE_OTP };

				for (char[] keyUsage : keyUsageTypes) {
					Parameter[] filter = new Parameter[] { new Parameter(SDKConstants.KEY_PROPERTY_USAGE, keyUsage) };
					Key[] keys = containers[containers.length - 1].findKeys(filter);
					for (Key key : keys) {
						keyList.add(key);
					}
				}
				return keyList.toArray(new Key[keyList.size()]);
			}
		} catch (LostCredentialsException e) {
			Log.e(LOG_TAG, "HID:updatePassword - LostCredentialsException : " + e.getMessage());
		} catch (UnsupportedDeviceException e) {
			Log.e(LOG_TAG, "HID:updatePassword - UnsupportedDeviceException : " + e.getMessage());
		} catch (InternalException e) {
			Log.e(LOG_TAG, "HID:updatePassword - InternalException : " + e.getMessage());
		} catch (InvalidParameterException e) {
			Log.e(LOG_TAG, "HID:updatePassword - InvalidParameterException : " + e.getMessage());
		} catch (Exception e) {
			Log.e(LOG_TAG, "HID:updatePassword - Cannot find OTP keys : " + e.getMessage());
		}

		return null;
	}

}
