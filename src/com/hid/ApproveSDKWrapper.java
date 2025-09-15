package com.hid;

import java.text.SimpleDateFormat;
import java.util.Date;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.hid.FingerprintHandler.BiometricEventListener;
import com.hidglobal.ia.service.beans.ConnectionConfiguration;
import com.hidglobal.ia.service.beans.KeyId;
import com.hidglobal.ia.service.beans.Parameter;
import com.hidglobal.ia.service.exception.AuthenticationException;
import com.hidglobal.ia.service.exception.FingerprintAuthenticationRequiredException;
import com.hidglobal.ia.service.exception.FingerprintNotEnrolledException;
import com.hidglobal.ia.service.exception.InexplicitContainerException;
import com.hidglobal.ia.service.exception.InternalException;
import com.hidglobal.ia.service.exception.InvalidContainerException;
import com.hidglobal.ia.service.exception.InvalidParameterException;
import com.hidglobal.ia.service.exception.InvalidPasswordException;
import com.hidglobal.ia.service.exception.LostCredentialsException;
import com.hidglobal.ia.service.exception.PasswordRequiredException;
import com.hidglobal.ia.service.exception.PasswordExpiredException;
import com.hidglobal.ia.service.exception.RemoteException;
import com.hidglobal.ia.service.exception.ServerAuthenticationException;
import com.hidglobal.ia.service.exception.ServerOperationFailedException;
import com.hidglobal.ia.service.exception.ServerUnsupportedOperationException;
import com.hidglobal.ia.service.exception.TransactionCanceledException;
import com.hidglobal.ia.service.exception.TransactionExpiredException;
import com.hidglobal.ia.service.exception.UnsupportedDeviceException;
import com.hidglobal.ia.service.manager.DeviceFactory;
import com.hidglobal.ia.service.manager.SDKConstants;
import com.hidglobal.ia.service.protectionpolicy.BioAuthenticationState;
import com.hidglobal.ia.service.protectionpolicy.BioPasswordPolicy;
import com.hidglobal.ia.service.protectionpolicy.PasswordPolicy;
import com.hidglobal.ia.service.protectionpolicy.ProtectionPolicy;
import com.hidglobal.ia.service.transaction.Container;
import com.hidglobal.ia.service.transaction.Device;
import com.hidglobal.ia.service.transaction.Key;
import com.hidglobal.ia.service.transaction.ServerActionInfo;
import com.hidglobal.ia.service.transaction.Transaction;
import com.hidglobal.ia.service.transaction.CancelationReason;
import com.konylabs.vm.Function;

import android.content.Context;
import android.text.format.DateFormat;
import android.util.Log;
import androidx.fragment.app.FragmentActivity;

public class ApproveSDKWrapper {
	private WaitNotifyMonitor monitor;
	private TransactionMonitor transactionMonitor;
	private Container container;
	private Context appContext;
	private static final String LOG_TAG = ApproveSDKConstants.LOG_TAG;
	private WaitNotifyMonitor signTransactionMonitor;
	private WaitNotifyMonitor notificationMonitor;
	private Transaction notificationTransaction;
	private String username;
	private FragmentActivity activity;

	/**
	 * This public method is used to create the container.
	 * 
	 * @param activationCode    - ActivationCode/Provision String to create the container.
	 * @param appContext        - Context of the application.
	 * @param pushId            - Push ID to be set for the container.
	 * @param promptCallback    - Callback to handle the prompt.
	 * @param exceptionCallback - Callback to handle exceptions.
	 * 
	 */
	public void createContainer(String activationCode, Context appContext, String pushId, Function promptCallback,
			Function exceptionCallback) {
		this.monitor = new WaitNotifyMonitor();
		this.appContext = appContext;
		ContainerCreatorAsync containerCreatorAsync = new ContainerCreatorAsync(activationCode, appContext, pushId,
				promptCallback, exceptionCallback, monitor);
		Thread thread = new Thread(containerCreatorAsync);
		thread.start();
	}

	/**
	 * This public method is used to set the Username.
	 * 
	 * @param username - Username to be set.
	 */
	public void setUsername(String username) {
		if (username != null) {
			Log.d(LOG_TAG, "HID:setUsername - Username from component is " + username);
			this.username = username;
		}
	}

	/**
	 * This public method is used to renew the user container.
	 * 
	 * @param password          - Password to renew the container, pass "" if
	 *                          biometrics are enabled.
	 * @param appContext        - Context of the application.
	 * @param activity          - FragmentActivity.
	 * @param promptCallback    - Callback to handle the prompt.
	 * @param exceptionCallback - Callback to handle exceptions.
	 * 
	 */
	public void renewContainer(String password, Context appContext, FragmentActivity activity, Function promptCallback,
			Function exceptionCallback) {
		boolean isBioEnabled = checkForBioAvailability();
		this.monitor = new WaitNotifyMonitor();
		ContainerRenewAsync containerRenewAsync = new ContainerRenewAsync(password, appContext, activity, isBioEnabled,
				promptCallback, exceptionCallback, getSingleUserContainer());
		Thread thread = new Thread(containerRenewAsync);
		if (isBioEnabled) {
			containerRenewAsync.setBiometricEventListener(new BiometricEventListener() {
				@Override
				public void onAuthSuccess() {

				}

				@Override
				public void onAuthFailed() {

				}

				@Override
				public void onAuthError() {
					// TODO Auto-generated method stub

				}
			});
		}
		thread.start();
	}

	/**
	 * This private method is used to get the the Password/Pin Policy for the
	 * container.
	 * 
	 * @param appContext - Context of the application.
	 * @return String - JSON String containing the Password/Pin Policy details.
	 */
	public String getPasswordPolicy(Context appContext) {
		Log.d(LOG_TAG, "HID:getPasswordPolicy");
		this.appContext = appContext;
		Container container = getSingleUserContainer();
		int ProfileExpiryDays = getContainerRenewableDate();
		JSONObject obj = new JSONObject();
		try {
			ProtectionPolicy policy = container.getProtectionPolicy();
			PasswordPolicy passwordPolicy = (PasswordPolicy) policy;
			Log.d(LOG_TAG, "HID:getPasswordPolicy policy instanceof PasswordPolicy");
			obj.put("maxAge", passwordPolicy.getMaxAge());
			obj.put("currentAge", passwordPolicy.getCurrentAge());
			obj.put("minAge", passwordPolicy.getMinAge());
			obj.put("minLength", passwordPolicy.getMinLength());
			obj.put("maxLength", passwordPolicy.getMaxLength());
			obj.put("minNumeric", passwordPolicy.getMinNumeric());
			obj.put("maxNumeric", passwordPolicy.getMaxNumeric());
			obj.put("minAlpha", passwordPolicy.getMinAlpha());
			obj.put("maxAlpha", passwordPolicy.getMaxAlpha());
			obj.put("maxUpperCase", passwordPolicy.getMaxUpperCase());
			obj.put("minUpperCase", passwordPolicy.getMinUpperCase());
			obj.put("maxLowerCase", passwordPolicy.getMaxLowerCase());
			obj.put("minLowerCase", passwordPolicy.getMinLowerCase());
			obj.put("maxSpl", passwordPolicy.getMaxNonAlpha());
			obj.put("minSpl", passwordPolicy.getMinNonAlpha());
			obj.put("isSequenceAllowed", passwordPolicy.isSequenceAllowed());
			obj.put("profileExpiryDate", ProfileExpiryDays + "");
			Log.d(LOG_TAG, "HID:getPasswordPolicy - PasswordPolicy is " + obj.toString());
			return obj.toString();
		} catch (JSONException e2) {
			// TODO Auto-generated catch block
			Log.d(LOG_TAG, "HID:getPasswordPolicy: JSONException" + e2.getStackTrace());
			e2.printStackTrace();
		} catch (UnsupportedDeviceException e) {
			Log.d(LOG_TAG, "HID:getPasswordPolicy: UnsupportedDeviceException" + e.getStackTrace());
			e.printStackTrace();
		} catch (InternalException e) {
			Log.d(LOG_TAG, "HID:getPasswordPolicy: InternalException" + e.getStackTrace());
			e.printStackTrace();
		} catch (LostCredentialsException e) {
			Log.d(LOG_TAG, "HID:getPasswordPolicy: LostCredentialsException" + e.getStackTrace());
			e.printStackTrace();
		} catch (Exception e) {
			Log.d(LOG_TAG, "HID:getPasswordPolicy: Exception" + e.getStackTrace());
			e.printStackTrace();
		}
		return obj.toString();
	}

	/**
	 * This public method is used to update the Password/Pin for the container.
	 * 
	 * @param oldPassword       - Old Password/Pin of the container.
	 * @param newPassword       - New Password/Pin to be set for the container.
	 * @param appContext        - Context of the application.
	 * @param exceptionCallback - Callback to handle exceptions
	 * @param isContainerPolicy - Boolean to check the container policy is present
	 *                          or not
	 * 
	 */
	public void updatePassword(String oldPassword, String newPassword, Context appContext, Function exceptionCallback,
			Boolean isContainerPolicy) {
		UpdatePassword updatePassword = new UpdatePassword(oldPassword, newPassword, appContext, exceptionCallback,
				isContainerPolicy, getSingleUserContainer());
		Thread thread = new Thread(updatePassword);
		thread.start();
	}

	/**
	 * This public method is used to get the container renewable date.
	 * 
	 * @return int - Number of days left for the container to be renewable.
	 */
	public int getContainerRenewableDate() {
		Container container = getSingleUserContainer();
		Log.d(LOG_TAG, "HID In getContainerRenewableDate");
		Date containerRenewalDate = container.getRenewalDate();
		Log.d(LOG_TAG, "HID:getContainerRenewableDate containerRenewalDate" + containerRenewalDate.toString());
		long containerStart = container.getCreationDate().getTime();
		Log.d(LOG_TAG, "HID:getContainerRenewableDate containerStart" + containerStart);
		long containerExpiry = container.getExpiryDate().getTime();
		Log.d(LOG_TAG, "HID:getContainerRenewableDate containerExpiry" + containerExpiry);
		int endDays = getDaysFromMilli(getWrtCurrentTime(containerExpiry));
		int totalDays = getDaysFromMilli(Math.abs(containerExpiry - containerStart));
		return calFinalDays(totalDays, endDays);
	}

	/**
	 * This private method is used to calculate the final days left for the
	 * container to be renewable.
	 * 
	 * @param total - Total number of days from container creation to expiry.
	 * @param end   - Number of days left from current date to expiry.
	 * @return int - Number of days left for the container to be renewable.
	 */
	private int calFinalDays(int total, int end) {
		Log.d(LOG_TAG, "HID:getContainerRenewableDate calFinalDays Total Days is " + total);
		Log.d(LOG_TAG, "HID:getContainerRenewableDate calFinalDays End Days is " + end);
		float perc = ((float) end / (float) total) * 100;
		Log.d(LOG_TAG, "HID:getContainerRenewableDate calFinalDays Percentage is " + perc);
		if (end <= 2 || perc < 20.0f)
			return end; // if 2 or fewer days are left || percentage is in last 20% of expiry time

		Log.d(LOG_TAG, "HID:getContainerRenewableDate calFinalDays Returning " + (-1 * end));
		return -1 * end;
	}

	/**
	 * This private method is used to get the number of days from milliseconds.
	 * 
	 * @param milliSeconds - Time in milliseconds.
	 * @return int - Number of days from milliseconds.
	 */
	private int getDaysFromMilli(long milliSeconds) {
		return (int) (milliSeconds / (1000 * 60 * 60 * 24));
	}

	/**
	 * This private method is used to get the absolute difference between the given
	 * time and the current system time in milliseconds.
	 * 
	 * @param time - Time in milliseconds to compare with the current system time.
	 * @return long - Returns the absolute difference between the given time and the
	 *         current system time in milliseconds.
	 */
	private long getWrtCurrentTime(long time) {
		long currentMilli = System.currentTimeMillis();
		Log.d(LOG_TAG, "HID:getContainerRenewableDate getWrtCurrentTime currentMilli" + currentMilli);
		return Math.abs(time - currentMilli);
	}

	/**
	 * This private method is used to check whether the container is renewable or
	 * not.
	 * 
	 * @param container - Container to check if it is renewable.
	 * @return Boolean true if renewable, false otherwise
	 */
	private Boolean isContainerRenewable(Container container) {
		if (container.isRenewable(null)) {
			return true;
		}
		return false;
	}

	/**
	 * This public method is used to set the Password/Pin for the User.
	 * 
	 * @param password - Password/Pin to be set for the User.
	 */
	public void setPasswordForUser(String password) {
		synchronized (monitor) {
			monitor.setMsg(password);
			monitor.notify();
		}
	}

	/**
	 * This public method is used to get the Login Flow whether the User is
	 * registered or not and if registered how many containers are present.
	 * 
	 * @param appContext             - Context of the application.
	 * @param pushID                 - Push ID to be set for the container, can be
	 *                               null or empty.
	 * @param genericExecuteCallback - Callback to handle the exceptions.
	 * 
	 * @return String ("Register" if not registered, "SingleLogin,userId" if single
	 *         container exists, "MultiLogin,userId1|userId2|..." if multiple
	 *         containers exist)
	 */
	public String getLoginFlow(Context appContext, String pushID, Function genericExecuteCallback)
			throws InvalidPasswordException, FingerprintNotEnrolledException, PasswordRequiredException {
		try {
			Device device = DeviceFactory.getDevice(appContext, new ConnectionConfiguration());
			Container[] containers = device.findContainers(new Parameter[0]);
			this.appContext = appContext;
			if (containers.length == 0) {
				return "Register";
			}
			if (containers.length == 1) {
				Log.d(LOG_TAG, "HID:getLoginFlow Single container exist");
				Log.d("ApproveSDKWrapper", "HID:getLoginFlow Single container: " + containers.toString());
		        Log.d("ApproveSDKWrapper", "HID:getLoginFlow Single container getUserId: " + containers[0].getUserId());
				container = containers[0];
				
				this.getInfo(appContext);
				this.getKeyList();
				
				if (pushID != null && !pushID.isEmpty()) {
					Log.d(LOG_TAG, "HID:getLoginFlow PushID is ---> " + pushID);
					container.updateDeviceInfo(SDKConstants.DEVICE_INFO_PUSHID, pushID.toCharArray(), null, null);
					Log.d(LOG_TAG, "PushID updated");
				}
				Log.d(LOG_TAG, "HID:getLoginFlow Single container: " + containers[0].getUserId());
				
				return "SingleLogin," + containers[0].getUserId();
			}
			StringBuffer multiUsers = new StringBuffer("MultiLogin,");
			for (Container c : containers) {
				multiUsers.append(c.getUserId() + "|");
				Log.d(LOG_TAG, "HID:getLoginFlow Multi container exist" + c.getUserId());
			}
			Log.d(LOG_TAG, "HID:getLoginFlow Multi container: " + multiUsers.toString());
			
			return multiUsers.substring(0, multiUsers.length() - 1);
		} catch (UnsupportedDeviceException e) {
			Log.d(LOG_TAG, "HID:getLoginFlow: UnsupportedDeviceException" + e.getStackTrace());
			genericExecuteCallback("UnsupportedDeviceException", e.getMessage(), genericExecuteCallback);
			e.printStackTrace();
		} catch (InternalException e) {
			Log.d(LOG_TAG, "HID:getLoginFlow: InternalException" + e.getStackTrace());
			genericExecuteCallback("InternalException", e.getMessage(), genericExecuteCallback);
			e.printStackTrace();
		} catch (LostCredentialsException e) {
			Log.d(LOG_TAG, "HID:getLoginFlow: LostCredentialsException" + e.getStackTrace());
			genericExecuteCallback("LostCredentialsException", e.getMessage(), genericExecuteCallback);
			e.printStackTrace();
		} catch (AuthenticationException e) {
			Log.d(LOG_TAG, "HID:getLoginFlow: AuthenticationException" + e.getStackTrace());
			genericExecuteCallback("AuthenticationException", e.getMessage(), genericExecuteCallback);
			e.printStackTrace();
		} catch (FingerprintAuthenticationRequiredException e) {
			Log.d(LOG_TAG, "HID:getLoginFlow: FingerprintAuthenticationRequiredException" + e.getStackTrace());
			genericExecuteCallback("FingerprintAuthenticationRequiredException", e.getMessage(),
					genericExecuteCallback);
			e.printStackTrace();
		} catch (RemoteException e) {
			Log.d(LOG_TAG, "HID:getLoginFlow: RemoteException" + e.getStackTrace());
			genericExecuteCallback("RemoteException", e.getMessage(), genericExecuteCallback);
			e.printStackTrace();
		} catch (InvalidParameterException e) {
			Log.d(LOG_TAG, "HID:getLoginFlow: InvalidParameterException" + e.getStackTrace());
			genericExecuteCallback("InvalidParameterException", e.getMessage(), genericExecuteCallback);
			e.printStackTrace();
		} catch (ServerOperationFailedException e) {
			Log.d(LOG_TAG, "HID:getLoginFlow: ServerOperationFailedException" + e.getStackTrace());
			genericExecuteCallback("ServerOperationFailedException", e.getMessage(), genericExecuteCallback);
			e.printStackTrace();
		} catch (Exception e) {
			Log.d(LOG_TAG, "HID:getLoginFlow: Exception" + e.getStackTrace());
			genericExecuteCallback("Unhandled Exception", e.getMessage(), genericExecuteCallback);
			e.printStackTrace();
		}
		return "Error";
	}

	/**
	 * This public method is used to generate the OTP.
	 * 
	 * @param activity           - FragmentActivity to run the OTP generation in.
	 * @param password           - Password to be used for OTP generation, pass ""
	 *                           if biometrics are enabled.
	 * @param isBiometricEnabled - Boolean to check if biometrics are enabled or
	 *                           not.
	 * @param otpSuccessCallback - Callback to handle the success response.
	 * @param otpFailureCallback - Callback to handle the failure response.
	 * @param otpLabel           - The label for the OTP key, can be "HOTP" or
	 *                           "TOTP".
	 */
	public void generateOTP(FragmentActivity activity, String password, boolean isBiometricEnabled,
			Function otpSuccessCallback, Function otpFailureCallback, String otpLabel) {
		String label = OtpKeyLabel.HOTP_KEY_LABEL.getCode();
		if (otpLabel.toLowerCase().equals(ApproveSDKConstants.TOTP_KEY)) {
			label = OtpKeyLabel.TOTP_KEY_LABEL.getCode();
		}
		generateOTPWrap(activity, password, isBiometricEnabled, otpSuccessCallback, otpFailureCallback, label);
	}

	/**
	 * This public method is used to generate the OTP for HOTP - OATH_event.
	 * 
	 * @param activity           - FragmentActivity to run the OTP generation in.
	 * @param password           - Password to be used for OTP generation, pass ""
	 *                           if biometrics are enabled.
	 * @param isBiometricEnabled - Boolean to check if biometrics are enabled or
	 *                           not.
	 * @param otpSuccessCallback - Callback to handle the success response.
	 * @param otpFailureCallback - Callback to handle the failure response.
	 */
	public void generateOTP(FragmentActivity activity, String password, boolean isBiometricEnabled,
			Function otpSuccessCallback, Function otpFailureCallback) {
		generateOTPWrap(activity, password, isBiometricEnabled, otpSuccessCallback, otpFailureCallback,
				OtpKeyLabel.HOTP_KEY_LABEL.getCode());
	}

	/**
	 * This private method is used to generate the OTP.
	 * 
	 * @param activity           - FragmentActivity to run the OTP generation in.
	 * @param password           - Password to be used for OTP generation, pass ""
	 *                           if biometrics are enabled.
	 * @param isBiometricEnabled - Boolean to check if biometrics are enabled or
	 *                           not.
	 * @param otpSuccessCallback - Callback to handle the success response.
	 * @param otpFailureCallback - Callback to handle the failure response.
	 * @param otpLabel           - The label for the OTP key will be set in
	 *                           accordance with TOTP or HOTP.
	 */
	private void generateOTPWrap(FragmentActivity activity, String password, boolean isBiometricEnabled,
			Function otpSuccessCallback, Function otpFailureCallback, String otpLabel) {
		OTPGeneratorSync generate;
		try {
			getPasswordPolicy(appContext);
			String lockPolicyType = getLockPolicy(otpLabel, ApproveSDKConstants.CODE_SECURE);
			Log.d(LOG_TAG, "HID:generateOTP - lockPolicyType: " + lockPolicyType);
			generate = new OTPGeneratorSync(activity, password, isBiometricEnabled, otpSuccessCallback,
					otpFailureCallback, getSingleUserContainer(), otpLabel);
			Thread thread = new Thread(generate);
			if (isBiometricEnabled) {
				generate.setBiometricEventListener(new BiometricEventListener() {
					@Override
					public void onAuthSuccess() {
//						Thread thread = new Thread(generate);
//						thread.start();
					}

					@Override
					public void onAuthFailed() {

					}

					@Override
					public void onAuthError() {
						// TODO Auto-generated method stub

					}
				});
			}
			thread.start();
		} catch (InternalException e) {
			Log.d(LOG_TAG, "HID:generateOTP: InternalException" + e.getStackTrace());
			e.printStackTrace();
		} catch (Exception e) {
			Log.d(LOG_TAG, "HID:generateOTP: Exception" + e.getStackTrace());
			e.printStackTrace();
		}
	}

	/**
	 * This public method is used to enable the Biometrics.
	 * 
	 * @param password          - Password to be used for enabling the biometrics.
	 * @param bioStatusCallback to fetch the biometric status
	 * 
	 */
	public void enableBioMetrics(String password, Function bioStatusCallback) {
		this.container = getSingleUserContainer();
		boolean state = BiometricUtils.isDeviceFingerPrintEnrolled(appContext);
		if (state) {
			Log.d(LOG_TAG, "HID:enableBioMetrics FingerPrint Enrolled");
			try {
				ProtectionPolicy policy = this.container.getProtectionPolicy();
				BioPasswordPolicy bioPasswordPolicy = (BioPasswordPolicy) policy;
				if (bioPasswordPolicy != null) {
					if (password == null) {
						bioPasswordPolicy.disableBioAuthentication();
						Log.d(LOG_TAG, "HID:enableBioMetrics Biometric support is disabled for policy :"
								+ bioPasswordPolicy.getId());
					} else {
						bioPasswordPolicy.enableBioAuthentication(password.toCharArray());
						Log.d(LOG_TAG, "HID:enableBioMetrics Biometric support is enabled for policy : "
								+ bioPasswordPolicy.getId());
					}
					boolean isEnabled = bioPasswordPolicy.getBioAuthenticationState() == BioAuthenticationState.ENABLED;
					Log.d(LOG_TAG, "HID:enableBioMetrics getBioAuthenticationState " + isEnabled);
					Log.d(LOG_TAG, "HID:enableBioMetrics BioPasswordPolicy getBioAuthenticationState: "
							+ bioPasswordPolicy.getBioAuthenticationState());
					executeBioStatusCallback(bioStatusCallback, isEnabled, "Success");
				} else {
					boolean isEnabled = false;
					String message = "Policy does not support biometric";
					executeBioStatusCallback(bioStatusCallback, isEnabled, message);
				}
			} catch (AuthenticationException e) {
				executeBioStatusCallback(bioStatusCallback, false, "PIN is incorrect");
				Log.d(LOG_TAG, "HID:enableBioMetrics: AuthenticationException" + e.getStackTrace());
			} catch (UnsupportedDeviceException e) {
				executeBioStatusCallback(bioStatusCallback, false, "UnsupportedDeviceException");
				Log.d(LOG_TAG, "HID:enableBioMetrics: UnsupportedDeviceException" + e.getStackTrace());
			} catch (InternalException e) {
				executeBioStatusCallback(bioStatusCallback, false, "InternalException");
				Log.d(LOG_TAG, "HID:enableBioMetrics: InternalException" + e.getStackTrace());
			} catch (LostCredentialsException e) {
				executeBioStatusCallback(bioStatusCallback, false, "LostCredentialsException");
				Log.d(LOG_TAG, "HID:enableBioMetrics: LostCredentialsException" + e.getStackTrace());
			} catch (FingerprintNotEnrolledException e) {
				executeBioStatusCallback(bioStatusCallback, false, "FingerprintNotEnrolledException");
				Log.d(LOG_TAG, "HID:enableBioMetrics: FingerprintNotEnrolledException" + e.getStackTrace());
			} catch (FingerprintAuthenticationRequiredException e) {
				executeBioStatusCallback(bioStatusCallback, false, "FingerprintAuthenticationRequiredException");
				Log.d(LOG_TAG, "HID:enableBioMetrics: FingerprintAuthenticationRequiredException" + e.getStackTrace());
			} catch (PasswordExpiredException e) {
				executeBioStatusCallback(bioStatusCallback, false, "PasswordExpiredException");
				Log.d(LOG_TAG, "HID:enableBioMetrics: PasswordExpiredException" + e.getStackTrace());
			} catch (Throwable t) {
				Log.e(LOG_TAG, "HID:enableBioMetrics: Exception" + t.getStackTrace());
				boolean isEnabled = false;
				String message = "Biometric enrollment got failed";
				executeBioStatusCallback(bioStatusCallback, isEnabled, message);
				t.printStackTrace();
			}
		} else {
			executeBioStatusCallback(bioStatusCallback, false, "Device does not support biometric");
			Log.d(LOG_TAG, "HID:enableBioMetrics: Device does not support biometric");
		}
	}

	/**
	 * This public method is used to check the availability of Biometrics
	 * 
	 * @return boolean value "true" or "false"
	 */
	public boolean checkForBioAvailability() {
		try {
			boolean state = BiometricUtils.isDeviceFingerPrintEnrolled(this.appContext);
			if (!state) {
				Log.d(LOG_TAG, "HID:checkForBioAvailability Fingerprint Not enrolled");
				return false;
			}
			ProtectionPolicy policy = getSingleUserContainer().getProtectionPolicy();
			BioPasswordPolicy bioPasswordPolicy = (BioPasswordPolicy) policy;
			if (!(policy.getType().equals(ProtectionPolicy.PolicyType.BIOPASSWORD.name()))) {
				Log.d(LOG_TAG, "HID:checkForBioAvailability Bio Policy Not present");
				return false;
			}
			if (bioPasswordPolicy.getBioAuthenticationState().equals(BioAuthenticationState.ENABLED)) {
				Log.d(LOG_TAG, "HID:checkForBioAvailability Bio Policy enabled");
				return true;
			}
			if (bioPasswordPolicy.getBioAuthenticationState().equals(BioAuthenticationState.INVALID_KEY)) {
				Log.d(LOG_TAG, "HID:checkForBioAvailability Bio Policy key has been invalidated");
				return false;
			}
			if (bioPasswordPolicy.getBioAuthenticationState().equals(BioAuthenticationState.NOT_CAPABLE)) {
				Log.d(LOG_TAG, "HID:checkForBioAvailability Bio Policy with the current device is not possible.");
				return false;
			}
			if (bioPasswordPolicy.getBioAuthenticationState().equals(BioAuthenticationState.NOT_ENABLED)) {
				Log.d(LOG_TAG, "HID:checkForBioAvailability Bio Policy Not enabled.");
				return false;
			}
			if (bioPasswordPolicy.getBioAuthenticationState().equals(BioAuthenticationState.NOT_ENROLLED)) {
				Log.d(LOG_TAG, "HID:checkForBioAvailability Biometric Feature in Device is not enrolled.");
				return false;
			}
		} catch (UnsupportedDeviceException e) {
			Log.d(LOG_TAG, "HID:checkForBioAvailability: UnsupportedDeviceException" + e.getStackTrace());
			e.printStackTrace();
		} catch (InternalException e) {
			Log.d(LOG_TAG, "HID:checkForBioAvailability: InternalException" + e.getStackTrace());
			e.printStackTrace();
		} catch (LostCredentialsException e) {
			Log.d(LOG_TAG, "HID:checkForBioAvailability: LostCredentialsException" + e.getStackTrace());
			e.printStackTrace();
		} catch (Throwable t) {
			Log.d(LOG_TAG, "HID:checkForBioAvailability: Exception" + t.getStackTrace());
			t.printStackTrace();
		}
		return false;
	}

	/**
	 * This public method is used to check the availability of Biometrics
	 * 
	 * @param appContext - Context of the application.
	 * @return boolean value "true" or "false"
	 */
	public boolean checkForBioAvailability(Context appContext) {
		this.appContext = appContext;
		try {
			boolean state = BiometricUtils.isDeviceFingerPrintEnrolled(appContext);
			if (!state) {
				Log.d(LOG_TAG, "HID:checkForBioAvailability Fingerprint Not enrolled");
				return false;
			}
			ProtectionPolicy policy = getSingleUserContainer().getProtectionPolicy();
			BioPasswordPolicy bioPasswordPolicy = (BioPasswordPolicy) policy;
			if (!(policy.getType().equals(ProtectionPolicy.PolicyType.BIOPASSWORD.name()))) {
				Log.d(LOG_TAG, "HID:checkForBioAvailability Bio Policy Not present");
				return false;
			}
			Log.d(LOG_TAG, "HID:checkForBioAvailability In checkForBioAvailability: "
					+ bioPasswordPolicy.getBioAuthenticationState());
			if (bioPasswordPolicy.getBioAuthenticationState().equals(BioAuthenticationState.ENABLED)) {
				Log.d(LOG_TAG, "HID:checkForBioAvailability Bio Policy enabled.");
				return true;
			}
			if (bioPasswordPolicy.getBioAuthenticationState().equals(BioAuthenticationState.INVALID_KEY)) {
				Log.d(LOG_TAG, "HID:checkForBioAvailability Bio Policy key has been invalidated.");
				return false;
			}
			if (bioPasswordPolicy.getBioAuthenticationState().equals(BioAuthenticationState.NOT_CAPABLE)) {
				Log.d(LOG_TAG, "HID:checkForBioAvailability Bio Policy with the current device is not possible.");
				return false;
			}
			if (bioPasswordPolicy.getBioAuthenticationState().equals(BioAuthenticationState.NOT_ENABLED)) {
				Log.d(LOG_TAG, "HID:checkForBioAvailability Bio Policy Not enabled.");
				return false;
			}
			if (bioPasswordPolicy.getBioAuthenticationState().equals(BioAuthenticationState.NOT_ENROLLED)) {
				Log.d(LOG_TAG, "HID:checkForBioAvailability Biometric Feature in Device is not enrolled.");
				return false;
			}
		} catch (UnsupportedDeviceException e) {
			Log.d(LOG_TAG, "HID:checkForBioAvailability: UnsupportedDeviceException " + e.getStackTrace());
			e.printStackTrace();
		} catch (InternalException e) {
			Log.d(LOG_TAG, "HID:checkForBioAvailability: InternalException " + e.getStackTrace());
			e.printStackTrace();
		} catch (LostCredentialsException e) {
			Log.d(LOG_TAG, "HID:checkForBioAvailability: LostCredentialsException " + e.getStackTrace());
			e.printStackTrace();
		} catch (Throwable t) {
			Log.d(LOG_TAG, "HID:checkForBioAvailability: Exception " + t.getStackTrace());
			t.printStackTrace();
		}
		return false;
	}

	/**
	 * This public method is used to disable the Biometrics
	 * 
	 */
	public void disableBioMetrics() {
		this.container = getSingleUserContainer();
		try {
			ProtectionPolicy policy = this.container.getProtectionPolicy();
			BioPasswordPolicy bioPasswordPolicy = (BioPasswordPolicy) policy;
			if (bioPasswordPolicy != null) {
				bioPasswordPolicy.disableBioAuthentication();
				Log.d(LOG_TAG,
						"HID:disableBioMetrics Biometric support is disabled for policy :" + bioPasswordPolicy.getId());
			}
		} catch (UnsupportedDeviceException e) {
			Log.d(LOG_TAG, "HID:disableBioMetrics: UnsupportedDeviceException " + e.getStackTrace());
			e.printStackTrace();
		} catch (InternalException e) {
			Log.d(LOG_TAG, "HID:disableBioMetrics: InternalException " + e.getStackTrace());
			e.printStackTrace();
		} catch (LostCredentialsException e) {
			Log.d(LOG_TAG, "HID:disableBioMetrics: LostCredentialsException " + e.getStackTrace());
			e.printStackTrace();
		} catch (FingerprintNotEnrolledException e) {
			Log.d(LOG_TAG, "HID:disableBioMetrics: FingerprintNotEnrolledException " + e.getStackTrace());
			e.printStackTrace();
		} catch (FingerprintAuthenticationRequiredException e) {
			Log.d(LOG_TAG, "HID:disableBioMetrics: FingerprintAuthenticationRequiredException " + e.getStackTrace());
			e.printStackTrace();
		} catch (AuthenticationException e) {
			Log.d(LOG_TAG, "HID:disableBioMetrics: AuthenticationException " + e.getStackTrace());
			e.printStackTrace();
		} catch (PasswordExpiredException e) {
			Log.d(LOG_TAG, "HID:disableBioMetrics: PasswordExpiredException " + e.getStackTrace());
			e.printStackTrace();
		} catch (Throwable t) {
			Log.d(LOG_TAG, "HID:disableBioMetrics: Exception " + t.getStackTrace());
			t.printStackTrace();
		}
	}

	/**
	 * This private method is used to check the multi user bio status.
	 * 
	 * @return boolean indicating whether the device is multi user or not.
	 */
	private boolean checkMultiUserBioStatus() {
		Device device;
		try {
			device = DeviceFactory.getDevice(appContext, new ConnectionConfiguration());
			Container[] containers = device.findContainers(new Parameter[0]);
			for (Container container : containers) {
				ProtectionPolicy policy = container.getProtectionPolicy();
				BioPasswordPolicy bioPasswordPolicy = (BioPasswordPolicy) policy;
				if (bioPasswordPolicy.getBioAuthenticationState().equals(BioAuthenticationState.ENABLED)) {
					return true;
				}
			}
		} catch (Throwable t) {
			// TODO Auto-generated catch block
			t.printStackTrace();
			return false;
		}

		return false;
	}

	/**
	 * This private method is used to execute a bio status callback with parameters.
	 * 
	 * @param bioStatusCallback - Callback to handle the biometric status.
	 * @param status            - Boolean indicating the status of the biometric
	 *                          operation.
	 * @param message           - String message to be passed to the callback.
	 */
	private void executeBioStatusCallback(Function bioStatusCallback, boolean status, String message) {
		Object[] obj = new Object[2];
		obj[0] = status;
		obj[1] = message;
		try {
			bioStatusCallback.execute(obj);
		} catch (Throwable t) {
			Log.e(LOG_TAG, "HID:executeBioStatusCallback Exception in executeBioStatusCallback " + t.getStackTrace());
			t.printStackTrace();
		}
	}

	/**
	 * This private method is used to get the single user container.
	 * 
	 * @return Container - representing the present container.
	 */
	private Container getSingleUserContainer() {
		Parameter[] filter = this.username != null && !this.username.isEmpty()
				? new Parameter[] { new Parameter(SDKConstants.CONTAINER_USERID, this.username.toCharArray()) }
				: new Parameter[0];
		Container container = null;
		try {
			Device device = DeviceFactory.getDevice(appContext, new ConnectionConfiguration());
			Container[] containers = device.findContainers(filter);
			Log.d("ApproveSDKWrapper", "HID:getSingleUserContainer - container: " + containers.toString());
		    Log.d("ApproveSDKWrapper", "HID:getSingleUserContainer - containers length: " + containers.length);
		    Log.d("ApproveSDKWrapper", "HID:getSingleUserContainer - containers[0] userId: " + containers[0].getUserId());
			container = containers[0];
		} catch (InternalException t) {
			Log.e(LOG_TAG, "HID:getSingleUserContainer InternalException " + t.getStackTrace());
			t.printStackTrace();
		} catch (UnsupportedDeviceException t) {
			Log.e(LOG_TAG, "HID:getSingleUserContainer UnsupportedDeviceException " + t.getStackTrace());
			t.printStackTrace();
		} catch (InvalidParameterException t) {
			Log.e(LOG_TAG, "HID:getSingleUserContainer InvalidParameterException " + t.getStackTrace());
			t.printStackTrace();
		} catch (Throwable t) {
			Log.e(LOG_TAG, "HID:getSingleUserContainer Exception " + t.getStackTrace());
			t.printStackTrace();
		}
		return container;
	}

	/**
	 * This private method is used to execute a callback with parameters.
	 * 
	 * @param tag      - Tag for the callback.
	 * @param message  - Message for the callback.
	 * @param callback - Callback function to be executed.
	 */
	private void genericExecuteCallback(String tag, String message, Function callback) {
		Object[] params = new Object[2];
		params[0] = tag;
		params[1] = message;
		try {
			callback.execute(params);
		} catch (Exception e) {
			Log.e(LOG_TAG, "HID:genericExecuteCallback Exception in genericExecuteCallback " + e.getStackTrace());
			e.printStackTrace();
		}
	}

	/**
	 * This private method is used to execute a callback with parameters.
	 * 
	 * @param params   - Array of parameters to be passed to the callback.
	 * @param callback - Callback function to be executed.
	 */
	private void genericExecuteCallback(Object[] params, Function callback) {
		try {
			callback.execute(params);
		} catch (Exception e) {
			Log.e(LOG_TAG, "HID:genericExecuteCallback Exception in genericExecuteCallback " + e.getStackTrace());
			e.printStackTrace();
		}
	}

	/**
	 * This public method is used to sign a transaction.
	 * 
	 * @param transactionDetails  - Details of the transaction to be signed.
	 * @param pwdPromptCallback   - Callback function to prompt for password.
	 * @param sCB_signTransacion  - Callback function for successful response.
	 * @param fCB_signTransaction - Callback function for failed response.
	 * @param appContext          - Context of the application.
	 * @param activity            - FragmentActivity to run the transaction signing
	 *                            in.
	 * @param otpLabel            - The label for the OTP key, can be "HOTP" or
	 *                            "TOTP".
	 */
	public void signTransaction(String transactionDetails, Function pwdPromptCallback, Function sCB_signTransacion,
			Function fCB_signTransaction, Context appContext, FragmentActivity activity, String otpLabel) {
		String label = OtpKeyLabel.OATH_OCRA_HOTP_SIGN_LABEL.getCode();
		if (otpLabel.toLowerCase().equals(ApproveSDKConstants.TOTP_KEY)) {
			label = OtpKeyLabel.OATH_OCRA_TOTP_SIGN_LABEL.getCode();
		}
		signTransactionWrap(transactionDetails, pwdPromptCallback, sCB_signTransacion, fCB_signTransaction, appContext,
				activity, label);
	}

	/**
	 * This public method is used to sign a transaction with default OCRA HOTP
	 * label.
	 * 
	 * @param transactionDetails  - Details of the transaction to be signed.
	 * @param pwdPromptCallback   - Callback function to prompt for password.
	 * @param sCB_signTransacion  - Callback function for successful response.
	 * @param fCB_signTransaction - Callback function for failed response.
	 * @param appContext          - Context of the application.
	 * @param activity            - FragmentActivity to run the transaction signing
	 *                            in.
	 */
	public void signTransaction(String transactionDetails, Function pwdPromptCallback, Function sCB_signTransacion,
			Function fCB_signTransaction, Context appContext, FragmentActivity activity) {
		signTransactionWrap(transactionDetails, pwdPromptCallback, sCB_signTransacion, fCB_signTransaction, appContext,
				activity, OtpKeyLabel.OATH_OCRA_HOTP_SIGN_LABEL.getCode());
	}

	/**
	 * This private method is used to sign a transaction.
	 * 
	 * @param transactionDetails  - Details of the transaction to be signed.
	 * @param pwdPromptCallback   - Callback function to prompt for password.
	 * @param sCB_signTransacion  - Callback function for successful response.
	 * @param fCB_signTransaction - Callback function for failed response.
	 * @param appContext          - Context of the application.
	 * @param activity            - FragmentActivity to run the transaction signing
	 *                            in.
	 * @param otpLabel            - The label for the OTP key will be set in
	 *                            accordance with TOTP or HOTP.
	 */
	private void signTransactionWrap(String transactionDetails, Function pwdPromptCallback, Function sCB_signTransacion,
			Function fCB_signTransaction, Context appContext, FragmentActivity activity, String otpLabel) {
		this.activity = activity;
		this.appContext = appContext;
		boolean isBioEnabled = checkForBioAvailability();
		String lockPolicyType = getLockPolicy(otpLabel, ApproveSDKConstants.CODE_SIGN);
		Log.d(LOG_TAG, "HID:signTransaction - lockPolicyType: " + lockPolicyType);
		signTransactionMonitor = new WaitNotifyMonitor();
		SignatureGeneratorAsync signatureGeneratorAsync = new SignatureGeneratorAsync(transactionDetails,
				getSingleUserContainer(), isBioEnabled, pwdPromptCallback, sCB_signTransacion, fCB_signTransaction,
				appContext, activity, signTransactionMonitor, otpLabel);
		Thread thread = new Thread(signatureGeneratorAsync);
		thread.start();
	}

	/**
	 * This public method is used to retrieve the transaction details.
	 * 
	 * @param txId               - Transaction ID to retrieve the transaction
	 *                           details.
	 * @param appContext         - Context of the application.
	 * @param activity           - FragmentActivity to run the transaction retrieval
	 *                           in.
	 * @param password           - Password to be used for transaction retrieval,
	 *                           pass "" if biometrics are enabled.
	 * @param isBiometricEnabled - Boolean to check if biometrics are enabled or
	 *                           not.
	 * @param callback           - Callback function to handle the response.
	 * 
	 * @return string - JSON string containing transaction details or error message.
	 */
	public String retriveTransaction(String txId, Context appContext, FragmentActivity activity, String password,
			boolean isBiometricEnabled, Function callback) throws Exception {
		JSONObject jsonObj = new JSONObject();
		this.appContext = appContext;
		this.activity = activity;
		try {
			Device device = DeviceFactory.getDevice(appContext, new ConnectionConfiguration());
			ServerActionInfo transactionInfo = device.retrieveActionInfo(txId.toCharArray());
			ProtectionPolicy policy = transactionInfo.getProtectionKey().getProtectionPolicy();
			Log.d(LOG_TAG, policy.getType());
			String username = transactionInfo.getContainer().getUserId();
			this.username = username;

			Transaction transaction = (Transaction) transactionInfo.getAction(null, new Parameter[0]);
			String transactionString = transaction.toString();
			container = transactionInfo.getContainer();
			if (transactionString == null || transactionString.isEmpty()) {
				Log.d(LOG_TAG, "HID:retriveTransaction: Transaction is empty");
				callback.execute(new Object[] { "error", "Transaction is empty", null });
				return null;
			}

			jsonObj.put("username", username);
			jsonObj.put("tds", transactionString);
			Log.d(LOG_TAG, "HID:retriveTransaction: Transaction retreival complete");
			callback.execute(new Object[] { "success", "No Exception", jsonObj });
		} catch (InternalException e) {
			e.printStackTrace();
			callback.execute(new Object[] { "error", "InternalException", e.getMessage() });
			Log.d(LOG_TAG, "HID:retriveTransaction: InternalException " + e.getStackTrace());
		} catch (InvalidParameterException e) {
			e.printStackTrace();
			callback.execute(new Object[] { "error", "InvalidParameterException", e.getMessage() });
			Log.d(LOG_TAG, "HID:retriveTransaction: InvalidParameterException " + e.getStackTrace());
		} catch (UnsupportedDeviceException e) {
			e.printStackTrace();
			callback.execute(new Object[] { "error", "UnsupportedDeviceException", e.getMessage() });
			Log.d(LOG_TAG, "HID:retriveTransaction: UnsupportedDeviceException" + e.getStackTrace());
		} catch (LostCredentialsException e) {
			e.printStackTrace();
			callback.execute(new Object[] { "error", "LostCredentialsException", e.getMessage() });
			Log.d(LOG_TAG, "HID:retriveTransaction: LostCredentialsException " + e.getStackTrace());
		} catch (InvalidContainerException e) {
			e.printStackTrace();
			callback.execute(new Object[] { "error", "InvalidContainerException", e.getMessage() });
			Log.d(LOG_TAG, "HID:retriveTransaction: InvalidContainerException " + e.getStackTrace());
		} catch (InexplicitContainerException e) {
			e.printStackTrace();
			callback.execute(new Object[] { "error", "InexplicitContainerException", e.getMessage() });
			Log.d(LOG_TAG, "HID:retriveTransaction: InexplicitContainerException " + e.getStackTrace());
		} catch (AuthenticationException e) {
			e.printStackTrace();
			callback.execute(new Object[] { "error", "AuthenticationException", e.getMessage() });
			Log.d(LOG_TAG, "HID:retriveTransaction: AuthenticationException " + e.getStackTrace());
		} catch (RemoteException e) {
			e.printStackTrace();
			callback.execute(new Object[] { "error", "RemoteException", e.getMessage() });
			Log.d(LOG_TAG, "HID:retriveTransaction: RemoteException " + e.getStackTrace());
		} catch (PasswordExpiredException e) {
			e.printStackTrace();
			callback.execute(new Object[] { "error", "PasswordExpiredException", e.getMessage() });
			Log.d(LOG_TAG, "HID:retriveTransaction: PasswordExpiredException " + e.getStackTrace());
		} catch (TransactionExpiredException e) {
			e.printStackTrace();
			callback.execute(new Object[] { "error", "TransactionExpiredException", e.getMessage() });
			Log.d(LOG_TAG, "HID:retriveTransaction: TransactionExpiredException " + e.getStackTrace());
		} catch (ServerOperationFailedException e) {
			e.printStackTrace();
			callback.execute(new Object[] { "error", "ServerOperationFailedException", e.getMessage() });
			Log.d(LOG_TAG, "HID:retriveTransaction: ServerOperationFailedException " + e.getStackTrace());
		} catch (Exception e) {
			e.printStackTrace();
			callback.execute(new Object[] { "error", "Exception", e.getMessage() });
			Log.d(LOG_TAG, "HID:retriveTransaction: Exception " + e.getStackTrace());
		}
		return jsonObj.toString();
	}

	/**
	 * This public method is used to verify the password and biometric
	 * authentication.
	 * 
	 * @param appContext         - Context of the application.
	 * @param activity           - FragmentActivity to run the verification in.
	 * @param password           - Password to be verified, pass "" if biometrics
	 *                           are enabled.
	 * @param isBiometricEnabled - Boolean to check if biometrics are enabled or
	 *                           not.
	 * @param bioString          - String to be used for biometric authentication,
	 *                           can be null or empty.
	 * @param callback           - Callback function to handle the response.
	 */
	public void verifyPassword(Context appContext, FragmentActivity activity, String password,
			boolean isBiometricEnabled, String bioString, Function callback) {
		this.appContext = appContext;
		this.activity = activity;
		Log.d(LOG_TAG, "Inside Verify password with bioEnabled = " + isBiometricEnabled);
		Container container = this.getSingleUserContainer();
		if (!isBiometricEnabled && (password == null || password.isEmpty())) {
			genericExecuteCallback(new Object[] { "error", ApproveSDKConstants.AUTHENTICATION_EXCEPTION,
					ApproveSDKConstants.AUTH_EXCEPTION_CODE }, callback);
			Log.d(LOG_TAG, "HID:verifyPassword Password is null or empty");
		}
		try {
			PasswordPolicy passwordPolicy = (PasswordPolicy) container.getProtectionPolicy();
			if (isBiometricEnabled) {
				BiometricAuthService bioAuthService = new BiometricAuthService();
				bioAuthService.setBiometricPrompt(activity, bioString, container.getProtectionPolicy(),
						new FingerprintHandler.BiometricEventListener() {

							@Override
							public void onAuthSuccess() {
								try {
									PasswordPolicy passwordPolicy = (PasswordPolicy) container.getProtectionPolicy();
									// passwordPolicy.verifyPassword(null);
								} catch (Exception e) {
									genericExecuteCallback(new Object[] { "error", e.getClass().getName(),
											ApproveSDKConstants.NO_EXCEPTION_CODE }, callback);
									Log.d(LOG_TAG, "HID:verifyPassword: Exception " + e.getStackTrace());
									e.printStackTrace();
								}
								genericExecuteCallback(new Object[] { "success", "No Exception",
										ApproveSDKConstants.NO_EXCEPTION_CODE }, callback);
								Log.d(LOG_TAG, "HID:verifyPassword: Success");

							}

							@Override
							public void onAuthFailed() {
								Log.d(LOG_TAG, "HID:verifyPassword Bio onAuthFailed");
							}

							@Override
							public void onAuthError() {
								Log.d(LOG_TAG, "HID:verifyPassword Bio onAuthError");
							}
						});
				try {
					passwordPolicy.verifyPassword(null);
				} catch (FingerprintAuthenticationRequiredException fe) {
					genericExecuteCallback(new Object[] { "error", ApproveSDKConstants.BIOMETRIC_ERROR,
							ApproveSDKConstants.BIOMETRIC_ERROR_CODE }, callback);
					Log.d(LOG_TAG,
							"HID:verifyPassword: FingerprintAuthenticationRequiredException " + fe.getStackTrace());
					fe.printStackTrace();
				} catch (InternalException e) {
					genericExecuteCallback(
							new Object[] { "error", "InternalException", ApproveSDKConstants.GENERIC_ERROR_CODE },
							callback);
					Log.d(LOG_TAG, "HID:verifyPassword: InternalException " + e.getStackTrace());
					e.printStackTrace();
				} catch (UnsupportedDeviceException e) {
					genericExecuteCallback(new Object[] { "error", "UnsupportedDeviceException",
							ApproveSDKConstants.GENERIC_ERROR_CODE }, callback);
					Log.d(LOG_TAG, "HID:verifyPassword: UnsupportedDeviceException " + e.getStackTrace());
					e.printStackTrace();
				} catch (LostCredentialsException e) {
					genericExecuteCallback(new Object[] { "error", "LostCredentialsException",
							ApproveSDKConstants.GENERIC_ERROR_CODE }, callback);
					Log.d(LOG_TAG, "HID:verifyPassword: LostCredentialsException " + e.getStackTrace());
					e.printStackTrace();
				} catch (AuthenticationException e) {
					genericExecuteCallback(
							new Object[] { "error", "AuthenticationException", ApproveSDKConstants.GENERIC_ERROR_CODE },
							callback);
					Log.d(LOG_TAG, "HID:verifyPassword: AuthenticationException " + e.getStackTrace());
					e.printStackTrace();
				} catch (PasswordExpiredException e) {
					genericExecuteCallback(new Object[] { "error", "PasswordExpiredException",
							ApproveSDKConstants.GENERIC_ERROR_CODE }, callback);
					Log.d(LOG_TAG, "HID:verifyPassword: PasswordExpiredException " + e.getStackTrace());
					e.printStackTrace();
				} catch (FingerprintNotEnrolledException e) {
					genericExecuteCallback(new Object[] { "error", "FingerprintNotEnrolledException",
							ApproveSDKConstants.GENERIC_ERROR_CODE }, callback);
					Log.d(LOG_TAG, "HID:verifyPassword: FingerprintNotEnrolledException " + e.getStackTrace());
					e.printStackTrace();
				} catch (PasswordRequiredException e) {
					genericExecuteCallback(new Object[] { "error", "PasswordRequiredException",
							ApproveSDKConstants.GENERIC_ERROR_CODE }, callback);
					Log.d(LOG_TAG, "HID:verifyPassword: PasswordRequiredException " + e.getStackTrace());
					e.printStackTrace();
				} catch (InvalidParameterException e) {
					genericExecuteCallback(new Object[] { "error", "InvalidParameterException",
							ApproveSDKConstants.GENERIC_ERROR_CODE }, callback);
					Log.d(LOG_TAG, "HID:verifyPassword: InvalidParameterException " + e.getStackTrace());
					e.printStackTrace();
				} catch (Exception e) {
					genericExecuteCallback(new Object[] { "error", ApproveSDKConstants.BIOMETRIC_ERROR,
							ApproveSDKConstants.BIOMETRIC_ERROR_CODE }, callback);
					Log.d(LOG_TAG, "HID:verifyPassword: Exception " + e.getStackTrace());
					e.printStackTrace();
				}
			} else {
				try {
					passwordPolicy.verifyPassword(password.toCharArray());
					genericExecuteCallback(new Object[] { "success", "No Exception" }, callback);
					Log.d(LOG_TAG, "HID:verifyPassword: Success");
				} catch (AuthenticationException Ae) {
					genericExecuteCallback(new Object[] { "error", ApproveSDKConstants.AUTHENTICATION_EXCEPTION,
							ApproveSDKConstants.AUTH_EXCEPTION_CODE }, callback);
					Log.d(LOG_TAG, "HID:verifyPassword: AuthenticationException " + Ae.getStackTrace());
				} catch (InternalException e) {
					genericExecuteCallback(
							new Object[] { "error", "InternalException", ApproveSDKConstants.GENERIC_ERROR_CODE },
							callback);
					Log.d(LOG_TAG, "HID:verifyPassword: InternalException " + e.getStackTrace());
					e.printStackTrace();
				} catch (UnsupportedDeviceException e) {
					genericExecuteCallback(new Object[] { "error", "UnsupportedDeviceException",
							ApproveSDKConstants.GENERIC_ERROR_CODE }, callback);
					Log.d(LOG_TAG, "HID:verifyPassword: UnsupportedDeviceException " + e.getStackTrace());
					e.printStackTrace();
				} catch (LostCredentialsException e) {
					genericExecuteCallback(new Object[] { "error", "LostCredentialsException",
							ApproveSDKConstants.GENERIC_ERROR_CODE }, callback);
					Log.d(LOG_TAG, "HID:verifyPassword: LostCredentialsException " + e.getStackTrace());
					e.printStackTrace();
				} catch (PasswordExpiredException e) {
					genericExecuteCallback(new Object[] { "error", "PasswordExpiredException",
							ApproveSDKConstants.GENERIC_ERROR_CODE }, callback);
					Log.d(LOG_TAG, "HID:verifyPassword: PasswordExpiredException " + e.getStackTrace());
					e.printStackTrace();
				} catch (FingerprintNotEnrolledException e) {
					genericExecuteCallback(new Object[] { "error", "FingerprintNotEnrolledException",
							ApproveSDKConstants.GENERIC_ERROR_CODE }, callback);
					Log.d(LOG_TAG, "HID:verifyPassword: FingerprintNotEnrolledException " + e.getStackTrace());
					e.printStackTrace();
				} catch (PasswordRequiredException e) {
					genericExecuteCallback(new Object[] { "error", "PasswordRequiredException",
							ApproveSDKConstants.GENERIC_ERROR_CODE }, callback);
					Log.d(LOG_TAG, "HID:verifyPassword: PasswordRequiredException " + e.getStackTrace());
					e.printStackTrace();
				} catch (InvalidParameterException e) {
					genericExecuteCallback(new Object[] { "error", "InvalidParameterException",
							ApproveSDKConstants.GENERIC_ERROR_CODE }, callback);
					Log.d(LOG_TAG, "HID:verifyPassword: InvalidParameterException " + e.getStackTrace());
					e.printStackTrace();
				} catch (Exception e) {
					genericExecuteCallback(
							new Object[] { "error", e.getClass().getName(), ApproveSDKConstants.NO_EXCEPTION_CODE },
							callback);
					Log.d(LOG_TAG, "HID:verifyPassword: Exception " + e.getStackTrace());
				}
			}
		} catch (UnsupportedDeviceException e) {
			genericExecuteCallback(
					new Object[] { "error", "UnsupportedDeviceException", ApproveSDKConstants.GENERIC_ERROR_CODE },
					callback);
			Log.d(LOG_TAG, "HID:verifyPassword: UnsupportedDeviceException " + e.getStackTrace());
		} catch (LostCredentialsException e) {
			genericExecuteCallback(
					new Object[] { "error", "LostCredentialsException", ApproveSDKConstants.GENERIC_ERROR_CODE },
					callback);
			Log.d(LOG_TAG, "HID:verifyPassword: LostCredentialsException " + e.getStackTrace());
		} catch (InternalException e) {
			genericExecuteCallback(
					new Object[] { "error", "InternalException", ApproveSDKConstants.GENERIC_ERROR_CODE }, callback);
			Log.d(LOG_TAG, "HID:verifyPassword: InternalException " + e.getStackTrace());
		} catch (Exception e) {
			genericExecuteCallback(
					new Object[] { "error", e.getClass().getName(), ApproveSDKConstants.NO_EXCEPTION_CODE }, callback);
			Log.d(LOG_TAG, "HID:verifyPassword: Exception " + e.getStackTrace());
		}

	}

	/**
	 * This public method sets the notification status for a
	 * transaction/notification.
	 * 
	 * @param txId         - The transaction ID.
	 * @param status       - The status to set (e.g., "approve", "deny", "report").
	 * @param password     - The password for authentication, if Biometric is not
	 *                     enabled and if enabled passed "".
	 * @param onCompleteCB - The callback function to execute after setting the
	 *                     status.
	 * @param pwdPromptCB  - The callback function to prompt for password, if
	 *                     required.
	 * @param appContext   - The application context.
	 * @param activity     - The activity from which the biometric prompt is shown.
	 */
	public void setNotificationStatus(String txId, String status, String password, Function onCompleteCB,
			Function pwdPromptCB, Context appContext, FragmentActivity activity) {
		this.appContext = appContext;
		this.activity = activity;
		Log.d(LOG_TAG, txId);
		notificationMonitor = new WaitNotifyMonitor();
		ApproveNotificationUpdater approveNotificationUpdater = new ApproveNotificationUpdater(txId, status, password,
				appContext, activity, checkForBioAvailability(appContext), onCompleteCB, pwdPromptCB,
				notificationMonitor);
		Thread thread = new Thread(approveNotificationUpdater);
		thread.start();
	}

	/**
	 * This public method is used to cancel a transaction.
	 * 
	 * @param txId          - The transaction ID to cancel.
	 * @param message       - The message to be sent with the cancellation. //optional
	 * @param reason        - The reason for cancellation (e.g., "cancel", "suspicious").
	 * @param cancelCallback - The callback function to execute after cancellation.
	 */
	public void transactionCancel(Context appContext, FragmentActivity activity, String txId, String message, String reason, Function cancelCallback) {
		this.appContext = appContext;
		this.activity = activity;
		try {
			Device device = DeviceFactory.getDevice(appContext, new ConnectionConfiguration());
			ServerActionInfo transactionInfo = device.retrieveActionInfo(txId.toCharArray());
			ProtectionPolicy policy = transactionInfo.getProtectionKey().getProtectionPolicy();
			Log.d(LOG_TAG, policy.getType());
			String username = transactionInfo.getContainer().getUserId();
			this.username = username;

			Transaction transaction = (Transaction) transactionInfo.getAction(null, new Parameter[0]);
			String transactionString = transaction.toString();
			container = transactionInfo.getContainer();
			if (transactionString == null || transactionString.isEmpty()) {
				Log.d(LOG_TAG, "HID:transactionCancel: Transaction is empty");
				genericExecuteCallback("error", "Transaction is empty", cancelCallback);
			}
			if (container == null) {
				Log.d(LOG_TAG, "HID:transactionCancel: Container is null");
				genericExecuteCallback("error", "Container is null", cancelCallback);
			}
			if (reason == null || reason.isEmpty()) {
				Log.d(LOG_TAG, "HID:transactionCancel: Reason is null or empty");
				genericExecuteCallback("error", "Reason is null or empty", cancelCallback);
			}
			if (message == null || message.isEmpty()) {
				Log.d(LOG_TAG, "HID:transactionCancel: Message is passed as null or empty");
				message = "";
			}
			
			Log.d(LOG_TAG, "HID:transactionCancel: Reason: " + reason);
			Log.d(LOG_TAG, "HID:transactionCancel: Message: " + message);
			
			if (reason.equals("cancel")) {
				Log.d(LOG_TAG, "HID:transactionCancel: Cancelling transaction with reason: " + reason);
				CancelationReason reasonCancel = ApproveSDKConstants.CANCELATION_REASON_CANCEL;
				transaction.cancel(message, reasonCancel , null);
				Log.d(LOG_TAG, "HID:transactionCancel: Transaction cancelled successfully with reason: " + reason);
				genericExecuteCallback("success", "Transaction cancelled successfully", cancelCallback);
			}else if (reason.equals("suspicious")) {
				Log.d(LOG_TAG, "HID:transactionCancel: Cancelling transaction with reason: " + reason);
				CancelationReason reasonSuspicious = ApproveSDKConstants.CANCELATION_REASON_SUSPICIOUS;
				transaction.cancel(message, reasonSuspicious, null);
				Log.d(LOG_TAG, "HID:transactionCancel: Transaction marked as suspicious with reason: " + reason);
				genericExecuteCallback("success", "Transaction marked as suspicious", cancelCallback);
			}else {
				Log.d(LOG_TAG, "HID:transactionCancel: Invalid reason provided");
				genericExecuteCallback("error", "Invalid reason provided", cancelCallback);
			}
		}catch(AuthenticationException e) {
			Log.d(LOG_TAG, "HID:transactionCancel: AuthenticationException " + e.getStackTrace());
			genericExecuteCallback("AuthenticationException", e.getMessage(), cancelCallback);
			e.printStackTrace();
		}catch (InternalException e) {
			Log.d(LOG_TAG, "HID:transactionCancel: InternalException " + e.getStackTrace());
			genericExecuteCallback("InternalException", e.getMessage(), cancelCallback);
			e.printStackTrace();
		}catch (InvalidParameterException e) {
			Log.d(LOG_TAG, "HID:transactionCancel: InvalidParameterException " + e.getStackTrace());
			genericExecuteCallback("InvalidParameterException", e.getMessage(), cancelCallback);
			e.printStackTrace();
		}catch (PasswordExpiredException e) {
			Log.d(LOG_TAG, "HID:transactionCancel: PasswordExpiredException " + e.getStackTrace());
			genericExecuteCallback("PasswordExpiredException", e.getMessage(), cancelCallback);
			e.printStackTrace();
		}catch (RemoteException e) {
			Log.d(LOG_TAG, "HID:transactionCancel: RemoteException " + e.getStackTrace());
			genericExecuteCallback("RemoteException", e.getMessage(), cancelCallback);
			e.printStackTrace();
		}catch (ServerUnsupportedOperationException e) {
			Log.d(LOG_TAG, "HID:transactionCancel: ServerUnsupportedOperationException " + e.getStackTrace());
			genericExecuteCallback("ServerUnsupportedOperationException", e.getMessage(), cancelCallback);
			e.printStackTrace();
		}catch (TransactionCanceledException e) {
			Log.d(LOG_TAG, "HID:transactionCancel: TransactionCanceledException " + e.getStackTrace());
			genericExecuteCallback("TransactionCanceledException", e.getMessage(), cancelCallback);
			e.printStackTrace();
		}catch (TransactionExpiredException e) {
			Log.d(LOG_TAG, "HID:transactionCancel: TransactionExpiredException " + e.getStackTrace());
			genericExecuteCallback("TransactionExpiredException", e.getMessage(), cancelCallback);
			e.printStackTrace();
		}catch(Exception e) {
			Log.d(LOG_TAG, "HID:transactionCancel: Exception " + e.getStackTrace());
			e.printStackTrace();
		}
	}

	/**
	 * This public method notifies the password to the monitor based (for Sign
	 * Transaction) on the mode.
	 * 
	 * @param password - The password to notify.
	 * @param mode     - The mode of operation (e.g., SIGN_TRANSACTION_FLOW or
	 *                 NOTIFICATION_FLOW).
	 */
	public void notifyPassword(String password, String mode) {
		Log.d(LOG_TAG, "HID:notifyPassword Inside notifyPassword");
		if (mode.equals(ApproveSDKConstants.SIGN_TRANSACTION_FLOW)) {
			if (signTransactionMonitor != null) {
				Log.d(LOG_TAG, "HID:notifyPassword Notifying");
				synchronized (signTransactionMonitor) {
					signTransactionMonitor.setMsg(password);
					signTransactionMonitor.notify();
				}
			}
		} else if (mode.equals(ApproveSDKConstants.NOTIFICATION_FLOW)) {
			if (notificationMonitor != null) {
				Log.d(LOG_TAG, "HID:notifyPassword Notifying");
				synchronized (notificationMonitor) {
					notificationMonitor.setMsg(password);
					notificationMonitor.notify();
				}
			}
		}
	}

	/**
	 * This public method retrieves pending notifications.
	 * 
	 * @param appContext                      - Context of the application.
	 * @param onRetrieveNotificationsCallback - The callback function to execute
	 *                                        after retrieving notifications.
	 */
	public void retrievePendingNotifications(Context appContext, Function onRetrieveNotificationsCallback) {
		this.appContext = appContext;
		RetrievePendingNotifications retrievePendingNotifications = new RetrievePendingNotifications(
				getSingleUserContainer(), onRetrieveNotificationsCallback);
		Thread thread = new Thread(retrievePendingNotifications);
		thread.start();
	}

	/**
	 * This method is depracated in HID SDK 6.0.2 and should not be used. Use deleteContainerWithReason instead.
	 * 
	 * This public method deletes the container.
	 * 
	 * @param appContext - Context of the application.
	 * @return boolean - true if the container is deleted successfully, false
	 *         otherwise.
	 */
	public boolean deleteContainer(Context appContext) {
		this.appContext = appContext;
		try {
			Container container = getSingleUserContainer();
			Device device = DeviceFactory.getDevice(appContext, new ConnectionConfiguration());
			device.deleteContainer(container.getId(), null);
		} catch (Exception e) {
			e.printStackTrace();
			Log.d(LOG_TAG, "HID:deleteContainer: Exception " + e.getStackTrace());
			return false;
		}
		return true;
	}
	
	/**
	 * This public method deletes the container with reason - no authentication required here.
	 * 
	 * @param appContext - Context of the application.
	 * @param reason - The reason for deletion, can be null or empty.
	 * @return boolean - true if the container is deleted successfully, false
	 *         otherwise.
	 */
	public boolean deleteContainerWithReason(Context appContext, String reason) {
		this.appContext = appContext;
		try {
			Container container = getSingleUserContainer();
			Device device = DeviceFactory.getDevice(appContext, new ConnectionConfiguration());
			final String reasonParam = reason;
			Log.d(LOG_TAG, "HID:deleteContainerWithReason: Reason for deletion: " + reasonParam);
			if (reason == null || reason.isEmpty()) {
				reason = null; // If reason is empty, set it to null
			}
			deleteContainer(this.appContext, container, reasonParam);
		} catch (Exception e) {
			e.printStackTrace();
			Log.d(LOG_TAG, "HID:deleteContainerWithReason: Exception " + e.getStackTrace());
			return false;
		}
		return true;
	}

	/**
	 * This method is depracated in HID SDK 6.0.2 and should not be used. Use deleteContainer (with reason param) instead.
	 * 
	 * This private method deletes the container.
	 * 
	 * @param appContext - Context of the application.
	 * @param container  - The container to be deleted.
	 * @return boolean - true if the container is deleted successfully, false
	 *         otherwise.
	 */
	private boolean deleteContainer(Context appContext, Container container) {
		this.appContext = appContext;
		try {
			Device device = DeviceFactory.getDevice(appContext, new ConnectionConfiguration());
			device.deleteContainer(container.getId(), null);
		} catch (InternalException e) {
			e.printStackTrace();
			Log.d(LOG_TAG, "HID:deleteContainer: InternalException " + e.getStackTrace());
			return false;
		} catch (Exception e) {
			e.printStackTrace();
			Log.d(LOG_TAG, "HID:deleteContainer: Exception " + e.getStackTrace());
			return false;
		}
		return true;
	}

	/**
	 * This private method deletes the container with reason.
	 * 
	 * @param appContext - Context of the application.
	 * @param container  - The container to be deleted.
	 * @return boolean - true if the container is deleted successfully, false
	 *         otherwise.
	 */
	private boolean deleteContainer(Context appContext, Container container, String reason) {
		this.appContext = appContext;
		try {
			Device device = DeviceFactory.getDevice(appContext, new ConnectionConfiguration());
			device.deleteContainer(container.getId(), null, reason);
		} catch (InternalException e) {
			e.printStackTrace();
			Log.d(LOG_TAG, "HID:deleteContainer: InternalException " + e.getStackTrace());
			return false;
		} catch (Exception e) {
			e.printStackTrace();
			Log.d(LOG_TAG, "HID:deleteContainer: Exception " + e.getStackTrace());
			return false;
		}
		return true;
	}

	/**
	 * This method is depracated in HID SDK 6.0.2 and should not be used. Use deleteContainerAuthWithReason instead.
	 * 
	 * This public method deletes the container with authentication.
	 * 
	 * @param context  - Context of the application.
	 * @param activity - FragmentActivity to run the deletion in.
	 * @param pwd      - The password for authentication, if any.
	 * @param callback - The callback function to execute after deletion.
	 */
	public void deleteContainerWithAuth(Context context, FragmentActivity activity, String pwd, Function callback) {
		Container container = getSingleUserContainer();
		try {
			PasswordPolicy policy = (PasswordPolicy) container.getProtectionPolicy();
			if (pwd.isEmpty() && checkForBioAvailability(context)) {
				BiometricAuthService bioAuthService = new BiometricAuthService();
				bioAuthService.setBiometricPrompt(activity, ApproveSDKConstants.BIO_PROMPT_DELETE_USER,
						container.getProtectionPolicy(), new FingerprintHandler.BiometricEventListener() {
							@Override
							public void onAuthSuccess() {
								try {
//									policy.verifyPassword(null);
									String status = deleteContainer(context, container) ? "success" : "failure";
									Log.d(LOG_TAG, "HID:deleteContainerWithAuth: status " + status);
									executeDeleteContainerCB(callback, status);
								} catch (Exception e) {
									executeDeleteContainerCB(callback, "failure");
									Log.d(LOG_TAG, "HID:deleteContainerWithAuth: Exception " + e.getStackTrace());
									e.printStackTrace();
								}
							}

							@Override
							public void onAuthFailed() {
								executeDeleteContainerCB(callback, ApproveSDKConstants.FINGERPRINT_EXCEPTION);
								Log.d(LOG_TAG, "HID:deleteContainerWithAuth: onAuthFailed");
							}

							@Override
							public void onAuthError() {
								executeDeleteContainerCB(callback, ApproveSDKConstants.FINGERPRINT_EXCEPTION);
								Log.d(LOG_TAG, "HID:deleteContainerWithAuth: onAuthError");
							}
						});
				policy.verifyPassword(null);
			} else if (pwd.isEmpty()) {
				// do Nothing
				Log.d(LOG_TAG, "HID:deleteContainerWithAuth: Password is empty");
				return;
			} else {
				policy.verifyPassword(pwd.toCharArray());
				String status = deleteContainer(context, container) ? "success" : "failure";
				Log.d(LOG_TAG, "HID:deleteContainerWithAuth: status" + status);
				executeDeleteContainerCB(callback, status);
			}
		} catch (AuthenticationException e) {
			Log.d(LOG_TAG, "HID:deleteContainerWithAuth: AuthenticationException " + e.getStackTrace());
			e.printStackTrace();
			executeDeleteContainerCB(callback, ApproveSDKConstants.AUTHENTICATION_EXCEPTION);
		} catch (PasswordRequiredException e) {
			Log.d(LOG_TAG, "HID:deleteContainerWithAuth: PasswordRequiredException " + e.getStackTrace());
			e.printStackTrace();
			executeDeleteContainerCB(callback, ApproveSDKConstants.AUTHENTICATION_EXCEPTION);
		} catch (FingerprintAuthenticationRequiredException e) {
			Log.d(LOG_TAG,
					"HID:deleteContainerWithAuth: FingerprintAuthenticationRequiredException " + e.getStackTrace());
			e.printStackTrace();
			executeDeleteContainerCB(callback, "FingerprintAuthenticationRequiredException");
		} catch (FingerprintNotEnrolledException e) {
			Log.d(LOG_TAG, "HID:deleteContainerWithAuth: FingerprintNotEnrolledException " + e.getStackTrace());
			e.printStackTrace();
			executeDeleteContainerCB(callback, "FingerprintNotEnrolledException");
		} catch (UnsupportedDeviceException e) {
			Log.d(LOG_TAG, "HID:deleteContainerWithAuth: UnsupportedDeviceException " + e.getStackTrace());
			e.printStackTrace();
			executeDeleteContainerCB(callback, "UnsupportedDeviceException");
		} catch (InternalException e) {
			Log.d(LOG_TAG, "HID:deleteContainerWithAuth: InternalException " + e.getStackTrace());
			e.printStackTrace();
			executeDeleteContainerCB(callback, "InternalException");
		} catch (LostCredentialsException e) {
			Log.d(LOG_TAG, "HID:deleteContainerWithAuth: LostCredentialsException " + e.getStackTrace());
			e.printStackTrace();
			executeDeleteContainerCB(callback, "LostCredentialsException");
		} catch (PasswordExpiredException e) {
			Log.d(LOG_TAG, "HID:deleteContainerWithAuth: PasswordExpiredException " + e.getStackTrace());
			e.printStackTrace();
			executeDeleteContainerCB(callback, "PasswordExpiredException");
		} catch (InvalidParameterException e) {
			Log.d(LOG_TAG, "HID:deleteContainerWithAuth: InvalidParameterException " + e.getStackTrace());
			e.printStackTrace();
			executeDeleteContainerCB(callback, "InvalidParameterException");
		} catch (Exception e) {
			Log.d(LOG_TAG, "HID:deleteContainerWithAuth: Exception " + e.getStackTrace());
			e.printStackTrace();
			executeDeleteContainerCB(callback, ApproveSDKConstants.GENERIC_EXCEPTION);
		}
	}

	/**
	 * This public method deletes the container with a reason.
	 * 
	 * @param context  - Context of the application.
	 * @param activity - FragmentActivity to run the deletion in.
	 * @param pwd      - The password for authentication, if any.
	 * @param reason   - The reason for deletion.
	 * @param callback - The callback function to execute after deletion.
	 */
	public void deleteContainerAuthWithReason(Context context, FragmentActivity activity, String pwd, String reason,
			Function callback) {
		Container container = getSingleUserContainer();
		final String reasonParam = reason;
		Log.d(LOG_TAG, "HID:deleteContainerAuthWithReason: Reason for deletion: " + reasonParam);
		if (reason == null || reason.isEmpty()) {
			reason = null; // If reason is empty, set it to null
		}
		try {
			PasswordPolicy policy = (PasswordPolicy) container.getProtectionPolicy();
			if (pwd.isEmpty() && checkForBioAvailability(context)) {
				BiometricAuthService bioAuthService = new BiometricAuthService();
				bioAuthService.setBiometricPrompt(activity, ApproveSDKConstants.BIO_PROMPT_DELETE_USER,
						container.getProtectionPolicy(), new FingerprintHandler.BiometricEventListener() {
							@Override
							public void onAuthSuccess() {
								try {
//									policy.verifyPassword(null);
									Log.d(LOG_TAG,
											"HID:deleteContainerAuthWithReason: Reason for deletion: " + reasonParam);
									String status = deleteContainer(context, container, reasonParam) ? "success"
											: "failure";
									Log.d(LOG_TAG, "HID:deleteContainerAuthWithReason: status " + status);
									executeDeleteContainerCB(callback, status);
								} catch (Exception e) {
									executeDeleteContainerCB(callback, "failure");
									Log.d(LOG_TAG, "HID:deleteContainerAuthWithReason: Exception " + e.getStackTrace());
									e.printStackTrace();
								}
							}

							@Override
							public void onAuthFailed() {
								executeDeleteContainerCB(callback, ApproveSDKConstants.FINGERPRINT_EXCEPTION);
								Log.d(LOG_TAG, "HID:deleteContainerAuthWithReason: onAuthFailed");
							}

							@Override
							public void onAuthError() {
								executeDeleteContainerCB(callback, ApproveSDKConstants.FINGERPRINT_EXCEPTION);
								Log.d(LOG_TAG, "HID:deleteContainerAuthWithReason: onAuthError");
							}
						});
				policy.verifyPassword(null);
			} else if (pwd.isEmpty()) {
				// do Nothing
				Log.d(LOG_TAG, "HID:deleteContainerAuthWithReason: Password is empty");
				return;
			} else {
				policy.verifyPassword(pwd.toCharArray());
				Log.d(LOG_TAG, "HID:deleteContainerAuthWithReason: Reason for deletion: " + reasonParam);
				String status = deleteContainer(context, container, reasonParam) ? "success" : "failure";
				Log.d(LOG_TAG, "HID:deleteContainerAuthWithReason: status" + status);
				executeDeleteContainerCB(callback, status);
			}
		} catch (AuthenticationException e) {
			Log.d(LOG_TAG, "HID:deleteContainerAuthWithReason: AuthenticationException " + e.getStackTrace());
			e.printStackTrace();
			executeDeleteContainerCB(callback, ApproveSDKConstants.AUTHENTICATION_EXCEPTION);
		} catch (PasswordRequiredException e) {
			Log.d(LOG_TAG, "HID:deleteContainerAuthWithReason: PasswordRequiredException " + e.getStackTrace());
			e.printStackTrace();
			executeDeleteContainerCB(callback, ApproveSDKConstants.AUTHENTICATION_EXCEPTION);
		} catch (FingerprintAuthenticationRequiredException e) {
			Log.d(LOG_TAG, "HID:deleteContainerAuthWithReason: FingerprintAuthenticationRequiredException "
					+ e.getStackTrace());
			e.printStackTrace();
			executeDeleteContainerCB(callback, "FingerprintAuthenticationRequiredException");
		} catch (FingerprintNotEnrolledException e) {
			Log.d(LOG_TAG, "HID:deleteContainerAuthWithReason: FingerprintNotEnrolledException " + e.getStackTrace());
			e.printStackTrace();
			executeDeleteContainerCB(callback, "FingerprintNotEnrolledException");
		} catch (UnsupportedDeviceException e) {
			Log.d(LOG_TAG, "HID:deleteContainerAuthWithReason: UnsupportedDeviceException " + e.getStackTrace());
			e.printStackTrace();
			executeDeleteContainerCB(callback, "UnsupportedDeviceException");
		} catch (InternalException e) {
			Log.d(LOG_TAG, "HID:deleteContainerAuthWithReason: InternalException " + e.getStackTrace());
			e.printStackTrace();
			executeDeleteContainerCB(callback, "InternalException");
		} catch (LostCredentialsException e) {
			Log.d(LOG_TAG, "HID:deleteContainerAuthWithReason: LostCredentialsException " + e.getStackTrace());
			e.printStackTrace();
			executeDeleteContainerCB(callback, "LostCredentialsException");
		} catch (PasswordExpiredException e) {
			Log.d(LOG_TAG, "HID:deleteContainerAuthWithReason: PasswordExpiredException " + e.getStackTrace());
			e.printStackTrace();
			executeDeleteContainerCB(callback, "PasswordExpiredException");
		} catch (InvalidParameterException e) {
			Log.d(LOG_TAG, "HID:deleteContainerAuthWithReason: InvalidParameterException " + e.getStackTrace());
			e.printStackTrace();
			executeDeleteContainerCB(callback, "InvalidParameterException");
		} catch (Exception e) {
			Log.d(LOG_TAG, "HID:deleteContainerAuthWithReason: Exception " + e.getStackTrace());
			e.printStackTrace();
			executeDeleteContainerCB(callback, ApproveSDKConstants.GENERIC_EXCEPTION);
		}
	}

	/**
	 * This private method executes the callback for delete container operation.
	 * 
	 * @param callback - The callback function to execute.
	 * @param msg      - The message to pass to the callback.
	 */
	private void executeDeleteContainerCB(Function callback, String msg) {
		try {
			callback.execute(new Object[] { msg });
		} catch (Exception e) {
			Log.d(LOG_TAG, "HID:deleteContainerWithAuth executeDeleteContainerCB: Exception " + e.getStackTrace());
			e.printStackTrace();
		}
	}

	/**
	 * This public method retrieves the device property, specifically the device ID.
	 * 
	 * @return string - representing the device ID.
	 */
	public String getDeviceProperty() {
		Container container = getSingleUserContainer();
		String deviceId = "";
		Log.d(LOG_TAG, "HID:getDeviceProperty");
		try {
			deviceId = new String(container.getProperty(ApproveSDKConstants.DEVICE_ID));
			Log.d(LOG_TAG, "HID:getDeviceProperty deviceId" + deviceId);

		} catch (Exception e) {
			// TODO Auto-generated catch block
			Log.d(LOG_TAG, "HID:getDeviceProperty Exception " + e.getStackTrace());
			e.printStackTrace();
		}
		Log.d(LOG_TAG, "HID:getDeviceProperty DeviceId--> " + deviceId);
		return deviceId;
	}

	/**
	 * This public method retrieves the friendly name of the container for a single
	 * user.
	 * 
	 * @return string - representing the friendly name of the container.
	 */
	public String getContainerFriendlyName() {
		Container container = getSingleUserContainer();
		String name = container.getName();
		Log.d(LOG_TAG, "HID:getContainerFriendlyName Container Friendly Name --> " + name);
		return name;
	}

	/**
	 * This public method retrieves the friendly name of the container for a single
	 * or multiple users.
	 * 
	 * @param appContext - Context of the application.
	 * @return string - representing the friendly name of the container(s).
	 */
	public String getMultiContainerFriendlyName(Context appContext) {
		try {
			Device device = DeviceFactory.getDevice(appContext, new ConnectionConfiguration());
			Container[] containers = device.findContainers(new Parameter[0]);
			this.appContext = appContext;
			if (containers.length == 0) {
				return "Register";
			}
			if (containers.length == 1) {
				container = containers[0];
				String name = container.getName();
				Log.d(LOG_TAG, "HID:getMultiContainerFriendlyName Container Friendly Name --> " + name);
				Log.d(LOG_TAG,
						"HID:getMultiContainerFriendlyName getContainerFriendlyName Container Login, UserId & Friendly Name --> "
								+ "SingleLogin:" + container.getUserId() + "," + name);
				return "SingleLogin:" + container.getUserId() + "," + name;
			}
			StringBuffer multiContainer = new StringBuffer("MultiLogin:");
			for (Container c : containers) {
				multiContainer.append(c.getUserId() + ",").append(c.getName() + "|");
			}
			Log.d(LOG_TAG,
					"HID:getMultiContainerFriendlyName getContainerFriendlyName Container Login, UserId & Friendly Name --> "
							+ multiContainer.substring(0, multiContainer.length() - 1));
			return multiContainer.substring(0, multiContainer.length() - 1);

		} catch (UnsupportedDeviceException ude) {
			Log.d(LOG_TAG, "HID:getMultiContainerFriendlyName UnsupportedDeviceException " + ude.getStackTrace());
			ude.printStackTrace();
		} catch (LostCredentialsException lce) {
			Log.d(LOG_TAG, "HID:getMultiContainerFriendlyName LostCredentialsException " + lce.getStackTrace());
			lce.printStackTrace();
		} catch (InternalException ie) {
			Log.d(LOG_TAG, "HID:getMultiContainerFriendlyName InternalException " + ie.getStackTrace());
			ie.printStackTrace();
		} catch (InvalidParameterException ipe) {
			Log.d(LOG_TAG, "HID:getMultiContainerFriendlyName InvalidParameterException " + ipe.getStackTrace());
			ipe.printStackTrace();
		} catch (Exception e) {
			Log.d(LOG_TAG, "HID:getMultiContainerFriendlyName Exception " + e.getStackTrace());
			e.printStackTrace();
		}
		return "Error";
	}

	/**
	 * This public method sets the friendly name of the container for a given
	 * username.
	 * 
	 * @param appContext      - Context of the application.
	 * @param username        - The username associated with the container.
	 * @param friendlyName    - The new friendly name to set for the container.
	 * @param setNameCallback - The callback function to execute after setting the
	 *                        name for success and failure response.
	 */
	public void setContainerFriendlyName(Context appContext, String username, String friendlyName,
			Function setNameCallback) {
		try {
			Device device = DeviceFactory.getDevice(appContext, new ConnectionConfiguration());
			Container[] containers = device.findContainers(new Parameter[0]);
			this.appContext = appContext;
			username = username.trim();
			this.username = username;
			Log.d(LOG_TAG, "HID:setContainerFriendlyName Wrapper Username --> " + this.username);
			Log.d(LOG_TAG, "HID:setContainerFriendlyName Username --> " + username);
			Log.d(LOG_TAG, "HID:setContainerFriendlyName Friendly Name --> " + friendlyName);
			for (Container c : containers) {
				String userId = c.getUserId().trim();
				Log.d(LOG_TAG, "HID:setContainerFriendlyName Container UserId--> " + userId);
				if (username.equals(userId)) {
					Log.d(LOG_TAG,
							"HID:setContainerFriendlyName Container Name matched with userId--> " + username + userId);
					Log.d(LOG_TAG, "HID:setContainerFriendlyName Friendly Name --> " + friendlyName);
					c.setName(friendlyName);
					Log.d(LOG_TAG, "HID:setContainerFriendlyName New Friendly Name -->" + friendlyName);
					executeSetNameCallback(setNameCallback, "Container Friendly Name Set Successfully", "success");
				}
			}
		} catch (UnsupportedDeviceException ude) {
			executeSetNameCallback(setNameCallback, ApproveSDKConstants.UNSUPPORTED_DEVICE_EXCEPTION,
					ApproveSDKConstants.UNSUPPORTED_DEVICE_CODE);
			Log.e(LOG_TAG, "HID:setContainerFriendlyName UnsupportedDeviceException " + ude.getStackTrace());
			ude.printStackTrace();
		} catch (LostCredentialsException lce) {
			executeSetNameCallback(setNameCallback, ApproveSDKConstants.LOST_CREDENTIALS_EXCEPTION,
					ApproveSDKConstants.LOST_CREDENTIALS_CODE);
			Log.e(LOG_TAG, "HID:setContainerFriendlyName LostCredentialsException " + lce.getStackTrace());
			lce.printStackTrace();
		} catch (InternalException ie) {
			executeSetNameCallback(setNameCallback, ApproveSDKConstants.INTERNAL_EXCEPTION,
					ApproveSDKConstants.INTERNAL_EXCEPTION_CODE);
			Log.e(LOG_TAG, "HID:setContainerFriendlyName InternalException " + ie.getStackTrace());
			ie.printStackTrace();
		} catch (InvalidParameterException ipe) {
			executeSetNameCallback(setNameCallback, ApproveSDKConstants.INVALID_PARAMETER_EXCEPTION,
					ApproveSDKConstants.INVALID_PARAMETER_CODE);
			Log.e(LOG_TAG, "HID:setContainerFriendlyName InvalidParameterException " + ipe.getStackTrace());
			ipe.printStackTrace();
		} catch (Exception e) {
			Log.e(LOG_TAG, "HID:setContainerFriendlyName Exception " + e.getStackTrace());
			e.printStackTrace();
		}

	}

	/**
	 * This private method executes the set name callback with the provided event
	 * type and event code.
	 * 
	 * @param setNameCallback - The callback function to execute.
	 * @param eventType       - The type of event.
	 * @param eventCode       - The code associated with the event.
	 */
	private void executeSetNameCallback(Function setNameCallback, String eventType, String eventCode) {
		try {
			setNameCallback.execute(new Object[] { eventType, eventCode });
			Log.d(LOG_TAG, "HID:executeSetNameCallback Callback Executed with EventType " + eventType);
			Log.d(LOG_TAG, "HID:executeSetNameCallback Callback Executed with EventCode " + eventCode);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			Log.e(LOG_TAG, "HID:executeSetNameCallback executeSetNameCallback Exception " + e.getStackTrace());
			e.printStackTrace();
		}
		Log.d(LOG_TAG, "HID:executeSetNameCallback executeSetNameCallback");
	}

	/**
	 * This public method retrieves the lock policy of the OTP key in the container.
	 * 
	 * @param otpLabel - The label of the OTP key (e.g., "hotp", "totp").
	 * @param code     - The code indicating the type of operation (e.g., "secure",
	 *                 "sign").
	 * @return string - The lock policy type as a string, or null if not found.
	 */
	public String getLockPolicy(String otpLabel, String code) {
		try {
			Log.d(LOG_TAG, "HID:getLockPolicy - otpLabel: " + otpLabel);
			Log.d(LOG_TAG, "HID:getLockPolicy - code: " + code);

			if (otpLabel == null || otpLabel.isEmpty()) {
				Log.d(LOG_TAG, "HID:getLockPolicy - otpLabel is null or empty");
				return null;
			}

			if (otpLabel == "hotp" || otpLabel == "totp") {
				if (code == ApproveSDKConstants.CODE_SECURE) {
					otpLabel = OtpKeyLabel.OATH_OCRA_HOTP_SIGN_LABEL.getCode();
					if (otpLabel.toLowerCase().equals(ApproveSDKConstants.TOTP_KEY)) {
						otpLabel = OtpKeyLabel.OATH_OCRA_TOTP_SIGN_LABEL.getCode();
						Log.d(LOG_TAG, "HID:getLockPolicy - otpLabel changed to: " + otpLabel);
					}
				}
				if (code == ApproveSDKConstants.CODE_SIGN) {
					otpLabel = OtpKeyLabel.OATH_OCRA_HOTP_SIGN_LABEL.getCode();
					if (otpLabel.toLowerCase().equals(ApproveSDKConstants.TOTP_KEY)) {
						otpLabel = OtpKeyLabel.OATH_OCRA_HOTP_SIGN_LABEL.getCode();
						Log.d(LOG_TAG, "HID:getLockPolicy - otpLabel changed to: " + otpLabel);
					}
				}

			}
			Container container = getSingleUserContainer();
			ProtectionPolicy otpKeyPolicy = container.getProtectionPolicy();
			Log.d(LOG_TAG, "HID:getLockPolicy - OTP key policy: " + otpKeyPolicy);
			if (otpKeyPolicy == null) {
				Log.d(LOG_TAG, "HID:getLockPolicy - No OTP key policy found");
				return null;
			}
			Log.d(LOG_TAG, "HID:getLockPolicy - OTP key policy found: " + otpKeyPolicy.getType());

			Parameter[] filter;
//			filter = new Parameter[] { new Parameter(SDKConstants.KEY_PROPERTY_LABEL, otpLabel.toCharArray()) };
			filter = new Parameter[] {
					new Parameter(SDKConstants.KEY_PROPERTY_USAGE, SDKConstants.KEY_PROPERTY_USAGE_OTP) };
			Key[] keys = container.findKeys(filter);
			Key otpKey = keys[0];
			Log.d(LOG_TAG, "HID:getLockPolicy - Key Length is " + keys.length);
			if (keys.length == 0) {
				Log.d(LOG_TAG, "HID:getLockPolicy - No OTP key found");
				return null;
			}
			if (keys.length > 1) {
				Log.d(LOG_TAG, "HID:getLockPolicy - More than one OTP key found");
				for (Key key : keys) {
					Log.d(LOG_TAG, "HID:getLockPolicy - Key: " + key);
					Log.d(LOG_TAG, "HID:getLockPolicy - Key found with label: "
							+ new String(key.getProperty(SDKConstants.KEY_PROPERTY_LABEL)));
					String keyLabel = new String(key.getProperty(SDKConstants.KEY_PROPERTY_LABEL));
					Log.d(LOG_TAG, "HID:getLockPolicy - Key label: " + keyLabel);

					if (keyLabel != null && keyLabel.contains(otpLabel)) {
						otpKey = key;
						Log.d(LOG_TAG, "HID:getLockPolicy - Using OTP key with label: " + otpLabel);
						break;
					}

				}
			}

			Log.d(LOG_TAG, "HID:getLockPolicy - OTP key found: " + otpKey);
			// Get protection policy of the OTP key
			otpKeyPolicy = otpKey.getProtectionPolicy();
			if (otpKeyPolicy == null) {
				Log.d(LOG_TAG, "HID:getLockPolicy - No OTP key policy found");
			}
			// Algorithm will indicate the opt algorithm for which the key is registered :
			// HOTP / TOTP / OCRA
			String algorithm = otpKey.getAlgorithm();
			Log.d(LOG_TAG, "HID:getLockPolicy - OTP key Algorithm: " + algorithm);

			// the label the key is registered with.
			char[] label = otpKey.getProperty(SDKConstants.KEY_PROPERTY_LABEL);
			Log.d(LOG_TAG, "HID:getLockPolicy - OTP key Label: " + new String(label));

			// Lock Policy Type
			String lockPolicyType = otpKeyPolicy.getLockPolicy().getType();
			Log.d(LOG_TAG, "HID:getLockPolicy - OTP key Lock Policy Type: " + lockPolicyType);
			return lockPolicyType;

		} catch (UnsupportedDeviceException ude) {
			Log.d(LOG_TAG, "HID:getLockPolicy: UnsupportedDeviceException " + ude.getStackTrace());
			ude.printStackTrace();
		} catch (LostCredentialsException lce) {
			Log.d(LOG_TAG, "HID:getLockPolicy: LostCredentialsException " + lce.getStackTrace());
			lce.printStackTrace();
		} catch (InternalException ie) {
			Log.d(LOG_TAG, "HID:getLockPolicy: InternalException " + ie.getStackTrace());
			ie.printStackTrace();
		} catch (InvalidParameterException ipe) {
			Log.d(LOG_TAG, "HID:getLockPolicy: InvalidParameterException " + ipe.getStackTrace());
			ipe.printStackTrace();
		} catch (Exception e) {
			Log.d(LOG_TAG, "HID:getLockPolicy: Exception " + e.getStackTrace());
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * This public method retrieves information about the device and its containers.
	 * 
	 * @return string - JSON formatted string containing device and container
	 *         information.
	 */
	public String getInfo(Context appContext) {
		this.appContext = appContext;
		String info = "";
		JSONObject deviceInfo = new JSONObject();
		JSONObject containerInfo = new JSONObject();
		JSONArray containerInfoArray = new JSONArray();
		JSONObject getInfo = new JSONObject();
		try {

			Device device = DeviceFactory.getDevice(appContext, new ConnectionConfiguration());

			deviceInfo.put("deviceBrand", new String(device.getDeviceInfo(SDKConstants.DEVICE_INFO_BRAND)));
			deviceInfo.put("deviceModel", new String(device.getDeviceInfo(SDKConstants.DEVICE_INFO_MODEL)));
			deviceInfo.put("deviceFriendlyName", new String(device.getDeviceInfo(SDKConstants.DEVICE_INFO_NAME)));
			deviceInfo.put("deviceOS", new String(device.getDeviceInfo(SDKConstants.DEVICE_INFO_OS)));
			deviceInfo.put("deviceOSName", new String(device.getDeviceInfo(SDKConstants.DEVICE_INFO_OS_NAME)));
			deviceInfo.put("deviceOSVersion", new String(device.getDeviceInfo(SDKConstants.DEVICE_INFO_OS_VERSION)));
			deviceInfo.put("deviceKeystore", new String(device.getDeviceInfo(SDKConstants.DEVICE_INFO_KEYSTORE)));
			deviceInfo.put("deviceInfoFingerprintEnrolled", new String(device.getDeviceInfo(SDKConstants.DEVICE_INFO_FPENROLLED)));
			deviceInfo.put("deviceInfoFingerprintCapability", new String(device.getDeviceInfo(SDKConstants.DEVICE_INFO_FPCAPABLE)));
			deviceInfo.put("deviceIsRooted", new String(device.getDeviceInfo(SDKConstants.DEVICE_INFO_ISROOTED)));
			deviceInfo.put("deviceHIDSDKVersion", device.getVersion());

			Container[] containers = device.findContainers(new Parameter[0]);
			if (containers.length == 0) {
				containerInfo.put("No containers found", "No containers found on the device.");
				containerInfoArray.put(containerInfo);
			}

			for (Container container : containers) {
				containerInfo.put("serverURL", container.getServerURL());
				containerInfo.put("serverDomain", new String(container.getProperty(SDKConstants.PROPERTY_DOMAIN)));
				containerInfo.put("serverVersion", new String(container.getProperty(SDKConstants.PROPERTY_PROTOCOL_VERSION)));
				containerInfo.put("deviceId", getDeviceProperty());
				containerInfo.put("containerId", container.getId());
				containerInfo.put("containerUserId", container.getUserId());
				containerInfo.put("containerFriendlyName", getContainerFriendlyName());
				containerInfo.put("containerCreationDate", container.getCreationDate().toString());
				containerInfo.put("containerExpirationDate", container.getExpiryDate().toString());
				containerInfo.put("isContainerRenewable", container.isRenewable(null));

				containerInfoArray.put(containerInfo);
			}

			getInfo.put("deviceInfo", deviceInfo);
			getInfo.put("containerInfo", containerInfoArray);
			

			info = getInfo.toString();
			Log.d(LOG_TAG, "HID:getInfo: Get Info: " + getInfo.toString());
		} catch (Exception e) {
			Log.d(LOG_TAG, "HID:getInfo: Exception " + e.getStackTrace());
			e.printStackTrace();
			return null;

		}
		return info;

	}

	/**
	 * This public method retrieves a list of keys from the container.
	 * 
	 * @return string - JSON formatted string containing key information.
	 */
	public String getKeyList() {
		JSONObject result = new JSONObject();
		JSONArray keyList = new JSONArray();
		try {
			Container container = getSingleUserContainer();

			if (container != null) {
				Key[] keys = container.findKeys(new Parameter[0]);
				for (Key key : keys) {
					JSONObject keyInfo = new JSONObject();

					keyInfo.put("keyId", key.getId());
					keyInfo.put("keyLabel", new String(key.getProperty(SDKConstants.KEY_PROPERTY_LABEL)));
					keyInfo.put("keyUsage", new String(key.getProperty(SDKConstants.KEY_PROPERTY_USAGE)));
					keyInfo.put("keyCreationDate", new String(this.formatDate(key.getProperty(SDKConstants.KEY_PROPERTY_CREATE))));
					keyInfo.put("keyExpiryDate", new String(this.formatDate(key.getProperty(SDKConstants.KEY_PROPERTY_EXPIRY))));

					// Extract policy details
					ProtectionPolicy keyPolicy = key.getProtectionPolicy();
					if (keyPolicy != null) {
						keyInfo.put("keyPolicyType", keyPolicy.getType());
						keyInfo.put("keyProtectionPolicyId", keyPolicy.getId().getId());
						keyInfo.put("keyLockPolicyType", keyPolicy.getLockPolicy().getType());
						if (keyPolicy instanceof PasswordPolicy || keyPolicy instanceof BioPasswordPolicy) {
							keyInfo.put("keyCurrentAge", String.valueOf(((PasswordPolicy) keyPolicy).getCurrentAge()));
						}
					} else {
						keyInfo.put("keyPolicyType", JSONObject.NULL);
						keyInfo.put("keyProtectionPolicyId", JSONObject.NULL);
						keyInfo.put("keyLockPolicyType", JSONObject.NULL);
						keyInfo.put("keyCurrentAge", JSONObject.NULL);
					}

					keyList.put(keyInfo);
				}
			}

			
			result.put("containerId", container.getId());
			result.put("containerUserId", container.getUserId());
			result.put("totalKeys", keyList.length());
			result.put("keys", keyList);

			Log.d(LOG_TAG, "HID:getKeyList: Key List: " + result.toString());

		} catch (Exception e) {
			Log.d(LOG_TAG, "HID:getKeyList: Exception " + e.getStackTrace());
			e.printStackTrace();
			return null;
		}
		return result.toString();
	}
	
	/**
	 * This private method formats the date from a char array to a human-readable
	 * string.
	 * 
	 * @param input - The char array containing the date value.
	 * @return char[] - The formatted date as a char array.
	 */
	private char[] formatDate(char[] input) {
	    String value = "-1";
	    if (input != null)
	        value = new String(input);

	    // Format style: e.g., "Wed Jul 09 13:14:51 GMT+05:30 2025"
	    SimpleDateFormat sdf = new SimpleDateFormat("EEE MMM dd HH:mm:ss z yyyy");

	    try {
	        long dateMillis = Long.parseLong(value);
	        if (dateMillis <= 0)
	            value = "never"; // no expiration
	        else
	            value = sdf.format(new Date(dateMillis));
	    } catch (Exception e) {
	        Log.w(LOG_TAG, "formatDate: Invalid input", e);
	    }

	    return value.toCharArray();
	}

	
	
	/**
	 * This public method generates authentication request for direct client signature and then calls directClientSignatureStatus to complete the signing process.
	 * 
	 * @param appContext  - Context of the application.
	 * @param activity    - FragmentActivity to run the operation in.
	 * @param txMessage   - The transaction message to sign.
	 * @param keyMode     - The key mode to use (e.g., "pkp", "pkip", "skp").
	 * @param dcsCallback - The callback function to execute after signing.
	 */
	public void directClientSignature(Context appContext, FragmentActivity activity, String txMessage, String keyMode, Function generateCallback) {
		this.transactionMonitor = new TransactionMonitor();
		
		new Thread(() -> {
			this.appContext = appContext;
			this.activity = activity;
			String keyLabel = null;
			Log.d(LOG_TAG, "HID:directClientSignature: Inside directClientSignature");
			Log.d(LOG_TAG, "HID:directClientSignature: Transaction Message: " + txMessage);
			Log.d(LOG_TAG, "HID:directClientSignature: Key Mode: " + keyMode); //keyMode can be "pkp","pkip","skp".
            try {
    			//Assigning the key based on the keyMode
    			if (keyMode == null || keyMode.isEmpty()) {
    				Log.d(LOG_TAG, "HID:directClientSignature: Key Mode is null or empty");
    				genericExecuteCallback("KeyModeNull", "Key Mode is null or empty", generateCallback);
    				return;
    			}else {
    				switch (keyMode.toLowerCase()) {
    					case "pkp":
    						keyLabel = OtpKeyLabel.PUSH_KEY_PUBLIC_LABEL.getCode();
    						Log.d(LOG_TAG, "HID:directClientSignature: Key Label set to: " + keyLabel);
    						break;
    					case "pkip":
    						keyLabel = OtpKeyLabel.PUSH_KEY_IDP_PUBLIC_LABEL.getCode();
    						Log.d(LOG_TAG, "HID:directClientSignature: Key Label set to: " + keyLabel);
    						break;
    					case "skp":
    						keyLabel = OtpKeyLabel.SIGN_KEY_PUBLIC_LABEL.getCode();
    						Log.d(LOG_TAG, "HID:directClientSignature: Key Label set to: " + keyLabel);
    						break;
    					default:
    						Log.d(LOG_TAG, "HID:directClientSignature: Invalid Key Mode: " + keyMode);
    						genericExecuteCallback("InvalidKeyMode", "Invalid Key Mode", generateCallback);
    						return;
    				}
    			}
    			
    			Container container = getSingleUserContainer();
    			
    			Key[] keys = container.findKeys(new Parameter[0]);
    			
    			if (keys.length == 0) {
    				Log.d(LOG_TAG, "HID:directClientSignature: No keys found in the container");
    				genericExecuteCallback("NoKeysFound", "No keys found in the container", generateCallback);
    				return;
    			}
    			
    			Key otpKey = keys[0];
    			
    			//Key Check
    			if (keys.length > 1) {
    				Log.d(LOG_TAG, "HID:directClientSignature - More than one OTP key found");
    				for (Key key : keys) {
    					Log.d(LOG_TAG, "HID:directClientSignature - Key: " + key);
    					
    					String keyCheck = new String(key.getProperty(SDKConstants.KEY_PROPERTY_LABEL));
    					
    					Log.d(LOG_TAG, "HID:directClientSignature - Key found with label: "
    							+ keyCheck);

    					if (keyCheck != null && keyCheck.equals(keyLabel)) {
    						otpKey = key;
    						Log.d(LOG_TAG, "HID:directClientSignature - Found Matched Key: " + otpKey);
    						break;
    					}

    				}
    			}
    			
    			Log.d(LOG_TAG, "HID:directClientSignature - Key found: " + otpKey);
    			
    			String keyId = otpKey.getId().toString();
    			Log.d(LOG_TAG, "HID:directClientSignature - Key ID: "
    					+ keyId);
    			
    			
    			if(txMessage == null || txMessage.isEmpty()) {
    				Log.d(LOG_TAG, "HID:directClientSignature: Transaction message is empty");
    				genericExecuteCallback("TransactionMessageEmpty", "Transaction message is empty", generateCallback);
    				return;
    			}else {
    				Log.d(LOG_TAG, "HID:directClientSignature: Transaction message: " + txMessage);
    				Transaction transaction = container.generateAuthenticationRequest(txMessage, otpKey.getId());
    				
    				transactionMonitor.setTransaction(transaction);
    				
    				Log.d(LOG_TAG, "HID:directClientSignature: Transaction generated successfully");
    				Log.d(LOG_TAG, "HID:directClientSignature: Transaction: " + transaction);
    				Log.d(LOG_TAG, "HID:directClientSignature: Transaction ID: " + transaction.getPayload());
    				Log.d(LOG_TAG, "HID:directClientSignature: Transaction Signing Key: " + transaction.getSigningKey());
    				Log.d(LOG_TAG, "HID:directClientSignature: Transaction Request Id: " + transaction.getRequestId());
    				
    				JSONObject transactionJson = new JSONObject();
    				transactionJson.put("transaction", transaction != null ? transaction : "");
    				transactionJson.put("transactionPayload", transaction.getPayload() != null ? transaction.getPayload().toString() : "");
    				transactionJson.put("keyLabel", otpKey.getProperty(SDKConstants.KEY_PROPERTY_LABEL) != null ? new String(otpKey.getProperty(SDKConstants.KEY_PROPERTY_LABEL)) : "");
    				transactionJson.put("keyId", keyId != null ? keyId : "");
    				Log.d(LOG_TAG, "HID:directClientSignature: Transaction generated successfully for key: " + keyMode + " with Id: " + keyId);
    				Log.d(LOG_TAG, "HID:directClientSignature: Transaction JSON: " + transactionJson.toString());
    				genericExecuteCallback("success", transactionJson.toString(), generateCallback);
    			}

            } catch(InternalException ie) {
    			Log.d(LOG_TAG, "HID:directClientSignature: InternalException " + ie.getStackTrace());
    			ie.printStackTrace();
    			genericExecuteCallback("InternalException", ie.getMessage(), generateCallback);
    		}catch(InvalidParameterException ipe) {
    			Log.d(LOG_TAG, "HID:directClientSignature: InvalidParameterException " + ipe.getStackTrace());
    			ipe.printStackTrace();
    			genericExecuteCallback("InvalidParameterException", ipe.getMessage(), generateCallback);
    		}catch(ServerUnsupportedOperationException sue) {
    			Log.d(LOG_TAG, "HID:directClientSignature: ServerUnsupportedOperationException " + sue.getStackTrace());
    			sue.printStackTrace();
    			genericExecuteCallback("ServerUnsupportedOperationException", sue.getMessage(), generateCallback);
    		}catch(LostCredentialsException lce) {
    			Log.d(LOG_TAG, "HID:directClientSignature: LostCredentialsException " + lce.getStackTrace());
    			lce.printStackTrace();
    			genericExecuteCallback("LostCredentialsException", lce.getMessage(), generateCallback);
    		}catch(UnsupportedDeviceException ude) {
    			Log.d(LOG_TAG, "HID:directClientSignature: UnsupportedDeviceException " + ude.getStackTrace());
    			ude.printStackTrace();
    			genericExecuteCallback("UnsupportedDeviceException", ude.getMessage(), generateCallback);
    		}catch(Exception e) {
    			Log.d(LOG_TAG, "HID:directClientSignature: Exception " + e.getStackTrace());
    			e.printStackTrace();
    			genericExecuteCallback("Exception", e.getMessage(), generateCallback);
    		}
        }).start();
	}
	
	/**
	 * This public method is used to sign the request for the request generated in directClientSignature method.
	 * 
	 * @param consensus - status of the transaction (e.g., "approve").
	 * @param password - password for the transaction, if required.
	 * @param isBiometricEnabled - boolean indicating if biometric authentication is enabled.
	 * @param dcsCallback - The callback function to execute after signing with status.
	 * @throws Exception - Throws an exception if the transaction monitor is not initialized or if an error occurs during the signing process.
	 */
	public void directClientSignatureWithStatus(String consensus, String password, boolean isBiometricEnabled, Function dcsCallback) throws Exception {
	    if (transactionMonitor != null) {
	        synchronized (transactionMonitor) {
	        	transactionMonitor.setUserInput(consensus, password, isBiometricEnabled);
	        	transactionMonitor.notify();

	            // Wait for transaction to be available and complete status update
	            new Thread(() -> {
	                try {
	                    Transaction transaction = transactionMonitor.getTransaction();
	                    Container container = getSingleUserContainer();

	                    if (transaction == null) {
	                    	dcsCallback.execute(new Object[]{"TransactionNotFound", "No transaction available"});
	                        return;
	                    }

	                    boolean result;
	                    if (isBiometricEnabled) {
	                        BiometricAuthService bioAuthService = new BiometricAuthService();
	                        bioAuthService.setBiometricPrompt(activity, ApproveSDKConstants.BIO_PROMPT_TITLE_PUSH_FLOW,
	                                container.getProtectionPolicy(), new FingerprintHandler.BiometricEventListener() {
	                                    @Override
	                                    public void onAuthSuccess() {
	                                        
	                                    }

	                                    @Override
	                                    public void onAuthFailed() {
	                                        
	                                    }

	                                    @Override
	                                    public void onAuthError() {
	                                        
	                                    }
	                                });
	                        
	                        result = transaction.setStatus(consensus, null, null, new Parameter[0]);
                            sendTransactionStatusResult(transaction, result, dcsCallback);
	                    } else {
	                        result = transaction.setStatus(consensus, password.toCharArray(), null, new Parameter[0]);
	                        sendTransactionStatusResult(transaction, result, dcsCallback);
	                    }

	                } catch (Exception e) {
	                	try {
							handleSetStatusException(e, dcsCallback);
						} catch (Exception e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}
	                } 
	            }).start();
	        }
	    } else {
	    	dcsCallback.execute(new Object[]{"MonitorNotInitialized", "Transaction monitor not available"});
	    }
	}
	
	/**
	 * This private method sends the transaction status result to the callback.
	 * 
	 * @param transaction - The transaction object containing the transaction.
	 * @param result      - The result of the transaction status update.
	 * @param dcsCallback - The callback function to execute with the result.
	 * @throws Exception
	 */
	private void sendTransactionStatusResult(Transaction transaction, boolean result, Function dcsCallback) throws Exception {
	    try {
	        JSONObject resultJson = new JSONObject();
	        resultJson.put("status", result ? "success" : "failure");
	        resultJson.put("requestId", transaction.getRequestId());
	        resultJson.put("idToken", transaction.getIdToken());

	        Log.d(LOG_TAG, "HID:sendTransactionStatusResult Completed Result " + result);
	        Log.d(LOG_TAG, "HID:sendTransactionStatusResult Completed RequestId " + transaction.getRequestId());
	        Log.d(LOG_TAG, "HID:sendTransactionStatusResult Completed IdToken " + transaction.getIdToken());

	        dcsCallback.execute(new Object[]{"TransactionStatus", resultJson.toString()});
	    } catch (JSONException e) {
	    	dcsCallback.execute(new Object[]{"JSONException", e.getMessage()});
	    }
	}
	
	/*
	 * This private method handles exceptions that may occur during the direct client signature set status operation.
	 * 
	 * @param e - The exception that occurred.
	 * @param callback - The callback function to execute with the exception details.
	 * @throws Exception - Throws the exception if it is not handled.
	 */
	private void handleSetStatusException(Exception e, Function callback) throws Exception {
	    String type = e.getClass().getSimpleName();
	    String message = e.getMessage();

	    Log.d(LOG_TAG, "HID:handleSetStatusException Exception: " + type + " - " + message);

	    switch (type) {
	        case "AuthenticationException":
	        	callback.execute(new Object[]{type, message});
	            break;
	        case "PasswordRequiredException":
	            callback.execute(new Object[]{type, message});
	            break;
	        case "FingerprintAuthenticationRequiredException":
	            callback.execute(new Object[]{type, message});
	            break;
	        case "TransactionExpiredException":
	            callback.execute(new Object[]{type, message});
	            break;
	        case "PasswordExpiredException":
	            callback.execute(new Object[]{type, message});
	            break;
	        case "InternalException":
	        	callback.execute(new Object[]{type, message});
	            break;
	        case "InvalidParameterException":
	        	callback.execute(new Object[]{type, message});
	            break;
	        case "UnsupportedDeviceException":
	        	callback.execute(new Object[]{type, message});
	            break;
	        case "LostCredentialsException":
	        	callback.execute(new Object[]{type, message});
	            break;
	        case "InvalidContainerException":
	        	callback.execute(new Object[]{type, message});
	            break;
	        case "InexplicitContainerException":
	        	callback.execute(new Object[]{type, message});
	            break;
	        case "ServerVersionException":
	        	callback.execute(new Object[]{type, message});
	            break;
	        case "RemoteException":
	        	callback.execute(new Object[]{type, message});
	            break;
	        case "ServerOperationFailedException":
	            callback.execute(new Object[]{type, message});
	            break;
	        default:
	            callback.execute(new Object[]{"Exception", message});
	            break;
	    }
	}

	
}
