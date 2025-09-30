package com.hid;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.hidglobal.ia.service.beans.Parameter;
import com.hidglobal.ia.service.exception.FingerprintAuthenticationRequiredException;
import com.hidglobal.ia.service.exception.InternalException;
import com.hidglobal.ia.service.exception.InvalidParameterException;
import com.hidglobal.ia.service.exception.RemoteException;
import com.hidglobal.ia.service.exception.UnsupportedDeviceException;
import com.hidglobal.ia.service.transaction.Container;
import com.konylabs.vm.Function;

import android.content.Context;
import android.util.Log;
@SuppressWarnings({"java:S1854"})
public class RetrievePendingNotifications implements Runnable {
	private Container container;
	private Function onRetrieveNotificationsCallback;
	private static final String LOG_TAG = ApproveSDKConstants.HID_LOG_TAG;
	private static final String FAILURE = "failure";

	public RetrievePendingNotifications(Container container, Function onRetrieveNotificationsCallback) {
		this.container = container;
		this.onRetrieveNotificationsCallback = onRetrieveNotificationsCallback;
	}

	public void run() {
		JSONObject jsonOBJ = new JSONObject();
		JSONArray jsonArray = new JSONArray();
		try {
			char[][] txidsChartArray = new char[0][0];
			txidsChartArray = container.retrieveTransactionsIds(null, new Parameter[0]);
			Log.d(LOG_TAG, "HID:retrievePendingNotifications ApproveSDK-->retrieveArrayLength :" + txidsChartArray.length);
			for (int i = 0; i < txidsChartArray.length; i++) {
				jsonArray.put(i, new String(txidsChartArray[i]));
				Log.d(LOG_TAG, "HID:retrievePendingNotifications ApproveSDK-->retrieveID :" + String.valueOf(txidsChartArray[i]) + " " + i);
			}
			jsonOBJ.put("txIDs", jsonArray);
			String retrieveIds = jsonOBJ.toString();

			if (jsonArray.length() != 0)
				onRetrieveNotificationsCallback("success", retrieveIds, onRetrieveNotificationsCallback);
			else
				onRetrieveNotificationsCallback(FAILURE, retrieveIds, onRetrieveNotificationsCallback);

		} catch (RemoteException e) {
			onRetrieveNotificationsCallback(FAILURE, "RemoteException", onRetrieveNotificationsCallback);
			Log.d(LOG_TAG, "HID:retrievePendingNotifications ApproveSDK-->RemoteException" + e.getStackTrace());
			e.printStackTrace();
		} catch (InternalException e) {
			onRetrieveNotificationsCallback(FAILURE, "InternalException", onRetrieveNotificationsCallback);
			Log.d(LOG_TAG, "HID:retrievePendingNotifications ApproveSDK-->InternalException" + e.getStackTrace());
			e.printStackTrace();
			e.getCause();
		} catch (FingerprintAuthenticationRequiredException e) {
			onRetrieveNotificationsCallback(FAILURE, "FingerprintAuthenticationRequiredException",
					onRetrieveNotificationsCallback);
			Log.d(LOG_TAG, "HID:retrievePendingNotifications ApproveSDK-->FingerprintAuthenticationRequiredException" + e.getStackTrace());
			e.printStackTrace();
		} catch (JSONException e) {
			onRetrieveNotificationsCallback(FAILURE, "JSONException", onRetrieveNotificationsCallback);
			Log.d(LOG_TAG, "HID:retrievePendingNotifications ApproveSDK-->JSONException" + e.getStackTrace());
			e.printStackTrace();
		} catch (UnsupportedDeviceException e) {
			onRetrieveNotificationsCallback(FAILURE, "UnsupportedDeviceException", onRetrieveNotificationsCallback);
			Log.d(LOG_TAG, "HID:retrievePendingNotifications ApproveSDK-->UnsupportedDeviceException" + e.getStackTrace());
			e.printStackTrace();
		} catch (InvalidParameterException e) {
			onRetrieveNotificationsCallback(FAILURE, "InvalidParameterException", onRetrieveNotificationsCallback);
			Log.d(LOG_TAG, "HID:retrievePendingNotifications ApproveSDK-->InvalidParameterException" + e.getStackTrace());
			e.printStackTrace();
		} catch (Exception e) {
			onRetrieveNotificationsCallback(FAILURE, "Exception", onRetrieveNotificationsCallback);
			Log.d(LOG_TAG, "HID:retrievePendingNotifications ApproveSDK-->Exception" + e.getStackTrace());
			e.printStackTrace();
		}
	}

	private void onRetrieveNotificationsCallback(String message, String ids, Function callback) {
		Object[] params = new Object[2];
		params[0] = message;
		params[1] = ids;
		try {
			callback.execute(params);
		} catch (Exception e) {
			Log.d(LOG_TAG, "HID:retrievePendingNotifications ApproveSDK-->Exception" + e.getStackTrace());
			e.printStackTrace();
		}
	}

}
