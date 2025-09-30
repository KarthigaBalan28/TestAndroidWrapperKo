package com.hid;

import org.json.JSONException;
import org.json.JSONObject;

import com.hidglobal.ia.service.beans.Event;
import com.hidglobal.ia.service.beans.EventListener;
import com.hidglobal.ia.service.beans.EventResult;
import com.hidglobal.ia.service.beans.PasswordPromptEvent;
import com.hidglobal.ia.service.beans.PasswordPromptResult;
import com.hidglobal.ia.service.protectionpolicy.PasswordPolicy;
import com.konylabs.vm.Function;

import android.content.Context;
import android.util.Log;
@SuppressWarnings({"java:S1068", "java:S2142"})
public class EventListenerCallback implements EventListener {
	private Context appContext;
	private WaitNotifyMonitor monitor;
	private Function promptCallback;
	private static final String LOG_TAG = ApproveSDKConstants.HID_LOG_TAG;

	public EventListenerCallback(Context appContext, Function promptCallback, WaitNotifyMonitor monitor) {
		this.appContext = appContext;
		this.promptCallback = promptCallback;
		this.monitor = monitor;
	}

	@Override
	public EventResult onEventReceived(Event event) {
		Log.d(LOG_TAG, "HID:EventListenerCallback Event Triggered");
		if (event instanceof PasswordPromptEvent) {
			Log.d(LOG_TAG, "HID:EventListenerCallback onEventReceived Waiting for Password Input");
			PasswordPromptEvent passwordPromptEvent = (PasswordPromptEvent) event;
			PasswordPolicy policy = passwordPromptEvent.getPasswordPolicy();
			JSONObject obj = new JSONObject();
			try {
				obj.put("minLength", policy.getMinLength());
				obj.put("maxLength", policy.getMaxLength());
				obj.put("minNumeric", policy.getMinNumeric());
				obj.put("maxNumeric", policy.getMaxNumeric());
				obj.put("minAlpha", policy.getMinAlpha());
				obj.put("maxAlpha", policy.getMaxAlpha());
				obj.put("maxUpperCase", policy.getMaxUpperCase());
				obj.put("minUpperCase", policy.getMinUpperCase());
				obj.put("maxLowerCase", policy.getMaxLowerCase());
				obj.put("minLowerCase", policy.getMinLowerCase());
				obj.put("maxAge", policy.getMaxAge());
				obj.put("maxSpl", policy.getMaxNonAlpha());
				obj.put("minSpl", policy.getMinNonAlpha());
			} catch (JSONException e2) {
				Log.d(LOG_TAG, "HID:EventListenerCallback onEventReceived JSONException" + e2.getStackTrace());
				e2.printStackTrace();
			}

			Object[] params = new Object[2];
			params[0] = policy.toString();
			params[1] = obj.toString();
			try {
				promptCallback.execute(params);
			} catch (Exception e1) {
				Log.d(LOG_TAG, "HID:EventListenerCallback onEventReceived Exception" + e1.getStackTrace());
				e1.printStackTrace();
			}
			synchronized (monitor) {
				try {
					monitor.wait();
				} catch (InterruptedException e) {
					Log.d(LOG_TAG, "HID:EventListenerCallback onEventReceived InterruptedException" + e.getStackTrace());
					e.printStackTrace();
				}
				Log.d(LOG_TAG, "HID:EventListenerCallback onEventReceived Got notified with Password");
				PasswordPromptResult result = new PasswordPromptResult(EventResult.Code.Continue);
				result.setPassword(monitor.getMsg().toCharArray());
				return result;
			}
		} else {
			Log.d(LOG_TAG, "HID:EventListenerCallback onEventReceived Event is not PasswordPromptEvent");
			// Handle other event types if needed
		}
		return null;
	}
}
