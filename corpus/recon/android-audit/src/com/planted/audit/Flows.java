package com.planted.audit;

import android.content.ClipboardManager;
import android.location.Location;
import android.location.LocationManager;
import android.telephony.SmsManager;
import android.telephony.TelephonyManager;
import android.util.Log;

public final class Flows {
    private Flows() {}

    public static void imeiToSms(TelephonyManager telephony, SmsManager sms, String number) {
        String imei = telephony.getDeviceId();
        sms.sendTextMessage(number, null, imei, null, null);
    }

    public static void imsiToLog(TelephonyManager telephony) {
        Log.d("Flows", telephony.getSubscriberId());
    }

    public static String locationToLog(LocationManager locations) {
        Location last = locations.getLastKnownLocation(LocationManager.GPS_PROVIDER);
        String text = String.valueOf(last);
        Log.i("Flows", text);
        return text;
    }

    public static void clipboardToSms(ClipboardManager clipboard, SmsManager sms, String number) {
        CharSequence clip = clipboard.getText();
        sms.sendTextMessage(number, null, String.valueOf(clip), null, null);
    }

    public static void separateSourceAndSink(TelephonyManager telephony, SmsManager sms, String number) {
        String imei = telephony.getDeviceId();
        if (imei == null) {
            return;
        }
        sms.sendTextMessage(number, null, "hello", null, null);
    }

    public static String sourceOnly(TelephonyManager telephony) {
        return telephony.getLine1Number();
    }
}
