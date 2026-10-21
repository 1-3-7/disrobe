package com.planted.audit;

import android.content.ClipboardManager;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import com.google.android.gms.safetynet.SafetyNetClient;
import com.google.android.play.core.integrity.IntegrityManager;
import android.database.sqlite.SQLiteDatabase;
import android.hardware.Camera;
import android.location.Location;
import android.location.LocationManager;
import android.media.MediaRecorder;
import android.net.http.SslError;
import android.os.Build;
import android.os.Debug;
import android.os.Environment;
import android.provider.Settings;
import android.telephony.SmsManager;
import android.telephony.TelephonyManager;
import android.util.Log;
import android.webkit.SslErrorHandler;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import dalvik.system.DexClassLoader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;
import org.apache.http.conn.ssl.AllowAllHostnameVerifier;
import org.apache.http.conn.ssl.SSLSocketFactory;

public final class Plants {
    private Plants() {}

    public static Cipher cryptoWeakCipher() throws GeneralSecurityException {
        return Cipher.getInstance("DES/CBC/PKCS5Padding");
    }

    public static Cipher cryptoEcb() throws GeneralSecurityException {
        return Cipher.getInstance("AES/ECB/PKCS5Padding");
    }

    public static Cipher cryptoBareAes() throws GeneralSecurityException {
        return Cipher.getInstance("AES");
    }

    public static Cipher cryptoRsaNoOaep() throws GeneralSecurityException {
        return Cipher.getInstance("RSA/ECB/PKCS1Padding");
    }

    public static MessageDigest cryptoWeakHash() throws GeneralSecurityException {
        return MessageDigest.getInstance("MD5");
    }

    public static SecureRandom cryptoSeededRandom() {
        SecureRandom random = new SecureRandom();
        random.setSeed(42L);
        return random;
    }

    public static byte[] cryptoInsecureRandom() {
        Random random = new Random();
        byte[] key = new byte[16];
        random.nextBytes(key);
        return new SecretKeySpec(key, "AES").getEncoded();
    }

    public static SecretKeySpec cryptoHardcodedKey() {
        return new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
    }

    public static IvParameterSpec cryptoStaticIv() {
        return new IvParameterSpec("fixed-iv-16bytes".getBytes());
    }

    public static SSLContext sslWeakProtocol() throws GeneralSecurityException {
        return SSLContext.getInstance("SSLv3");
    }

    static final class TrustAll implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }

    static final class AllowAllHosts implements HostnameVerifier {
        @Override
        public boolean verify(String host, SSLSession session) {
            return true;
        }
    }

    static final class IgnoreSslErrors extends WebViewClient {
        @Override
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            handler.proceed();
        }
    }

    public static HostnameVerifier sslApacheAllowAllField() {
        return SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
    }

    public static HostnameVerifier sslApacheAllowAllCtor() {
        return new AllowAllHostnameVerifier();
    }

    public static FileOutputStream storageWorldAccessible(Context ctx) throws IOException {
        return ctx.openFileOutput("notes.txt", Context.MODE_WORLD_READABLE);
    }

    public static File storageExternal() {
        return Environment.getExternalStorageDirectory();
    }

    public static File storageSdcardPath() {
        return new File("/sdcard/Download/export.csv");
    }

    public static File storageTempFile() throws IOException {
        return File.createTempFile("cache", ".bin");
    }

    public static void sqlDynamicQuery(SQLiteDatabase db, String name) {
        db.execSQL("DELETE FROM users WHERE name = '" + name + "'");
    }

    public static void webviewJavascript(WebView view) {
        view.getSettings().setJavaScriptEnabled(true);
    }

    public static void webviewFileAccess(WebView view) {
        view.getSettings().setAllowFileAccessFromFileURLs(true);
    }

    public static void webviewMixedContent(WebView view) {
        view.getSettings().setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
    }

    public static void webviewSavePassword(WebView view) {
        view.getSettings().setSavePassword(true);
    }

    public static void webviewJsInterface(WebView view, Object bridge) {
        view.addJavascriptInterface(bridge, "Android");
    }

    public static void webviewDebugging() {
        WebView.setWebContentsDebuggingEnabled(true);
    }

    public static void logCall(String state) {
        Log.d("Plants", state);
    }

    public static void logSensitive(String password) {
        Log.i("Plants", "password=" + password);
    }

    public static Process execCommand() throws IOException {
        return Runtime.getRuntime().exec("ls -l /data");
    }

    public static Process rootSuCommand() throws IOException {
        return Runtime.getRuntime().exec("su");
    }

    public static boolean rootDetection() {
        return new File("/system/xbin/su").exists();
    }

    public static boolean emulatorCheck() {
        return Build.FINGERPRINT.startsWith("generic");
    }

    public static boolean debuggerCheck() {
        return Debug.isDebuggerConnected();
    }

    public static ClassLoader dynamicCodeLoading(Context ctx, String dexPath) {
        return new DexClassLoader(
                dexPath, ctx.getCodeCacheDir().getPath(), null, Plants.class.getClassLoader());
    }

    public static void nativeLoadPath(String path) {
        System.load(path);
    }

    public static Object reflection(Method method, Object target)
            throws ReflectiveOperationException {
        return method.invoke(target);
    }

    public static String deviceIdentifier(TelephonyManager telephony) {
        return telephony.getDeviceId();
    }

    public static String deviceIdentifierAndroidId(Context ctx) {
        return Settings.Secure.getString(ctx.getContentResolver(), Settings.Secure.ANDROID_ID);
    }

    public static String deviceIdentifierSerial() {
        return Build.SERIAL;
    }

    public static void smsSend(String number, String text) {
        SmsManager.getDefault().sendTextMessage(number, null, text, null, null);
    }

    public static CharSequence clipboardRead(ClipboardManager clipboard) {
        return clipboard.getText();
    }

    public static MediaRecorder audioCapture() {
        MediaRecorder recorder = new MediaRecorder();
        recorder.setAudioSource(MediaRecorder.AudioSource.MIC);
        return recorder;
    }

    public static Camera cameraCapture() {
        return Camera.open();
    }

    public static Location locationAccess(LocationManager locations) {
        return locations.getLastKnownLocation(LocationManager.GPS_PROVIDER);
    }

    public static List<PackageInfo> installedApps(PackageManager packages) {
        return packages.getInstalledPackages(0);
    }

    public static PackageInfo signatureCheck(Context ctx)
            throws PackageManager.NameNotFoundException {
        return ctx.getPackageManager()
                .getPackageInfo(ctx.getPackageName(), PackageManager.GET_SIGNATURES);
    }

    public static boolean fridaCheck() {
        return new File("/data/local/tmp/re.frida.server").exists();
    }

    public static Object playIntegrity(IntegrityManager integrity, Object request) {
        return integrity.requestIntegrityToken(request);
    }

    public static Object safetyNetAttest(SafetyNetClient client, byte[] nonce) {
        return client.attest(nonce, "api-key-placeholder");
    }
}
