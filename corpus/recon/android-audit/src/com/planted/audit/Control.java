package com.planted.audit;

import android.content.Context;
import android.content.pm.PackageManager;
import android.database.sqlite.SQLiteDatabase;
import android.net.http.SslError;
import android.webkit.SslErrorHandler;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

public final class Control {
    private Control() {}

    public static Cipher cipher() throws GeneralSecurityException {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    public static Cipher rsa() throws GeneralSecurityException {
        return Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    }

    public static MessageDigest digest() throws GeneralSecurityException {
        return MessageDigest.getInstance("SHA-256");
    }

    public static SecretKeySpec key(SecureRandom random) {
        byte[] key = new byte[32];
        random.nextBytes(key);
        return new SecretKeySpec(key, "AES");
    }

    public static IvParameterSpec iv(SecureRandom random) {
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static int dice() {
        return new Random().nextInt(6);
    }

    public static SSLContext tls() throws GeneralSecurityException {
        return SSLContext.getInstance("TLSv1.3");
    }

    static final class Pinned implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            throw new CertificateException("client certificates are not accepted");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            if (chain == null || chain.length == 0) {
                throw new CertificateException("empty chain");
            }
            chain[0].checkValidity();
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    static final class StrictHosts implements HostnameVerifier {
        @Override
        public boolean verify(String host, SSLSession session) {
            return "example.com".equals(host);
        }
    }

    static final class FailSslErrors extends WebViewClient {
        @Override
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            handler.cancel();
        }
    }

    public static FileOutputStream privateFile(Context ctx) throws IOException {
        return ctx.openFileOutput("notes.txt", Context.MODE_PRIVATE);
    }

    public static File appFiles(Context ctx) {
        return ctx.getFilesDir();
    }

    public static File internalPath(Context ctx) {
        return new File(ctx.getFilesDir(), "export.csv");
    }

    public static void boundQuery(SQLiteDatabase db, String name) {
        db.execSQL("DELETE FROM users WHERE name = ?", new Object[] {name});
    }

    public static void webview(WebView view) {
        WebSettings settings = view.getSettings();
        settings.setJavaScriptEnabled(false);
        settings.setAllowFileAccessFromFileURLs(false);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        settings.setSavePassword(false);
    }

    public static boolean isGeneric(String fingerprint) {
        return fingerprint.startsWith("generic");
    }

    public static boolean exists(File file) {
        return file.exists();
    }

    public static void loadLibrary() {
        System.loadLibrary("native");
    }

    public static String versionName(Context ctx, PackageManager packages)
            throws PackageManager.NameNotFoundException {
        return packages.getPackageInfo(ctx.getPackageName(), 0).versionName;
    }
}
