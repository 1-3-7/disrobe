package com.google.android.gms.safetynet;

public interface SafetyNetClient {
    Object attest(byte[] nonce, String apiKey);
}
