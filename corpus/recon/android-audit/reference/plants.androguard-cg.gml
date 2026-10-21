graph [
  directed 1
  node [
    id 0
    label "Lcom/google/android/gms/safetynet/SafetyNetClient;->attest([B Ljava/lang/String;)Ljava/lang/Object; [access_flags=public abstract] @ 0x0"
    external 0
    entrypoint 0
    methodname "attest"
    descriptor "([B Ljava/lang/String;)Ljava/lang/Object;"
    accessflags "public abstract"
    classname "Lcom/google/android/gms/safetynet/SafetyNetClient;"
  ]
  node [
    id 1
    label "Lcom/google/android/play/core/integrity/IntegrityManager;->requestIntegrityToken(Ljava/lang/Object;)Ljava/lang/Object; [access_flags=public abstract] @ 0x0"
    external 0
    entrypoint 0
    methodname "requestIntegrityToken"
    descriptor "(Ljava/lang/Object;)Ljava/lang/Object;"
    accessflags "public abstract"
    classname "Lcom/google/android/play/core/integrity/IntegrityManager;"
  ]
  node [
    id 2
    label "Lcom/planted/audit/Plants$AllowAllHosts;-><init>()V [access_flags=constructor] @ 0xcb4"
    external 0
    entrypoint 0
    methodname "<init>"
    descriptor "()V"
    accessflags "constructor"
    classname "Lcom/planted/audit/Plants$AllowAllHosts;"
  ]
  node [
    id 3
    label "Ljava/lang/Object;-><init>()V"
    external 1
    entrypoint 0
    methodname "<init>"
    descriptor "()V"
    accessflags ""
    classname "Ljava/lang/Object;"
  ]
  node [
    id 4
    label "Lcom/planted/audit/Plants$AllowAllHosts;->verify(Ljava/lang/String; Ljavax/net/ssl/SSLSession;)Z [access_flags=public] @ 0xca0"
    external 0
    entrypoint 0
    methodname "verify"
    descriptor "(Ljava/lang/String; Ljavax/net/ssl/SSLSession;)Z"
    accessflags "public"
    classname "Lcom/planted/audit/Plants$AllowAllHosts;"
  ]
  node [
    id 5
    label "Lcom/planted/audit/Plants$IgnoreSslErrors;-><init>()V [access_flags=constructor] @ 0xccc"
    external 0
    entrypoint 0
    methodname "<init>"
    descriptor "()V"
    accessflags "constructor"
    classname "Lcom/planted/audit/Plants$IgnoreSslErrors;"
  ]
  node [
    id 6
    label "Landroid/webkit/WebViewClient;-><init>()V"
    external 1
    entrypoint 0
    methodname "<init>"
    descriptor "()V"
    accessflags ""
    classname "Landroid/webkit/WebViewClient;"
  ]
  node [
    id 7
    label "Lcom/planted/audit/Plants$IgnoreSslErrors;->onReceivedSslError(Landroid/webkit/WebView; Landroid/webkit/SslErrorHandler; Landroid/net/http/SslError;)V [access_flags=public] @ 0xce4"
    external 0
    entrypoint 0
    methodname "onReceivedSslError"
    descriptor "(Landroid/webkit/WebView; Landroid/webkit/SslErrorHandler; Landroid/net/http/SslError;)V"
    accessflags "public"
    classname "Lcom/planted/audit/Plants$IgnoreSslErrors;"
  ]
  node [
    id 8
    label "Landroid/webkit/SslErrorHandler;->proceed()V"
    external 1
    entrypoint 0
    methodname "proceed"
    descriptor "()V"
    accessflags ""
    classname "Landroid/webkit/SslErrorHandler;"
  ]
  node [
    id 9
    label "Lcom/planted/audit/Plants$TrustAll;-><init>()V [access_flags=constructor] @ 0xd10"
    external 0
    entrypoint 0
    methodname "<init>"
    descriptor "()V"
    accessflags "constructor"
    classname "Lcom/planted/audit/Plants$TrustAll;"
  ]
  node [
    id 10
    label "Lcom/planted/audit/Plants$TrustAll;->checkClientTrusted([Ljava/security/cert/X509Certificate; Ljava/lang/String;)V [access_flags=public] @ 0xd28"
    external 0
    entrypoint 0
    methodname "checkClientTrusted"
    descriptor "([Ljava/security/cert/X509Certificate; Ljava/lang/String;)V"
    accessflags "public"
    classname "Lcom/planted/audit/Plants$TrustAll;"
  ]
  node [
    id 11
    label "Lcom/planted/audit/Plants$TrustAll;->checkServerTrusted([Ljava/security/cert/X509Certificate; Ljava/lang/String;)V [access_flags=public] @ 0xd3c"
    external 0
    entrypoint 0
    methodname "checkServerTrusted"
    descriptor "([Ljava/security/cert/X509Certificate; Ljava/lang/String;)V"
    accessflags "public"
    classname "Lcom/planted/audit/Plants$TrustAll;"
  ]
  node [
    id 12
    label "Lcom/planted/audit/Plants$TrustAll;->getAcceptedIssuers()[Ljava/security/cert/X509Certificate; [access_flags=public] @ 0xcfc"
    external 0
    entrypoint 0
    methodname "getAcceptedIssuers"
    descriptor "()[Ljava/security/cert/X509Certificate;"
    accessflags "public"
    classname "Lcom/planted/audit/Plants$TrustAll;"
  ]
  node [
    id 13
    label "Lcom/planted/audit/Plants;-><init>()V [access_flags=private constructor] @ 0x121c"
    external 0
    entrypoint 1
    methodname "<init>"
    descriptor "()V"
    accessflags "private constructor"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 14
    label "Lcom/planted/audit/Plants;->audioCapture()Landroid/media/MediaRecorder; [access_flags=public static] @ 0xdbc"
    external 0
    entrypoint 1
    methodname "audioCapture"
    descriptor "()Landroid/media/MediaRecorder;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 15
    label "Landroid/media/MediaRecorder;-><init>()V"
    external 1
    entrypoint 0
    methodname "<init>"
    descriptor "()V"
    accessflags ""
    classname "Landroid/media/MediaRecorder;"
  ]
  node [
    id 16
    label "Landroid/media/MediaRecorder;->setAudioSource(I)V"
    external 1
    entrypoint 0
    methodname "setAudioSource"
    descriptor "(I)V"
    accessflags ""
    classname "Landroid/media/MediaRecorder;"
  ]
  node [
    id 17
    label "Lcom/planted/audit/Plants;->cameraCapture()Landroid/hardware/Camera; [access_flags=public static] @ 0xd80"
    external 0
    entrypoint 1
    methodname "cameraCapture"
    descriptor "()Landroid/hardware/Camera;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 18
    label "Landroid/hardware/Camera;->open()Landroid/hardware/Camera;"
    external 1
    entrypoint 0
    methodname "open"
    descriptor "()Landroid/hardware/Camera;"
    accessflags ""
    classname "Landroid/hardware/Camera;"
  ]
  node [
    id 19
    label "Lcom/planted/audit/Plants;->clipboardRead(Landroid/content/ClipboardManager;)Ljava/lang/CharSequence; [access_flags=public static] @ 0xf30"
    external 0
    entrypoint 1
    methodname "clipboardRead"
    descriptor "(Landroid/content/ClipboardManager;)Ljava/lang/CharSequence;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 20
    label "Landroid/content/ClipboardManager;->getText()Ljava/lang/CharSequence;"
    external 1
    entrypoint 0
    methodname "getText"
    descriptor "()Ljava/lang/CharSequence;"
    accessflags ""
    classname "Landroid/content/ClipboardManager;"
  ]
  node [
    id 21
    label "Lcom/planted/audit/Plants;->cryptoBareAes()Ljavax/crypto/Cipher; [access_flags=public static] @ 0x10f4"
    external 0
    entrypoint 1
    methodname "cryptoBareAes"
    descriptor "()Ljavax/crypto/Cipher;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 22
    label "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;"
    external 1
    entrypoint 0
    methodname "getInstance"
    descriptor "(Ljava/lang/String;)Ljavax/crypto/Cipher;"
    accessflags ""
    classname "Ljavax/crypto/Cipher;"
  ]
  node [
    id 23
    label "Lcom/planted/audit/Plants;->cryptoEcb()Ljavax/crypto/Cipher; [access_flags=public static] @ 0x1114"
    external 0
    entrypoint 1
    methodname "cryptoEcb"
    descriptor "()Ljavax/crypto/Cipher;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 24
    label "Lcom/planted/audit/Plants;->cryptoHardcodedKey()Ljavax/crypto/spec/SecretKeySpec; [access_flags=public static] @ 0x119c"
    external 0
    entrypoint 1
    methodname "cryptoHardcodedKey"
    descriptor "()Ljavax/crypto/spec/SecretKeySpec;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 25
    label "Ljava/lang/String;->getBytes()[B"
    external 1
    entrypoint 0
    methodname "getBytes"
    descriptor "()[B"
    accessflags ""
    classname "Ljava/lang/String;"
  ]
  node [
    id 26
    label "Ljavax/crypto/spec/SecretKeySpec;-><init>([B Ljava/lang/String;)V"
    external 1
    entrypoint 0
    methodname "<init>"
    descriptor "([B Ljava/lang/String;)V"
    accessflags ""
    classname "Ljavax/crypto/spec/SecretKeySpec;"
  ]
  node [
    id 27
    label "Lcom/planted/audit/Plants;->cryptoInsecureRandom()[B [access_flags=public static] @ 0xe70"
    external 0
    entrypoint 1
    methodname "cryptoInsecureRandom"
    descriptor "()[B"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 28
    label "Ljava/util/Random;-><init>()V"
    external 1
    entrypoint 0
    methodname "<init>"
    descriptor "()V"
    accessflags ""
    classname "Ljava/util/Random;"
  ]
  node [
    id 29
    label "Ljava/util/Random;->nextBytes([B)V"
    external 1
    entrypoint 0
    methodname "nextBytes"
    descriptor "([B)V"
    accessflags ""
    classname "Ljava/util/Random;"
  ]
  node [
    id 30
    label "Ljavax/crypto/spec/SecretKeySpec;->getEncoded()[B"
    external 1
    entrypoint 0
    methodname "getEncoded"
    descriptor "()[B"
    accessflags ""
    classname "Ljavax/crypto/spec/SecretKeySpec;"
  ]
  node [
    id 31
    label "Lcom/planted/audit/Plants;->cryptoRsaNoOaep()Ljavax/crypto/Cipher; [access_flags=public static] @ 0x1134"
    external 0
    entrypoint 1
    methodname "cryptoRsaNoOaep"
    descriptor "()Ljavax/crypto/Cipher;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 32
    label "Lcom/planted/audit/Plants;->cryptoSeededRandom()Ljava/security/SecureRandom; [access_flags=public static] @ 0x10b0"
    external 0
    entrypoint 1
    methodname "cryptoSeededRandom"
    descriptor "()Ljava/security/SecureRandom;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 33
    label "Ljava/security/SecureRandom;->setSeed(J)V"
    external 1
    entrypoint 0
    methodname "setSeed"
    descriptor "(J)V"
    accessflags ""
    classname "Ljava/security/SecureRandom;"
  ]
  node [
    id 34
    label "Ljava/security/SecureRandom;-><init>()V"
    external 1
    entrypoint 0
    methodname "<init>"
    descriptor "()V"
    accessflags ""
    classname "Ljava/security/SecureRandom;"
  ]
  node [
    id 35
    label "Lcom/planted/audit/Plants;->cryptoStaticIv()Ljavax/crypto/spec/IvParameterSpec; [access_flags=public static] @ 0x1174"
    external 0
    entrypoint 1
    methodname "cryptoStaticIv"
    descriptor "()Ljavax/crypto/spec/IvParameterSpec;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 36
    label "Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V"
    external 1
    entrypoint 0
    methodname "<init>"
    descriptor "([B)V"
    accessflags ""
    classname "Ljavax/crypto/spec/IvParameterSpec;"
  ]
  node [
    id 37
    label "Lcom/planted/audit/Plants;->cryptoWeakCipher()Ljavax/crypto/Cipher; [access_flags=public static] @ 0x1154"
    external 0
    entrypoint 1
    methodname "cryptoWeakCipher"
    descriptor "()Ljavax/crypto/Cipher;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 38
    label "Lcom/planted/audit/Plants;->cryptoWeakHash()Ljava/security/MessageDigest; [access_flags=public static] @ 0x1090"
    external 0
    entrypoint 1
    methodname "cryptoWeakHash"
    descriptor "()Ljava/security/MessageDigest;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 39
    label "Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;"
    external 1
    entrypoint 0
    methodname "getInstance"
    descriptor "(Ljava/lang/String;)Ljava/security/MessageDigest;"
    accessflags ""
    classname "Ljava/security/MessageDigest;"
  ]
  node [
    id 40
    label "Lcom/planted/audit/Plants;->debuggerCheck()Z [access_flags=public static] @ 0xde0"
    external 0
    entrypoint 1
    methodname "debuggerCheck"
    descriptor "()Z"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 41
    label "Landroid/os/Debug;->isDebuggerConnected()Z"
    external 1
    entrypoint 0
    methodname "isDebuggerConnected"
    descriptor "()Z"
    accessflags ""
    classname "Landroid/os/Debug;"
  ]
  node [
    id 42
    label "Lcom/planted/audit/Plants;->deviceIdentifier(Landroid/telephony/TelephonyManager;)Ljava/lang/String; [access_flags=public static] @ 0x1034"
    external 0
    entrypoint 1
    methodname "deviceIdentifier"
    descriptor "(Landroid/telephony/TelephonyManager;)Ljava/lang/String;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 43
    label "Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;"
    external 1
    entrypoint 0
    methodname "getDeviceId"
    descriptor "()Ljava/lang/String;"
    accessflags ""
    classname "Landroid/telephony/TelephonyManager;"
  ]
  node [
    id 44
    label "Lcom/planted/audit/Plants;->deviceIdentifierAndroidId(Landroid/content/Context;)Ljava/lang/String; [access_flags=public static] @ 0x1050"
    external 0
    entrypoint 1
    methodname "deviceIdentifierAndroidId"
    descriptor "(Landroid/content/Context;)Ljava/lang/String;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 45
    label "Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;"
    external 1
    entrypoint 0
    methodname "getContentResolver"
    descriptor "()Landroid/content/ContentResolver;"
    accessflags ""
    classname "Landroid/content/Context;"
  ]
  node [
    id 46
    label "Landroid/provider/Settings$Secure;->getString(Landroid/content/ContentResolver; Ljava/lang/String;)Ljava/lang/String;"
    external 1
    entrypoint 0
    methodname "getString"
    descriptor "(Landroid/content/ContentResolver; Ljava/lang/String;)Ljava/lang/String;"
    accessflags ""
    classname "Landroid/provider/Settings$Secure;"
  ]
  node [
    id 47
    label "Lcom/planted/audit/Plants;->deviceIdentifierSerial()Ljava/lang/String; [access_flags=public static] @ 0x1078"
    external 0
    entrypoint 1
    methodname "deviceIdentifierSerial"
    descriptor "()Ljava/lang/String;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 48
    label "Lcom/planted/audit/Plants;->dynamicCodeLoading(Landroid/content/Context; Ljava/lang/String;)Ljava/lang/ClassLoader; [access_flags=public static] @ 0xf4c"
    external 0
    entrypoint 1
    methodname "dynamicCodeLoading"
    descriptor "(Landroid/content/Context; Ljava/lang/String;)Ljava/lang/ClassLoader;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 49
    label "Landroid/content/Context;->getCodeCacheDir()Ljava/io/File;"
    external 1
    entrypoint 0
    methodname "getCodeCacheDir"
    descriptor "()Ljava/io/File;"
    accessflags ""
    classname "Landroid/content/Context;"
  ]
  node [
    id 50
    label "Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;"
    external 1
    entrypoint 0
    methodname "getClassLoader"
    descriptor "()Ljava/lang/ClassLoader;"
    accessflags ""
    classname "Ljava/lang/Class;"
  ]
  node [
    id 51
    label "Ljava/io/File;->getPath()Ljava/lang/String;"
    external 1
    entrypoint 0
    methodname "getPath"
    descriptor "()Ljava/lang/String;"
    accessflags ""
    classname "Ljava/io/File;"
  ]
  node [
    id 52
    label "Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String; Ljava/lang/String; Ljava/lang/String; Ljava/lang/ClassLoader;)V"
    external 1
    entrypoint 0
    methodname "<init>"
    descriptor "(Ljava/lang/String; Ljava/lang/String; Ljava/lang/String; Ljava/lang/ClassLoader;)V"
    accessflags ""
    classname "Ldalvik/system/DexClassLoader;"
  ]
  node [
    id 53
    label "Lcom/planted/audit/Plants;->emulatorCheck()Z [access_flags=public static] @ 0xdfc"
    external 0
    entrypoint 1
    methodname "emulatorCheck"
    descriptor "()Z"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 54
    label "Ljava/lang/String;->startsWith(Ljava/lang/String;)Z"
    external 1
    entrypoint 0
    methodname "startsWith"
    descriptor "(Ljava/lang/String;)Z"
    accessflags ""
    classname "Ljava/lang/String;"
  ]
  node [
    id 55
    label "Lcom/planted/audit/Plants;->execCommand()Ljava/lang/Process; [access_flags=public static] @ 0xfe4"
    external 0
    entrypoint 1
    methodname "execCommand"
    descriptor "()Ljava/lang/Process;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 56
    label "Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;"
    external 1
    entrypoint 0
    methodname "exec"
    descriptor "(Ljava/lang/String;)Ljava/lang/Process;"
    accessflags ""
    classname "Ljava/lang/Runtime;"
  ]
  node [
    id 57
    label "Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;"
    external 1
    entrypoint 0
    methodname "getRuntime"
    descriptor "()Ljava/lang/Runtime;"
    accessflags ""
    classname "Ljava/lang/Runtime;"
  ]
  node [
    id 58
    label "Lcom/planted/audit/Plants;->fridaCheck()Z [access_flags=public static] @ 0xe20"
    external 0
    entrypoint 1
    methodname "fridaCheck"
    descriptor "()Z"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 59
    label "Ljava/io/File;->exists()Z"
    external 1
    entrypoint 0
    methodname "exists"
    descriptor "()Z"
    accessflags ""
    classname "Ljava/io/File;"
  ]
  node [
    id 60
    label "Ljava/io/File;-><init>(Ljava/lang/String;)V"
    external 1
    entrypoint 0
    methodname "<init>"
    descriptor "(Ljava/lang/String;)V"
    accessflags ""
    classname "Ljava/io/File;"
  ]
  node [
    id 61
    label "Lcom/planted/audit/Plants;->installedApps(Landroid/content/pm/PackageManager;)Ljava/util/List; [access_flags=public static] @ 0x10d8"
    external 0
    entrypoint 1
    methodname "installedApps"
    descriptor "(Landroid/content/pm/PackageManager;)Ljava/util/List;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 62
    label "Landroid/content/pm/PackageManager;->getInstalledPackages(I)Ljava/util/List;"
    external 1
    entrypoint 0
    methodname "getInstalledPackages"
    descriptor "(I)Ljava/util/List;"
    accessflags ""
    classname "Landroid/content/pm/PackageManager;"
  ]
  node [
    id 63
    label "Lcom/planted/audit/Plants;->locationAccess(Landroid/location/LocationManager;)Landroid/location/Location; [access_flags=public static] @ 0xd9c"
    external 0
    entrypoint 1
    methodname "locationAccess"
    descriptor "(Landroid/location/LocationManager;)Landroid/location/Location;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 64
    label "Landroid/location/LocationManager;->getLastKnownLocation(Ljava/lang/String;)Landroid/location/Location;"
    external 1
    entrypoint 0
    methodname "getLastKnownLocation"
    descriptor "(Ljava/lang/String;)Landroid/location/Location;"
    accessflags ""
    classname "Landroid/location/LocationManager;"
  ]
  node [
    id 65
    label "Lcom/planted/audit/Plants;->logCall(Ljava/lang/String;)V [access_flags=public static] @ 0x1234"
    external 0
    entrypoint 1
    methodname "logCall"
    descriptor "(Ljava/lang/String;)V"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 66
    label "Landroid/util/Log;->d(Ljava/lang/String; Ljava/lang/String;)I"
    external 1
    entrypoint 0
    methodname "d"
    descriptor "(Ljava/lang/String; Ljava/lang/String;)I"
    accessflags ""
    classname "Landroid/util/Log;"
  ]
  node [
    id 67
    label "Lcom/planted/audit/Plants;->logSensitive(Ljava/lang/String;)V [access_flags=public static] @ 0x1250"
    external 0
    entrypoint 1
    methodname "logSensitive"
    descriptor "(Ljava/lang/String;)V"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 68
    label "Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;"
    external 1
    entrypoint 0
    methodname "append"
    descriptor "(Ljava/lang/String;)Ljava/lang/StringBuilder;"
    accessflags ""
    classname "Ljava/lang/StringBuilder;"
  ]
  node [
    id 69
    label "Ljava/lang/StringBuilder;->toString()Ljava/lang/String;"
    external 1
    entrypoint 0
    methodname "toString"
    descriptor "()Ljava/lang/String;"
    accessflags ""
    classname "Ljava/lang/StringBuilder;"
  ]
  node [
    id 70
    label "Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V"
    external 1
    entrypoint 0
    methodname "<init>"
    descriptor "(Ljava/lang/String;)V"
    accessflags ""
    classname "Ljava/lang/StringBuilder;"
  ]
  node [
    id 71
    label "Landroid/util/Log;->i(Ljava/lang/String; Ljava/lang/String;)I"
    external 1
    entrypoint 0
    methodname "i"
    descriptor "(Ljava/lang/String; Ljava/lang/String;)I"
    accessflags ""
    classname "Landroid/util/Log;"
  ]
  node [
    id 72
    label "Lcom/planted/audit/Plants;->nativeLoadPath(Ljava/lang/String;)V [access_flags=public static] @ 0x128c"
    external 0
    entrypoint 1
    methodname "nativeLoadPath"
    descriptor "(Ljava/lang/String;)V"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 73
    label "Ljava/lang/System;->load(Ljava/lang/String;)V"
    external 1
    entrypoint 0
    methodname "load"
    descriptor "(Ljava/lang/String;)V"
    accessflags ""
    classname "Ljava/lang/System;"
  ]
  node [
    id 74
    label "Lcom/planted/audit/Plants;->playIntegrity(Lcom/google/android/play/core/integrity/IntegrityManager; Ljava/lang/Object;)Ljava/lang/Object; [access_flags=public static] @ 0xf88"
    external 0
    entrypoint 1
    methodname "playIntegrity"
    descriptor "(Lcom/google/android/play/core/integrity/IntegrityManager; Ljava/lang/Object;)Ljava/lang/Object;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 75
    label "Lcom/planted/audit/Plants;->reflection(Ljava/lang/reflect/Method; Ljava/lang/Object;)Ljava/lang/Object; [access_flags=public static] @ 0xfa4"
    external 0
    entrypoint 1
    methodname "reflection"
    descriptor "(Ljava/lang/reflect/Method; Ljava/lang/Object;)Ljava/lang/Object;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 76
    label "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object; [Ljava/lang/Object;)Ljava/lang/Object;"
    external 1
    entrypoint 0
    methodname "invoke"
    descriptor "(Ljava/lang/Object; [Ljava/lang/Object;)Ljava/lang/Object;"
    accessflags ""
    classname "Ljava/lang/reflect/Method;"
  ]
  node [
    id 77
    label "Lcom/planted/audit/Plants;->rootDetection()Z [access_flags=public static] @ 0xe48"
    external 0
    entrypoint 1
    methodname "rootDetection"
    descriptor "()Z"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 78
    label "Lcom/planted/audit/Plants;->rootSuCommand()Ljava/lang/Process; [access_flags=public static] @ 0x100c"
    external 0
    entrypoint 1
    methodname "rootSuCommand"
    descriptor "()Ljava/lang/Process;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 79
    label "Lcom/planted/audit/Plants;->safetyNetAttest(Lcom/google/android/gms/safetynet/SafetyNetClient; [B)Ljava/lang/Object; [access_flags=public static] @ 0xfc4"
    external 0
    entrypoint 1
    methodname "safetyNetAttest"
    descriptor "(Lcom/google/android/gms/safetynet/SafetyNetClient; [B)Ljava/lang/Object;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 80
    label "Lcom/planted/audit/Plants;->signatureCheck(Landroid/content/Context;)Landroid/content/pm/PackageInfo; [access_flags=public static] @ 0xd50"
    external 0
    entrypoint 1
    methodname "signatureCheck"
    descriptor "(Landroid/content/Context;)Landroid/content/pm/PackageInfo;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 81
    label "Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String; I)Landroid/content/pm/PackageInfo;"
    external 1
    entrypoint 0
    methodname "getPackageInfo"
    descriptor "(Ljava/lang/String; I)Landroid/content/pm/PackageInfo;"
    accessflags ""
    classname "Landroid/content/pm/PackageManager;"
  ]
  node [
    id 82
    label "Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;"
    external 1
    entrypoint 0
    methodname "getPackageManager"
    descriptor "()Landroid/content/pm/PackageManager;"
    accessflags ""
    classname "Landroid/content/Context;"
  ]
  node [
    id 83
    label "Landroid/content/Context;->getPackageName()Ljava/lang/String;"
    external 1
    entrypoint 0
    methodname "getPackageName"
    descriptor "()Ljava/lang/String;"
    accessflags ""
    classname "Landroid/content/Context;"
  ]
  node [
    id 84
    label "Lcom/planted/audit/Plants;->smsSend(Ljava/lang/String; Ljava/lang/String;)V [access_flags=public static] @ 0x12a4"
    external 0
    entrypoint 1
    methodname "smsSend"
    descriptor "(Ljava/lang/String; Ljava/lang/String;)V"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 85
    label "Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String; Ljava/lang/String; Ljava/lang/String; Landroid/app/PendingIntent; Landroid/app/PendingIntent;)V"
    external 1
    entrypoint 0
    methodname "sendTextMessage"
    descriptor "(Ljava/lang/String; Ljava/lang/String; Ljava/lang/String; Landroid/app/PendingIntent; Landroid/app/PendingIntent;)V"
    accessflags ""
    classname "Landroid/telephony/SmsManager;"
  ]
  node [
    id 86
    label "Landroid/telephony/SmsManager;->getDefault()Landroid/telephony/SmsManager;"
    external 1
    entrypoint 0
    methodname "getDefault"
    descriptor "()Landroid/telephony/SmsManager;"
    accessflags ""
    classname "Landroid/telephony/SmsManager;"
  ]
  node [
    id 87
    label "Lcom/planted/audit/Plants;->sqlDynamicQuery(Landroid/database/sqlite/SQLiteDatabase; Ljava/lang/String;)V [access_flags=public static] @ 0x12d0"
    external 0
    entrypoint 1
    methodname "sqlDynamicQuery"
    descriptor "(Landroid/database/sqlite/SQLiteDatabase; Ljava/lang/String;)V"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 88
    label "Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V"
    external 1
    entrypoint 0
    methodname "execSQL"
    descriptor "(Ljava/lang/String;)V"
    accessflags ""
    classname "Landroid/database/sqlite/SQLiteDatabase;"
  ]
  node [
    id 89
    label "Lcom/planted/audit/Plants;->sslApacheAllowAllCtor()Ljavax/net/ssl/HostnameVerifier; [access_flags=public static] @ 0x11c8"
    external 0
    entrypoint 1
    methodname "sslApacheAllowAllCtor"
    descriptor "()Ljavax/net/ssl/HostnameVerifier;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 90
    label "Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;-><init>()V"
    external 1
    entrypoint 0
    methodname "<init>"
    descriptor "()V"
    accessflags ""
    classname "Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;"
  ]
  node [
    id 91
    label "Lcom/planted/audit/Plants;->sslApacheAllowAllField()Ljavax/net/ssl/HostnameVerifier; [access_flags=public static] @ 0x11e4"
    external 0
    entrypoint 1
    methodname "sslApacheAllowAllField"
    descriptor "()Ljavax/net/ssl/HostnameVerifier;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 92
    label "Lcom/planted/audit/Plants;->sslWeakProtocol()Ljavax/net/ssl/SSLContext; [access_flags=public static] @ 0x11fc"
    external 0
    entrypoint 1
    methodname "sslWeakProtocol"
    descriptor "()Ljavax/net/ssl/SSLContext;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 93
    label "Ljavax/net/ssl/SSLContext;->getInstance(Ljava/lang/String;)Ljavax/net/ssl/SSLContext;"
    external 1
    entrypoint 0
    methodname "getInstance"
    descriptor "(Ljava/lang/String;)Ljavax/net/ssl/SSLContext;"
    accessflags ""
    classname "Ljavax/net/ssl/SSLContext;"
  ]
  node [
    id 94
    label "Lcom/planted/audit/Plants;->storageExternal()Ljava/io/File; [access_flags=public static] @ 0xeb0"
    external 0
    entrypoint 1
    methodname "storageExternal"
    descriptor "()Ljava/io/File;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 95
    label "Landroid/os/Environment;->getExternalStorageDirectory()Ljava/io/File;"
    external 1
    entrypoint 0
    methodname "getExternalStorageDirectory"
    descriptor "()Ljava/io/File;"
    accessflags ""
    classname "Landroid/os/Environment;"
  ]
  node [
    id 96
    label "Lcom/planted/audit/Plants;->storageSdcardPath()Ljava/io/File; [access_flags=public static] @ 0xecc"
    external 0
    entrypoint 1
    methodname "storageSdcardPath"
    descriptor "()Ljava/io/File;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 97
    label "Lcom/planted/audit/Plants;->storageTempFile()Ljava/io/File; [access_flags=public static] @ 0xeec"
    external 0
    entrypoint 1
    methodname "storageTempFile"
    descriptor "()Ljava/io/File;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 98
    label "Ljava/io/File;->createTempFile(Ljava/lang/String; Ljava/lang/String;)Ljava/io/File;"
    external 1
    entrypoint 0
    methodname "createTempFile"
    descriptor "(Ljava/lang/String; Ljava/lang/String;)Ljava/io/File;"
    accessflags ""
    classname "Ljava/io/File;"
  ]
  node [
    id 99
    label "Lcom/planted/audit/Plants;->storageWorldAccessible(Landroid/content/Context;)Ljava/io/FileOutputStream; [access_flags=public static] @ 0xf10"
    external 0
    entrypoint 1
    methodname "storageWorldAccessible"
    descriptor "(Landroid/content/Context;)Ljava/io/FileOutputStream;"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 100
    label "Landroid/content/Context;->openFileOutput(Ljava/lang/String; I)Ljava/io/FileOutputStream;"
    external 1
    entrypoint 0
    methodname "openFileOutput"
    descriptor "(Ljava/lang/String; I)Ljava/io/FileOutputStream;"
    accessflags ""
    classname "Landroid/content/Context;"
  ]
  node [
    id 101
    label "Lcom/planted/audit/Plants;->webviewDebugging()V [access_flags=public static] @ 0x1314"
    external 0
    entrypoint 1
    methodname "webviewDebugging"
    descriptor "()V"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 102
    label "Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V"
    external 1
    entrypoint 0
    methodname "setWebContentsDebuggingEnabled"
    descriptor "(Z)V"
    accessflags ""
    classname "Landroid/webkit/WebView;"
  ]
  node [
    id 103
    label "Lcom/planted/audit/Plants;->webviewFileAccess(Landroid/webkit/WebView;)V [access_flags=public static] @ 0x1330"
    external 0
    entrypoint 1
    methodname "webviewFileAccess"
    descriptor "(Landroid/webkit/WebView;)V"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 104
    label "Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;"
    external 1
    entrypoint 0
    methodname "getSettings"
    descriptor "()Landroid/webkit/WebSettings;"
    accessflags ""
    classname "Landroid/webkit/WebView;"
  ]
  node [
    id 105
    label "Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V"
    external 1
    entrypoint 0
    methodname "setAllowFileAccessFromFileURLs"
    descriptor "(Z)V"
    accessflags ""
    classname "Landroid/webkit/WebSettings;"
  ]
  node [
    id 106
    label "Lcom/planted/audit/Plants;->webviewJavascript(Landroid/webkit/WebView;)V [access_flags=public static] @ 0x1354"
    external 0
    entrypoint 1
    methodname "webviewJavascript"
    descriptor "(Landroid/webkit/WebView;)V"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 107
    label "Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V"
    external 1
    entrypoint 0
    methodname "setJavaScriptEnabled"
    descriptor "(Z)V"
    accessflags ""
    classname "Landroid/webkit/WebSettings;"
  ]
  node [
    id 108
    label "Lcom/planted/audit/Plants;->webviewJsInterface(Landroid/webkit/WebView; Ljava/lang/Object;)V [access_flags=public static] @ 0x1378"
    external 0
    entrypoint 1
    methodname "webviewJsInterface"
    descriptor "(Landroid/webkit/WebView; Ljava/lang/Object;)V"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 109
    label "Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object; Ljava/lang/String;)V"
    external 1
    entrypoint 0
    methodname "addJavascriptInterface"
    descriptor "(Ljava/lang/Object; Ljava/lang/String;)V"
    accessflags ""
    classname "Landroid/webkit/WebView;"
  ]
  node [
    id 110
    label "Lcom/planted/audit/Plants;->webviewMixedContent(Landroid/webkit/WebView;)V [access_flags=public static] @ 0x1394"
    external 0
    entrypoint 1
    methodname "webviewMixedContent"
    descriptor "(Landroid/webkit/WebView;)V"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 111
    label "Landroid/webkit/WebSettings;->setMixedContentMode(I)V"
    external 1
    entrypoint 0
    methodname "setMixedContentMode"
    descriptor "(I)V"
    accessflags ""
    classname "Landroid/webkit/WebSettings;"
  ]
  node [
    id 112
    label "Lcom/planted/audit/Plants;->webviewSavePassword(Landroid/webkit/WebView;)V [access_flags=public static] @ 0x13b8"
    external 0
    entrypoint 1
    methodname "webviewSavePassword"
    descriptor "(Landroid/webkit/WebView;)V"
    accessflags "public static"
    classname "Lcom/planted/audit/Plants;"
  ]
  node [
    id 113
    label "Landroid/webkit/WebSettings;->setSavePassword(Z)V"
    external 1
    entrypoint 0
    methodname "setSavePassword"
    descriptor "(Z)V"
    accessflags ""
    classname "Landroid/webkit/WebSettings;"
  ]
  edge [
    source 2
    target 3
  ]
  edge [
    source 5
    target 6
  ]
  edge [
    source 7
    target 8
  ]
  edge [
    source 9
    target 3
  ]
  edge [
    source 13
    target 3
  ]
  edge [
    source 14
    target 15
  ]
  edge [
    source 14
    target 16
  ]
  edge [
    source 17
    target 18
  ]
  edge [
    source 19
    target 20
  ]
  edge [
    source 21
    target 22
  ]
  edge [
    source 23
    target 22
  ]
  edge [
    source 24
    target 25
  ]
  edge [
    source 24
    target 26
  ]
  edge [
    source 27
    target 28
  ]
  edge [
    source 27
    target 29
  ]
  edge [
    source 27
    target 30
  ]
  edge [
    source 27
    target 26
  ]
  edge [
    source 31
    target 22
  ]
  edge [
    source 32
    target 33
  ]
  edge [
    source 32
    target 34
  ]
  edge [
    source 35
    target 36
  ]
  edge [
    source 35
    target 25
  ]
  edge [
    source 37
    target 22
  ]
  edge [
    source 38
    target 39
  ]
  edge [
    source 40
    target 41
  ]
  edge [
    source 42
    target 43
  ]
  edge [
    source 44
    target 45
  ]
  edge [
    source 44
    target 46
  ]
  edge [
    source 48
    target 49
  ]
  edge [
    source 48
    target 50
  ]
  edge [
    source 48
    target 51
  ]
  edge [
    source 48
    target 52
  ]
  edge [
    source 53
    target 54
  ]
  edge [
    source 55
    target 56
  ]
  edge [
    source 55
    target 57
  ]
  edge [
    source 58
    target 59
  ]
  edge [
    source 58
    target 60
  ]
  edge [
    source 61
    target 62
  ]
  edge [
    source 63
    target 64
  ]
  edge [
    source 65
    target 66
  ]
  edge [
    source 67
    target 68
  ]
  edge [
    source 67
    target 69
  ]
  edge [
    source 67
    target 70
  ]
  edge [
    source 67
    target 71
  ]
  edge [
    source 72
    target 73
  ]
  edge [
    source 74
    target 1
  ]
  edge [
    source 75
    target 76
  ]
  edge [
    source 77
    target 59
  ]
  edge [
    source 77
    target 60
  ]
  edge [
    source 78
    target 56
  ]
  edge [
    source 78
    target 57
  ]
  edge [
    source 79
    target 0
  ]
  edge [
    source 80
    target 81
  ]
  edge [
    source 80
    target 82
  ]
  edge [
    source 80
    target 83
  ]
  edge [
    source 84
    target 85
  ]
  edge [
    source 84
    target 86
  ]
  edge [
    source 87
    target 68
  ]
  edge [
    source 87
    target 70
  ]
  edge [
    source 87
    target 88
  ]
  edge [
    source 87
    target 69
  ]
  edge [
    source 89
    target 90
  ]
  edge [
    source 92
    target 93
  ]
  edge [
    source 94
    target 95
  ]
  edge [
    source 96
    target 60
  ]
  edge [
    source 97
    target 98
  ]
  edge [
    source 99
    target 100
  ]
  edge [
    source 101
    target 102
  ]
  edge [
    source 103
    target 104
  ]
  edge [
    source 103
    target 105
  ]
  edge [
    source 106
    target 107
  ]
  edge [
    source 106
    target 104
  ]
  edge [
    source 108
    target 109
  ]
  edge [
    source 110
    target 111
  ]
  edge [
    source 110
    target 104
  ]
  edge [
    source 112
    target 104
  ]
  edge [
    source 112
    target 113
  ]
]
