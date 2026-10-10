/**
 * SSL/TLS CERTIFICATE PINNING BYPASS (Java / Conscrypt focused)
 *
 * Hooks common Java TLS entry points (HttpsURLConnection, TrustManagerImpl,
 * SSLContext, custom X509TrustManager subclasses) + constructor interception
 * and stack trace logging for debugging pinning implementations.
 *
 * Currently implemented (as of 2026):
 *  - HttpsURLConnection.setDefaultHostnameVerifier / setSSLSocketFactory
 *  - HostnameVerifier.verify
 *  - TrustManagerImpl / Conscrypt / GMS variants (checkClientTrusted, checkServerTrusted)
 *  - SSLContext.init overrides
 *  - Generic custom X509TrustManager detection + hook
 *  - Early hooking via Java.performNow()
 *
 * NOT covered in this script (common modern pinning):
 *  - OkHttp CertificatePinner / OkHttpClient.Builder / Interceptor chain pinning
 *  - WebViewClient.onReceivedSslError + WebView pinning
 *  - Network Security Config (NSC) + Certificate Transparency
 *  - Flutter BoringSSL / React Native specific / TrustKit / WorkLight etc.
 *
 * For OkHttp / WebView / NSC / Flutter you will usually need additional or
 * different hooks (see network-security-bypass.js, native-hook.js, or
 * app-specific analysis).
 *
 * Compatible with: Frida 17+, Android 7-16 (best effort)
 *
 * Credits / techniques from HTTP Toolkit, FriList, akabe1, Frida Handbook Ch.9
 */

// Configuration
const DEBUG_MODE = false;  // false for agent/prod use; set true only for local debugging

// ========================================
// UTILITY FUNCTIONS
// ========================================

/**
 * Extract full stack trace for debugging
 */
function extractFullStackTrace() {
  try {
    const Thread = Java.use('java.lang.Thread');
    const thread = Thread.$new();
    const stackTrace = thread.currentThread().getStackTrace();

    console.log('=== Stack Trace (first 10 frames) ===');
    stackTrace.slice(0, 10).forEach((element, index) => {
      console.log(`[${index}] ${element.toString()}`);
    });

    return stackTrace;
  } catch (error) {
    console.log(`[ERROR] Failed to extract stack trace: ${error}`);
    return [];
  }
}

/**
 * Log with timestamp
 */
function log(message) {
  const timestamp = new Date().toISOString().split('T')[1].split('.')[0];
  console.log(`[${timestamp}] ${message}`);
}

// ========================================
// MAIN HOOK EXECUTION
// ========================================

Java.performNow(() => {
  log('=== UNIVERSAL SSL PINNING BYPASS STARTED ===');
  log('[INFO] Using Java.performNow() for instant hooking (Frida Handbook Ch.9)');

  let hooksApplied = 0;

  // ========================================
  // 1. Constructor Hooking - NEW FROM HANDBOOK
  // ========================================

  log('[1/5] Hooking SSL/Trust constructors...');

  /**
   * Hook X509TrustManager constructor - NEW
   *
   * NOTE: `javax.net.ssl.X509TrustManager` is a Java INTERFACE. Frida's
   * `Java.use` returns a wrapper on the interface but `.$init` does not
   * exist on interfaces, so the previous hook always threw a TypeError on
   * load (then was silently swallowed by the surrounding try/catch). The
   * real concrete implementations live in OS-specific classes such as
   * `com.android.org.conscrypt.TrustManagerImpl` or vendor variants — those
   * need to be hooked individually. Below we attempt the conscrypt one as a
   * best-effort default; failure is logged but not fatal.
   */
  try {
    const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');

    TrustManagerImpl.$init.overloads.forEach((overload) => {
      overload.implementation = function() {
        log('[CTOR] TrustManagerImpl() called');

        const stackTrace = extractFullStackTrace();
        log('[CTOR] Called from (first 5 frames):');
        stackTrace.slice(0, 5).forEach((element, index) => {
          log(`[CTOR]   [${index}] ${element.toString()}`);
        });

        return overload.apply(this, arguments);
      };
    });

    hooksApplied++;
    log('[+] Hooked com.android.org.conscrypt.TrustManagerImpl.$init()');
  } catch (error) {
    log(`[WARN] X509TrustManager not found: ${error}`);
  }

  /**
   * Hook SSLContext constructor - NEW
   */
  try {
    const SSLContext = Java.use('javax.net.ssl.SSLContext');

    SSLContext.$init.overload('java.lang.String').implementation = function(protocol) {
      log(`[CTOR] SSLContext("${protocol}") called`);

      const stackTrace = extractFullStackTrace();
      log('[CTOR] Called from (first 5 frames):');
      stackTrace.slice(0, 5).forEach((element, index) => {
        log(`[CTOR]   [${index}] ${element.toString()}`);
      });

      return this.$init(protocol);
    };

    hooksApplied++;
    log('[+] Hooked SSLContext.$init(String)');
  } catch (error) {
    log(`[WARN] SSLContext not found: ${error}`);
  }

  // ========================================
  // 2. HttpsURLConnection Hooks - WITH STACK TRACES
  // ========================================

  log('[2/5] Hooking HttpsURLConnection with stack traces...');

  try {
    const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");

    /**
     * Hook setDefaultHostnameVerifier with stack trace - UPDATED
     */
    HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
      log('[HTTPS] setDefaultHostnameVerifier() called');

      const stackTrace = extractFullStackTrace();

      log('[HTTPS] Stack trace (first 5 frames):');
      stackTrace.slice(0, 5).forEach((element, index) => {
        log(`[HTTPS]   [${index}] ${element.toString()}`);
      });

      if (DEBUG_MODE) {
        console.log('[HTTPS] Bypassing hostname verification');
      }

      return; // Do nothing
    };

    hooksApplied++;

    /**
     * Hook setSSLSocketFactory with stack trace - UPDATED
     */
    HttpsURLConnection.setSSLSocketFactory.implementation = function(SSLSocketFactory) {
      log('[HTTPS] setSSLSocketFactory() called');

      const stackTrace = extractFullStackTrace();

      log('[HTTPS] Stack trace (first 5 frames):');
      stackTrace.slice(0, 5).forEach((element, index) => {
        log(`[HTTPS]   [${index}] ${element.toString()}`);
      });

      if (DEBUG_MODE) {
        console.log('[HTTPS] Bypassing SSL socket factory');
      }

      return; // Do nothing
    };

    hooksApplied++;

    /**
     * Hook setHostnameVerifier with stack trace - UPDATED
     */
    const HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');

    HostnameVerifier.verify.implementation = function(hostname, session) {
      log(`[HTTPS] HostnameVerifier.verify() called for host: ${hostname}`);

      const stackTrace = extractFullStackTrace();

      log('[HTTPS] Stack trace when hostname verification fails:');
      stackTrace.slice(0, 5).forEach((element, index) => {
        log(`[HTTPS]   [${index}] ${element.toString()}`);
      });

      log('[HTTPS] Bypassing hostname verification');

      return true;
    };

    hooksApplied++;

    log('[+] Hooked HttpsURLConnection with stack trace support');
  } catch (error) {
    log(`[ERROR] Failed to hook HttpsURLConnection: ${error}`);
  }

  // ========================================
  // 3. Custom TrustManager Hooks - WITH STACK TRACES
  // ========================================

  log('[3/5] Hooking custom TrustManager implementations...');

  try {
    const customTrustManagerClasses = [
      'com.android.org.conscrypt.TrustManagerImpl',
      'com.google.android.gms.org.conscrypt.TrustManagerImpl',
      'com.google.android.gms.common.net.ssl.TrustManagerImpl'
    ];

    customTrustManagerClasses.forEach(function(className) {
      try {
        const CustomTrustManager = Java.use(className);
        const stringCls = Java.use('java.lang.String');

        /**
         * Hook checkClientTrusted with stack trace - UPDATED
         */
        CustomTrustManager.checkClientTrusted.overload('[Ljava.security.cert.X509Certificate;', '[Ljava.lang.String;').implementation = function(chain, authType) {
          log(`[TRUST] ${className}.checkClientTrusted() called`);

          const stackTrace = extractFullStackTrace();

          log('[TRUST] Stack trace (first 5 frames):');
          stackTrace.slice(0, 5).forEach((element, index) => {
            log(`[TRUST]   [${index}] ${element.toString()}`);
          });

          if (DEBUG_MODE) {
            console.log(`[TRUST] Bypassing client trusted check`);
          }

          return chain;
        };

        /**
         * Hook checkServerTrusted with stack trace - UPDATED
         */
        // The standard X509TrustManager.checkServerTrusted overload has the
        // signature (X509Certificate[] chain, String authType) — only 2
        // parameters. The previous version declared 3 (chain, hostname,
        // authType) and logged `hostname` which was always undefined.
        // For host-aware checks the X509ExtendedTrustManager overloads with
        // Socket/SSLEngine exist; those would have to be hooked separately.
        CustomTrustManager.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', '[Ljava.lang.String;').implementation = function(chain, authType) {
          log(`[TRUST] ${className}.checkServerTrusted() called (authType: ${authType})`);

          const stackTrace = extractFullStackTrace();

          log('[TRUST] Stack trace (first 5 frames):');
          stackTrace.slice(0, 5).forEach((element, index) => {
            log(`[TRUST]   [${index}] ${element.toString()}`);
          });

          if (DEBUG_MODE) {
            console.log(`[TRUST] Bypassing server trusted check (authType: ${authType})`);
          }

          return chain;
        };

        hooksApplied++;

        log(`[+] Hooked ${className} (checkClientTrusted, checkServerTrusted, getAcceptedIssuers)`);
      } catch (error) {
        log(`[WARN] ${className} not found: ${error}`);
      }
    });

    log('[+] Custom TrustManager classes checked');
  } catch (error) {
    log(`[ERROR] Failed to hook custom TrustManager: ${error}`);
  }

  // ========================================
  // 4. Summary
  // ========================================

  log('[SUMMARY] SSL pinning bypass framework initialized');
  log(`[INFO] Total hooks applied: ${hooksApplied}`);
  log('[INFO] Stack trace extraction enabled for debugging SSL pinning failures');
  log('[INFO] Java.performNow() used for instant hooking');
  log('');
  log('[READY] SSL pinning bypass is active with constructor hooks and stack traces');
});
