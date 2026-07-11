// Universal SSL Pinning Bypass for Android
// Usage: frida -U -l ssl-bypass.js -f com.target.app --no-pause

Java.perform(function() {
    // Bypass TrustManager
    var TrustManager = Java.use('javax.net.ssl.TrustManager');
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    var TrustAllManager = Java.registerClass({
        name: 'com.vulnforge.TrustAllManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var TrustAllHostnameVerifier = Java.registerClass({
        name: 'com.vulnforge.TrustAllVerifier',
        implements: [Java.use('javax.net.ssl.HostnameVerifier')],
        methods: {
            verify: function(hostname, session) { return true; }
        }
    });

    // Hook SSLContext.init to use our trust manager
    SSLContext.init.implementation = function(keyManager, trustManager, secureRandom) {
        console.log('[+] SSLContext.init hooked - applying trust-all');
        this.init.call(this, keyManager, [TrustAllManager.$new()], secureRandom);
    };

    // Hook HttpsURLConnection
    var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
    HttpsURLConnection.setHostnameVerifier.implementation = function(verifier) {
        console.log('[+] HttpsURLConnection.setHostnameVerifier hooked');
    };
    HttpsURLConnection.getHostnameVerifier.implementation = function() {
        return TrustAllHostnameVerifier.$new();
    };

    // OkHttp3
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        OkHttpClient.newCall.implementation = function(request) {
            console.log('[+] OkHttp call intercepted: ' + request.url());
            return this.newCall(request);
        };
    } catch(e) {}

    console.log('[+] SSL Pinning bypass active!');
});
