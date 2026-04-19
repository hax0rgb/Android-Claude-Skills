/*
 * Universal SSL Pinning Bypass for Android
 * Covers: TrustManagerImpl, OkHttp3, Retrofit, Volley, custom TrustManagers,
 *         HostnameVerifier, SSLContext, WebViewClient, Network Security Config
 *
 * Usage: frida -U -f <package> -l frida-ssl-bypass.js --no-pause
 */

setTimeout(function() {
    Java.perform(function() {
        console.log("[*] SSL Pinning Bypass loaded");

        // 1. TrustManagerImpl (Android system default)
        try {
            var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                console.log('[+] Bypassed TrustManagerImpl for: ' + host);
                return untrustedChain;
            };
            console.log('[+] TrustManagerImpl hooked');
        } catch(e) {
            console.log('[-] TrustManagerImpl: ' + e.message);
        }

        // 2. OkHttp3 CertificatePinner
        try {
            var CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
                console.log('[+] Bypassed OkHttp3 CertificatePinner for: ' + hostname);
            };
            console.log('[+] OkHttp3 CertificatePinner hooked');
        } catch(e) {
            console.log('[-] OkHttp3 CertificatePinner: ' + e.message);
        }

        // 3. OkHttp3 CertificatePinner (legacy overload)
        try {
            var CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(hostname, certs) {
                console.log('[+] Bypassed OkHttp3 CertificatePinner (legacy) for: ' + hostname);
            };
        } catch(e) {}

        // 4. X509TrustManager (custom implementations)
        try {
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');

            var TrustManager = Java.registerClass({
                name: 'com.bypass.TrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; }
                }
            });

            var TrustManagers = [TrustManager.$new()];
            var sslContext = SSLContext.getInstance('TLS');
            sslContext.init(null, TrustManagers, null);

            // Replace default SSLContext
            SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(km, tm, sr) {
                console.log('[+] Bypassed SSLContext.init');
                this.init(km, TrustManagers, sr);
            };
            console.log('[+] X509TrustManager bypass active');
        } catch(e) {
            console.log('[-] X509TrustManager: ' + e.message);
        }

        // 5. HostnameVerifier
        try {
            var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
            var SSLSession = Java.use('javax.net.ssl.SSLSession');

            var Verifier = Java.registerClass({
                name: 'com.bypass.HostnameVerifier',
                implements: [HostnameVerifier],
                methods: {
                    verify: function(hostname, session) {
                        console.log('[+] Bypassed HostnameVerifier for: ' + hostname);
                        return true;
                    }
                }
            });

            // Hook HttpsURLConnection
            try {
                var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
                HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(verifier) {
                    console.log('[+] Replacing default HostnameVerifier');
                    this.setDefaultHostnameVerifier(Verifier.$new());
                };
                HttpsURLConnection.setHostnameVerifier.implementation = function(verifier) {
                    console.log('[+] Replacing instance HostnameVerifier');
                    this.setHostnameVerifier(Verifier.$new());
                };
            } catch(e) {}
            console.log('[+] HostnameVerifier bypass active');
        } catch(e) {
            console.log('[-] HostnameVerifier: ' + e.message);
        }

        // 6. WebViewClient SSL errors
        try {
            var WebViewClient = Java.use('android.webkit.WebViewClient');
            WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
                console.log('[+] Bypassed WebView SSL error');
                handler.proceed();
            };
            console.log('[+] WebViewClient SSL bypass active');
        } catch(e) {
            console.log('[-] WebViewClient: ' + e.message);
        }

        // 7. Apache HTTP (legacy apps)
        try {
            var AbstractVerifier = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
            AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean').implementation = function(host, cns, subjectAlts, strictWithSubDomains) {
                console.log('[+] Bypassed Apache AbstractVerifier for: ' + host);
            };
            console.log('[+] Apache HTTP bypass active');
        } catch(e) {}

        // 8. Conscrypt (newer Android)
        try {
            var Platform = Java.use('com.android.org.conscrypt.Platform');
            Platform.checkServerTrusted.implementation = function(x509tm, chain, authType, engine) {
                console.log('[+] Bypassed Conscrypt Platform.checkServerTrusted');
            };
            console.log('[+] Conscrypt bypass active');
        } catch(e) {}

        // 9. Network Security Config (Android 7+)
        try {
            var NetworkSecurityTrustManager = Java.use('android.security.net.config.NetworkSecurityTrustManager');
            NetworkSecurityTrustManager.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function(certs, authType) {
                console.log('[+] Bypassed NetworkSecurityTrustManager');
            };
            console.log('[+] Network Security Config bypass active');
        } catch(e) {}

        // 10. Trustkit
        try {
            var TrustKit = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
            TrustKit.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(hostname, session) {
                console.log('[+] Bypassed TrustKit for: ' + hostname);
                return true;
            };
            console.log('[+] TrustKit bypass active');
        } catch(e) {}

        console.log('[*] SSL Pinning Bypass complete');
    });
}, 1000);
