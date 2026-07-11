// Bypass common Android root detection
// Usage: frida -U -l root-bypass.js -f com.target.app --no-pause

Java.perform(function() {
    // Hook common root check methods
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmd) {
        var cmdStr = cmd ? cmd.join(' ') : '';
        if (cmdStr.indexOf('su') >= 0 || cmdStr.indexOf('magisk') >= 0 ||
            cmdStr.indexOf('superuser') >= 0 || cmdStr.indexOf('busybox') >= 0) {
            console.log('[+] Blocked root check: ' + cmdStr);
            return null;
        }
        return this.exec(cmd);
    };

    // File.exists for common root files
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getPath();
        if (path.indexOf('/su') >= 0 || path.indexOf('magisk') >= 0 ||
            path.indexOf('Superuser') >= 0 || path.indexOf('busybox') >= 0) {
            console.log('[+] Blocked root file check: ' + path);
            return false;
        }
        return this.exists();
    };

    // SystemProperties.get (root beer, etc)
    try {
        var SystemProperties = Java.use('android.os.SystemProperties');
        SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
            if (key.indexOf('ro.debuggable') >= 0) { return '0'; }
            if (key.indexOf('ro.secure') >= 0) { return '1'; }
            return this.get(key, def);
        };
    } catch(e) {}

    console.log('[+] Root detection bypass active!');
});
