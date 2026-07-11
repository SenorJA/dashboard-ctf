// Frida Script Template for VulnForge
// Replace TARGET_CLASS and TARGET_METHOD with actual values

Java.perform(function() {
    console.log('[+] Script loaded');

    // Example: Hook a method
    // var TargetClass = Java.use('com.target.app.TargetClass');
    // TargetClass.targetMethod.implementation = function(arg) {
    //     console.log('[+] Hooked: ' + arg);
    //     return this.targetMethod(arg);
    // };

    console.log('[+] Ready');
});
