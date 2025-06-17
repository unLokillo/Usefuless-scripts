// =========================================================================
//  INICIO SCRIPT ANTI-ROOT (Tu script proporcionado)
// =========================================================================
/*
 * This script combines, fixes & extends a long list of other scripts, most notably including:
 *
 * - https://codeshare.frida.re/@dzonerzy/fridantiroot/
 * - https://github.com/AshenOneYe/FridaAntiRootDetection/blob/main/antiroot.js
 */

Java.perform(function() {
    console.log("[Anti-Root] Iniciando hooks de Java...");
    var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
        "eu.chainfire.supersu.pro", "com.kingouser.com", "com.topjohnwu.magisk"
    ];

    var RootBinaries = ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk", "magisk"];

    var RootProperties = {
        "ro.build.selinux": "1",
        "ro.debuggable": "0",
        "service.adb.root": "0",
        "ro.secure": "1"
    };

    var RootPropertiesKeys = [];

    for (var k in RootProperties) RootPropertiesKeys.push(k);

    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    var Runtime = Java.use('java.lang.Runtime');
    var NativeFile = Java.use('java.io.File');
    var StringJava = Java.use('java.lang.String'); // Renombrado para evitar conflicto con variable String global
    var SystemProperties = Java.use('android.os.SystemProperties');
    var BufferedReader = Java.use('java.io.BufferedReader');
    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
    // var StringBuffer = Java.use('java.lang.StringBuffer'); // No usado, se puede comentar

    var loaded_classes = Java.enumerateLoadedClassesSync();
    send("[Anti-Root] Loaded " + loaded_classes.length + " classes!");

    // var useKeyInfo = false; // No usado
    // var useProcessManager = false; // No usado

    send("[Anti-Root] loaded: " + loaded_classes.indexOf('java.lang.ProcessManager'));
    if (loaded_classes.indexOf('java.lang.ProcessManager') != -1) {
        try {
            //useProcessManager = true;
            //var ProcessManager = Java.use('java.lang.ProcessManager');
        } catch (err) {
            send("[Anti-Root] ProcessManager Hook failed: " + err);
        }
    } else {
        send("[Anti-Root] ProcessManager hook not loaded");
    }

    // var KeyInfo = null; // No usado
    if (loaded_classes.indexOf('android.security.keystore.KeyInfo') != -1) {
        try {
            //useKeyInfo = true;
            //var KeyInfo = Java.use('android.security.keystore.KeyInfo');
        } catch (err) {
            send("[Anti-Root] KeyInfo Hook failed: " + err);
        }
    } else {
        send("[Anti-Root] KeyInfo hook not loaded");
    }

    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pname, flags) {
        var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
        if (shouldFakePackage) {
            send("[Anti-Root] Bypass root check for package: " + pname);
            pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
        }
        return this.getPackageInfo.overload('java.lang.String', 'int').call(this, pname, flags);
    };

    NativeFile.exists.implementation = function() {
        var name = NativeFile.getName.call(this); // Debería ser this.getName()
        var shouldFakeReturn = (RootBinaries.indexOf(name) > -1);
        if (shouldFakeReturn) {
            send("[Anti-Root] Bypass return value for binary: " + name);
            return false;
        } else {
            return this.exists.call(this);
        }
    };

    var exec = Runtime.exec.overload('[Ljava.lang.String;');
    var exec1 = Runtime.exec.overload('java.lang.String');
    var exec2 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;');
    var exec3 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;');
    var exec4 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File');
    var exec5 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File');

    exec5.implementation = function(cmd, env, dir) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("[Anti-Root] Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("[Anti-Root] Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec5.call(this, cmd, env, dir);
    };

    exec4.implementation = function(cmdarr, env, file) {
        for (var i = 0; i < cmdarr.length; i = i + 1) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("[Anti-Root] Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("[Anti-Root] Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
        }
        return exec4.call(this, cmdarr, env, file);
    };

    exec3.implementation = function(cmdarr, envp) {
        for (var i = 0; i < cmdarr.length; i = i + 1) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("[Anti-Root] Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("[Anti-Root] Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
        }
        return exec3.call(this, cmdarr, envp);
    };

    exec2.implementation = function(cmd, env) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("[Anti-Root] Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("[Anti-Root] Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec2.call(this, cmd, env);
    };

    exec.implementation = function(cmd) {
        for (var i = 0; i < cmd.length; i = i + 1) {
            var tmp_cmd = cmd[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("[Anti-Root] Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("[Anti-Root] Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
        }
        return exec.call(this, cmd);
    };

    exec1.implementation = function(cmd) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("[Anti-Root] Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("[Anti-Root] Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec1.call(this, cmd);
    };

    StringJava.contains.implementation = function(name) {
        if (name == "test-keys") {
            send("[Anti-Root] Bypass test-keys check");
            return false;
        }
        return this.contains.call(this, name);
    };

    var systemPropertiesGet = SystemProperties.get.overload('java.lang.String'); // Renombrado para evitar conflicto
    systemPropertiesGet.implementation = function(name) {
        if (RootPropertiesKeys.indexOf(name) != -1) {
            send("[Anti-Root] Bypass " + name);
            return RootProperties[name];
        }
        return this.get.call(this, name);
    };

    BufferedReader.readLine.overload('boolean').implementation = function(ignoreLF) { // Añadido parámetro que faltaba
        var text = this.readLine.overload('boolean').call(this, ignoreLF); // Pasado el parámetro
        if (text === null) {
            // just pass
        } else {
            var shouldFakeRead = (text.indexOf("ro.build.tags=test-keys") > -1);
            if (shouldFakeRead) {
                send("[Anti-Root] Bypass build.prop file read");
                text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
            }
        }
        return text;
    };

    // var executeCommand = ProcessBuilder.command.overload('java.util.List'); // No usado, se puede comentar

    ProcessBuilder.start.implementation = function() {
        var cmd = this.command.call(this);
        var shouldModifyCommand = false;
        if (cmd !== null) { // Añadida comprobación de nulidad
            for (var i = 0; i < cmd.size(); i = i + 1) {
                var tmp_cmd = cmd.get(i).toString();
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd.indexOf("mount") != -1 || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd.indexOf("id") != -1) {
                    shouldModifyCommand = true;
                }
            }
            if (shouldModifyCommand) {
                send("[Anti-Root] Bypass ProcessBuilder " + cmd);
                this.command.call(this, ["grep"]);
                return this.start.call(this);
            }
            if (cmd.indexOf("su") != -1) {
                send("[Anti-Root] Bypass ProcessBuilder " + cmd);
                this.command.call(this, ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"]);
                return this.start.call(this);
            }
        }
        return this.start.call(this);
    };

    // Las secciones de ProcessManager y KeyInfo están comentadas en el original y parecen no usarse activamente.
    // if (useProcessManager) { ... }
    // if (useKeyInfo) { ... }

    console.log("[Anti-Root] Hooks de Java aplicados.");
}); // FIN DEL Java.perform() DEL SCRIPT ANTI-ROOT

// =========================================================================
//  INICIO CÓDIGO NATIVO Y FUNCIONES GLOBALES DEL SCRIPT ANTI-ROOT
//  (Estas partes se ejecutan fuera del Java.perform inicial)
// =========================================================================
const commonPaths = [
    "/data/local/bin/su", "/data/local/su", "/data/local/xbin/su", "/dev/com.koushikdutta.superuser.daemon/",
    "/sbin/su", "/system/app/Superuser.apk", "/system/bin/failsafe/su", "/system/bin/su", "/su/bin/su",
    "/system/etc/init.d/99SuperSUDaemon", "/system/sd/xbin/su", "/system/xbin/busybox", "/system/xbin/daemonsu",
    "/system/xbin/su", "/system/sbin/su", "/vendor/bin/su", "/cache/su", "/data/su", "/dev/su",
    "/system/bin/.ext/su", "/system/usr/we-need-root/su", "/system/app/Kinguser.apk", "/data/adb/magisk",
    "/sbin/.magisk", "/cache/.disable_magisk", "/dev/.magisk.unblock", "/cache/magisk.log",
    "/data/adb/magisk.img", "/data/adb/magisk.db", "/data/adb/magisk_simple", "/init.magisk.rc",
    "/system/xbin/ku.sud", "/data/adb/ksu", "/data/adb/ksud"
];

const ROOTmanagementApp = [
    "com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
    "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su",
    "com.koushikdutta.rommanager", "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher",
    "com.chelpus.lackypatch", "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro",
    "com.topjohnwu.magisk", "me.weishu.kernelsu"
];

function stackTraceHere(isLog) {
    var Exception = Java.use('java.lang.Exception');
    var Log = Java.use('android.util.Log');
    var stackinfo = Log.getStackTraceString(Exception.$new());
    if (isLog) {
        console.log(stackinfo);
    } else {
        return stackinfo;
    }
}

// function stackTraceNativeHere(isLog){ // Esta función no se usa y requiere contexto de this.context
//     var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
//     .map(DebugSymbol.fromAddress)
//     .join("\n\t");
//     console.log(backtrace)
// }

function bypassJavaFileCheck() {
    Java.perform(function() { // Envolver en Java.perform si usa Java.use
        var UnixFileSystem = Java.use("java.io.UnixFileSystem");
        UnixFileSystem.checkAccess.implementation = function(file, access) {
            // var stack = stackTraceHere(false); // Puede ser intensivo, comentar si no es necesario
            const filename = file.getAbsolutePath();
            if (filename.indexOf("magisk") >= 0) {
                console.log("[Anti-Root] Bypass Java File Check (magisk): " + filename);
                return false;
            }
            if (commonPaths.indexOf(filename) >= 0) {
                console.log("[Anti-Root] Bypass Java File Check (commonPaths): " + filename);
                return false;
            }
            return this.checkAccess(file, access);
        };
    });
}

function bypassNativeFileCheck() {
    var fopen = Module.findExportByName("libc.so", "fopen");
    if (fopen) {
        Interceptor.attach(fopen, {
            onEnter: function(args) {
                this.inputPath = args[0].readUtf8String();
            },
            onLeave: function(retval) {
                if (retval.toInt32() != 0) {
                    if (commonPaths.indexOf(this.inputPath) >= 0) {
                        console.log("[Anti-Root] Bypass native fopen: " + this.inputPath);
                        retval.replace(ptr(0x0));
                    }
                }
            }
        });
    } else { console.warn("[Anti-Root] libc.so fopen not found"); }


    var access_libc = Module.findExportByName("libc.so", "access"); // Renombrado para evitar conflicto
    if (access_libc) {
        Interceptor.attach(access_libc, {
            onEnter: function(args) {
                this.inputPath = args[0].readUtf8String();
            },
            onLeave: function(retval) {
                if (retval.toInt32() == 0) {
                    if (commonPaths.indexOf(this.inputPath) >= 0) {
                        console.log("[Anti-Root] Bypass native access: " + this.inputPath);
                        retval.replace(ptr(-1));
                    }
                }
            }
        });
    } else { console.warn("[Anti-Root] libc.so access not found"); }

    var system_libc = Module.findExportByName("libc.so", "system"); // Renombrado para evitar conflicto
     if (system_libc) {
        Interceptor.attach(system_libc, {
            onEnter: function(args) {
                var cmd = Memory.readCString(args[0]);
                send("[Anti-Root] SYSTEM CMD: " + cmd);
                if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
                    send("[Anti-Root] Bypass native system (getprop/mount/etc): " + cmd);
                    Memory.writeUtf8String(args[0], "grep");
                }
                if (cmd == "su") {
                    send("[Anti-Root] Bypass native system (su): " + cmd);
                    Memory.writeUtf8String(args[0], "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled");
                }
            },
            onLeave: function(retval) {}
        });
    } else { console.warn("[Anti-Root] libc.so system not found"); }
}

function setProp() {
    Java.perform(function() { // Envolver en Java.perform
        var Build = Java.use("android.os.Build");
        try {
            var TAGS = Build.class.getDeclaredField("TAGS");
            TAGS.setAccessible(true);
            TAGS.set(null, "release-keys");
        } catch(e) { console.error("[Anti-Root] Error setting Build.TAGS: " + e); }

        try {
            var FINGERPRINT = Build.class.getDeclaredField("FINGERPRINT");
            FINGERPRINT.setAccessible(true);
            FINGERPRINT.set(null, "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys");
        } catch(e) { console.error("[Anti-Root] Error setting Build.FINGERPRINT: " + e); }
    });

    var system_property_get = Module.findExportByName("libc.so", "__system_property_get");
    if (system_property_get) {
        Interceptor.attach(system_property_get, {
            onEnter: function(args) {
                this.key = args[0].readCString();
                this.ret = args[1];
            },
            onLeave: function(retval) { // retval aquí es el valor de retorno de __system_property_get
                if (this.key == "ro.build.fingerprint") {
                    var tmp = "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys";
                    var p = Memory.allocUtf8String(tmp);
                    Memory.copy(this.ret, p, tmp.length + 1);
                    console.log("[Anti-Root] Faked ro.build.fingerprint via __system_property_get");
                }
                 // Podrías añadir más propiedades aquí si es necesario
                if (this.key == "ro.build.tags" && this.ret) {
                    var currentVal = Memory.readCString(this.ret);
                    if (currentVal == "test-keys") {
                        var fakeTag = "release-keys";
                        var p = Memory.allocUtf8String(fakeTag);
                        Memory.copy(this.ret, p, fakeTag.length + 1);
                        console.log("[Anti-Root] Faked ro.build.tags via __system_property_get");
                    }
                }
            }
        });
    }  else { console.warn("[Anti-Root] libc.so __system_property_get not found"); }
}

function bypassRootAppCheck() {
    Java.perform(function() { // Envolver en Java.perform
        var ApplicationPackageManager = Java.use("android.app.ApplicationPackageManager");
        ApplicationPackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(str, i) {
            if (ROOTmanagementApp.indexOf(str) >= 0) {
                console.log("[Anti-Root] Bypass Root App Check: " + str);
                str = "ashen.one.ye.not.found"; // Fake package name
            }
            return this.getPackageInfo.call(this, str, i); // Usar call para llamar al método original en el contexto correcto
        };
    });
}

function bypassShellCheck() {
    Java.perform(function() { // Envolver en Java.perform
        var StringJava = Java.use('java.lang.String'); // Usar el renombrado
        var ProcessImpl = Java.use("java.lang.ProcessImpl");

        ProcessImpl.start.implementation = function(cmdarray, env, dir, redirects, redirectErrorStream) {
            if (cmdarray !== null && cmdarray.length > 0) { // Comprobar si cmdarray es válido
                if (cmdarray[0] == "mount") {
                    console.log("[Anti-Root] Bypass Shell (mount): " + cmdarray.toString());
                    arguments[0] = Java.array('java.lang.String', [StringJava.$new("")]);
                    // return ProcessImpl.start.apply(this, arguments); // No necesitas llamar a apply si ya modificaste arguments
                }
                if (cmdarray[0] == "getprop") {
                    console.log("[Anti-Root] Bypass Shell (getprop): " + cmdarray.toString());
                    const prop = ["ro.secure", "ro.debuggable"];
                    if (cmdarray.length > 1 && prop.indexOf(cmdarray[1]) >= 0) {
                        arguments[0] = Java.array('java.lang.String', [StringJava.$new("")]);
                    }
                }
                if (cmdarray[0].indexOf("which") >= 0) {
                    const prop = ["su"];
                    if (cmdarray.length > 1 && prop.indexOf(cmdarray[1]) >= 0) {
                        console.log("[Anti-Root] Bypass Shell (which su): " + cmdarray.toString());
                        arguments[0] = Java.array('java.lang.String', [StringJava.$new("")]);
                    }
                }
                // Bypass 'su' command more broadly
                if (cmdarray.includes("su")) {
                     console.log("[Anti-Root] Bypass Shell (su command): " + cmdarray.toString());
                     arguments[0] = Java.array('java.lang.String', [StringJava.$new("justafakecommandthatcannotexists")]);
                }
            }
            return ProcessImpl.start.apply(this, arguments); // Llamar siempre al original con los argumentos (posiblemente modificados)
        };
    });
}

// Llamar a las funciones de bypass que están fuera del Java.perform inicial
console.log("[Anti-Root] Aplicando hooks nativos y globales...");
bypassNativeFileCheck();
bypassJavaFileCheck(); // Esta función ahora tiene su propio Java.perform
setProp();             // Esta función ahora tiene su propio Java.perform
bypassRootAppCheck();  // Esta función ahora tiene su propio Java.perform
bypassShellCheck();    // Esta función ahora tiene su propio Java.perform
console.log("[Anti-Root] Todos los hooks de anti-root aplicados.");
// =========================================================================
//  FIN SCRIPT ANTI-ROOT
// =========================================================================
// =========================================================================
//  FRIDA SCRIPT GENÉRICO PARA BÚSQUEDA DE CADENAS EN MEMORIA (RPC)
//  generic_memory_search_rpc.js
//
//  Instrucciones:
//  1. Añade este script al final de tu script principal de Frida.
//  2. Lanza Frida: frida -U -f com.tu.app -l tu_script_completo.js --no-pause
//  3. Desde la consola REPL de Frida que se abre, llama a:
//     rpc.exports.searchstrings(["cadena1", "cadena2"], {maxResultsPerTerm: 5, showHexdump: false});
// =========================================================================

(function() { // IIFE para encapsular todo el módulo de búsqueda

    // --- INICIO FUNCIONES HELPER ---
    function _stringToHex(str) {
        var hex = '';
        for (var i = 0; i < str.length; i++) {
            var charCode = str.charCodeAt(i);
            var hexCode = charCode.toString(16);
            hex += (hexCode.length < 2 ? '0' : '') + hexCode;
        }
        return hex;
    }

    function _extractReadableStrings(buffer, minLength) {
        var strings = [];
        var currentString = "";
        if (!buffer || typeof buffer.byteLength === 'undefined') {
            // console.warn("[MemorySearch] _extractReadableStrings: buffer inválido.");
            return strings; // Devolver array vacío si el buffer no es válido
        }
        var dataView = new Uint8Array(buffer);

        for (var i = 0; i < dataView.length; i++) {
            var charCode = dataView[i];
            if (charCode >= 32 && charCode <= 126) { // Caracteres ASCII imprimibles
                currentString += String.fromCharCode(charCode);
            } else {
                if (currentString.length >= minLength) {
                    strings.push(currentString);
                }
                currentString = "";
            }
        }
        if (currentString.length >= minLength) { // Capturar la última cadena si existe
            strings.push(currentString);
        }
        return strings;
    }
    // --- FIN FUNCIONES HELPER ---

    function _searchStringsInMemory(searchTermsInput, options) {
        console.log("\n==================================================");
        console.log("  [MemorySearch] INICIANDO BÚSQUEDA DE CADENAS");
        console.log("==================================================");

        var defaultOptions = {
            minContextStringLength: 8,
            maxResultsPerTerm: 0,
            hexdumpOffsetBefore: 16,
            hexdumpLength: 64,
            showHexdump: true,
            showRangeInfo: false
        };
        var currentOptions = Object.assign({}, defaultOptions, options || {});

        var searchTerms = [];
        if (typeof searchTermsInput === 'string') {
            searchTerms = [searchTermsInput];
        } else if (Array.isArray(searchTermsInput)) {
            searchTerms = searchTermsInput;
        } else {
            console.error("[MemorySearch] [!] Error: El argumento de búsqueda debe ser una cadena o un array de cadenas.");
            return "Error: Input inválido";
        }

        if (searchTerms.length === 0) {
            console.warn("[MemorySearch] [!] No se especificaron cadenas para buscar.");
            return "Advertencia: No hay términos de búsqueda";
        }

        console.log("[MemorySearch] [*] Cadenas a buscar: " + searchTerms.join(", "));
        console.log("[MemorySearch] [*] Opciones: " + JSON.stringify(currentOptions));

        var regions = [];
        try {
             regions = Process.enumerateRangesSync({protection: 'r--', coalesce: true});
        } catch (e) {
            console.error("[MemorySearch] [!] Error al enumerar regiones de memoria: " + e.message);
            return "Error: Falló enumerateRangesSync";
        }

        var summary = {};
        var overallTotalFoundCount = 0; // Cuenta total de hallazgos brutos
        var overallDisplayedDetailsCount = 0; // Cuenta de hallazgos cuyos detalles se mostraron

        console.log("[MemorySearch] [*] Escaneando " + regions.length + " regiones de memoria legibles...");

        searchTerms.forEach(function(term) {
            if (typeof term !== 'string' || term.length === 0) {
                console.warn("[MemorySearch] [!] Omitiendo término de búsqueda inválido: " + term);
                return;
            }

            summary[term] = { count: 0, displayedDetails: 0, errors: 0 };
            var pattern = _stringToHex(term);
            console.log("\n--- [MemorySearch] Buscando término: \"" + term + "\" ---");

            var termHitsInCurrentScan = 0; // Para el conteo total del término en este escaneo

            for (var i = 0; i < regions.length; i++) {
                var range = regions[i];

                // Optimización: Si ya hemos mostrado suficientes detalles para este término, y maxResultsPerTerm está activado,
                // solo escaneamos para contar, no para procesar detalles.
                if (currentOptions.maxResultsPerTerm > 0 && summary[term].displayedDetails >= currentOptions.maxResultsPerTerm) {
                    try {
                        var quickScanResults = Memory.scanSync(range.base, range.size, pattern);
                        termHitsInCurrentScan += quickScanResults.length;
                    } catch(e_qs) { /* ignorar errores en el conteo rápido */ }
                    continue; // Ir a la siguiente región
                }

                try {
                    var results = Memory.scanSync(range.base, range.size, pattern);

                    if (results.length > 0) {
                        termHitsInCurrentScan += results.length;

                        for (var j = 0; j < results.length; j++) {
                            var hit = results[j];
                            
                            // Si aún no hemos alcanzado el límite de visualización para este término
                            if (currentOptions.maxResultsPerTerm === 0 || summary[term].displayedDetails < currentOptions.maxResultsPerTerm) {
                                summary[term].displayedDetails++;
                                overallDisplayedDetailsCount++;

                                console.log("\n  ------------------------------------------------");
                                // Usar displayedDetails para el # de detalle mostrado, y count para el # de hallazgo del término
                                console.log("  [MemorySearch] [+] Detalle Hallazgo #" + overallDisplayedDetailsCount + " (Término: \"" + term + "\", Coincidencia Término #" + (summary[term].count + j + 1) + ")");
                                console.log("      Dirección: " + hit.address);
                                if (currentOptions.showRangeInfo) {
                                    console.log("      Región   : " + range.base + " - " + range.base.add(range.size) + " (Prot: " + range.protection + ")");
                                }

                                var dumpAddress = hit.address;
                                var actualOffsetBefore = 0;
                                if (currentOptions.hexdumpOffsetBefore > 0) {
                                    actualOffsetBefore = Math.min(currentOptions.hexdumpOffsetBefore, hit.address.toInt32() - range.base.toInt32());
                                    if (actualOffsetBefore < 0) actualOffsetBefore = 0;
                                    dumpAddress = hit.address.sub(actualOffsetBefore);
                                }
                                
                                var dumpLength = currentOptions.hexdumpLength;
                                var availableInRange = range.base.add(range.size).sub(dumpAddress).toInt32();
                                
                                if (availableInRange <= 0) {
                                     console.log("      [MemorySearch] [!] Sin espacio para dumpear contexto en " + dumpAddress);
                                     summary[term].errors++;
                                     continue; // Saltar al siguiente hit
                                }
                                dumpLength = Math.min(dumpLength, availableInRange);
                                if (dumpLength <=0) {
                                    console.log("      [MemorySearch] [!] Longitud de dump no válida: " + dumpLength);
                                    summary[term].errors++;
                                    continue; // Saltar al siguiente hit
                                }
                                
                                var hexdumpSuccess = false;
                                if (currentOptions.showHexdump) {
                                    console.log("\n      Contexto Hexdump (@" + dumpAddress + ", len:" + dumpLength + "):");
                                    try {
                                        Memory.readU8(dumpAddress); // Validar lectura
                                        var hexdumpContent = hexdump(dumpAddress, {
                                            length: dumpLength, ansi: false, header: false, offset: 0
                                        });
                                        console.log(hexdumpContent);
                                        hexdumpSuccess = true;
                                    } catch (e_dump) {
                                        summary[term].errors++;
                                        console.log("      [MemorySearch] [!] Error al dumpear: " + e_dump.message);
                                    }
                                }

                                console.log("\n      Posibles cadenas legibles cercanas (min len " + currentOptions.minContextStringLength + "):");
                                try {
                                    // Solo leer si el dumpAddress y dumpLength son válidos
                                    var contextBuffer = Memory.readByteArray(dumpAddress, dumpLength);
                                    var readableStrings = _extractReadableStrings(contextBuffer, currentOptions.minContextStringLength); 
                                    if (readableStrings.length > 0) {
                                        readableStrings.forEach(function(s) {
                                            if (s.toLowerCase().includes(term.toLowerCase())) {
                                                console.log("        * \"" + s + "\" (CONTIENE TÉRMINO)");
                                            } else {
                                                console.log("        - \"" + s + "\"");
                                            }
                                        });
                                    } else {
                                        console.log("        (Ninguna encontrada con longitud suficiente)");
                                    }
                                } catch (e_extract) {
                                    console.log("      [MemorySearch] [!] Error al extraer cadenas: " + e_extract.message);
                                    summary[term].errors++;
                                }
                                console.log("  ------------------------------------------------");
                            } // Fin de if (mostrar detalles)
                        } // Fin de for (results en una región)
                    } // Fin de if (results.length > 0)
                } catch (e_scan_region) {
                    // console.warn("[MemorySearch] [!] Advertencia al escanear región " + range.base + ": " + e_scan_region.message);
                }
            } // Fin del bucle de regiones (for i)

            summary[term].count = termHitsInCurrentScan; // Actualizar el conteo total para el término
            overallTotalFoundCount += termHitsInCurrentScan; // Sumar al conteo global de hallazgos

            if (currentOptions.maxResultsPerTerm > 0 && summary[term].count > summary[term].displayedDetails) {
                console.log("  --- [MemorySearch] ...y " + (summary[term].count - summary[term].displayedDetails) + " más coincidencias para \"" + term + "\" (detalles no mostrados).");
            }
            if (summary[term].count === 0) {
                console.log("  [MemorySearch] [*] No se encontró el término \"" + term + "\".");
            }
        }); // Fin del bucle de searchTerms

        console.log("\n==================================================");
        console.log("  [MemorySearch] RESUMEN DE LA BÚSQUEDA");
        console.log("==================================================");
        // El overallTotalFoundCount puede ser mayor que la suma de summary[term].count si hay solapamientos
        // Es mejor reportar la suma de los conteos individuales para evitar confusión.
        var sumOfTermCounts = 0;
        searchTerms.forEach(function(t) { if(summary[t]) sumOfTermCounts += summary[t].count; });
        console.log("  Total de coincidencias encontradas (suma por término): " + sumOfTermCounts);
        console.log("  Total de detalles de hallazgos mostrados: " + overallDisplayedDetailsCount);
        console.log("  ------------------------------------------------");
        searchTerms.forEach(function(term) {
            if (summary[term]) {
                console.log("  Término: \"" + term + "\"");
                console.log("    - Coincidencias encontradas : " + summary[term].count);
                if (currentOptions.maxResultsPerTerm > 0 || summary[term].count > 0) { // Mostrar siempre si hay hallazgos
                     console.log("    - Detalles mostrados      : " + summary[term].displayedDetails);
                }
                console.log("    - Errores dumpeando/extrayendo: " + summary[term].errors);
            }
        });
        console.log("==================================================");
        return "Búsqueda completada. Revisa la consola de Frida.";
    }


    // Asegurar que rpc y rpc.exports existen.
    if (typeof rpc === 'undefined') {
        // Esto es poco probable en un script de Frida estándar, pero por si acaso.
        // En la práctica, Frida provee 'rpc'.
        global.rpc = { exports: {} };
    } else if (typeof rpc.exports === 'undefined') {
        rpc.exports = {};
    }

    // Exportar la función para ser llamada vía RPC
    rpc.exports.searchstrings = function(searchTerms, options) {
        // Java.performNow envuelve la lógica para asegurar que se ejecuta
        // en un hilo con acceso a la VM de Java si fuera necesario,
        // aunque Memory.scanSync y otras APIs de Frida a menudo no lo requieren explícitamente
        // cuando se llaman desde un script de Frida. Es una buena práctica para RPC.
        var resultMessage = "Llamada RPC recibida.";
        try {
            Java.performNow(function() { // Usar performNow para ejecución síncrona en el contexto de la llamada RPC
                resultMessage = _searchStringsInMemory(searchTerms, options);
            });
        } catch (e) {
            console.error("[MemorySearch] [RPC EXCEPTION] " + e.message);
            if (e.stack) console.error(e.stack);
            resultMessage = "Error durante la ejecución RPC: " + e.message;
        }
        return resultMessage; // Devolver el mensaje para el llamador (Python o consola)
    };

    console.log("[MemorySearchModule] [+] Módulo de búsqueda de cadenas en memoria cargado y listo.");
    console.log("    -> Desde la consola REPL de Frida, usa:");
    console.log("       rpc.exports.searchstrings(['termino'], {'maxResultsPerTerm': 5, 'showHexdump': false})");

})();
// =========================================================================
//  FIN SCRIPT GENÉRICO PARA BÚSQUEDA DE CADENAS EN MEMORIA
// =========================================================================
