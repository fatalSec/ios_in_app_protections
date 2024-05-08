Interceptor.attach(Module.findExportByName(null, "NSLog"), {
    onEnter: function(args){
        console.log(`[*] NSLog intercepted...`);
        console.log(ObjC.Object(ptr(args[0])));
    }
});

Interceptor.attach(Module.findExportByName(null, "ptrace"), {
    onEnter: function(args){
        console.log(`[*] ptrace intercepted...`);
        var request = args[0].toInt32();
        if(request == 31){
            console.log(`[+] request: ${request}\n Bypassing it...`);
            args[0] = ptr(-1);
        }
    }
});

Interceptor.attach(Module.findExportByName(null, "getppid"), {
    onLeave: function(retval){
        console.log(`[*] getppid intercepted...`);
        var ret = retval.toInt32();
        console.log(`[+] retval: ${ret}`);
        if(ret !== 1){
            console.log(`[-] Bypassing it...`);
            retval.replace(0x1);
        }
    }
});

Interceptor.attach(Module.findExportByName(null, "sysctl"), {
    onEnter: function(args){
        this.kinfo = this.context.x2;
    },
    onLeave: function(retval){
        console.log(`[*] sysctl intercepted...`);
        var p = this.kinfo.add(32);
        var p_flag = p.readInt() & 0x00000800;
        if(p_flag === 0x800){
            console.log(`[-] Bypassing it...`);
            p.writeInt(0);
        }
    }
});

const tamper_libs = [
    "Substrate",
    "cycript",
    "SSLKillSwitch",
    "SSLKillSwitch2",
    "frida"
];

Interceptor.attach(Module.findExportByName(null, "strstr"), {
    onEnter: function(args){
        var i = tamper_libs.length;
        this.using_tamper_lib = false;
        while(i--){
            var lib = args[1].readCString();
            if(lib == tamper_libs[i]){
                console.log(`strstr invoked using ${lib}\n Bypassing it...`);
                this.using_tamper_lib = true;
            
            }
        }
    },
    onLeave: function(retval){
        if(this.using_tamper_lib){
            retval.replace(0x00);
        }
    }
});