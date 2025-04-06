var _module = Process.findModuleByName("JailbreakDetector");
console.log(`[+] ${_module.name} is loaded at ${_module.base}`);

Interceptor.attach(Module.findExportByName(null,'xpc_pipe_routine_with_flags'),{
    onEnter: function(args){
        console.log(`Hooked _xpc_pipe_routine_with_flags`);
    },
    onLeave: function(retval){
        console.log(`[*] Original return value: ${retval}`);
        retval.replace(ptr(1));
        console.log(`[*] Manipulated return value: ${retval}`);
    }
});


var blacklist = ["/var/log/apt", "/var/log/dpkg", "/var/lib"];
Interceptor.attach(_module.base.add(0x4574),function(){
    console.log(`[SVC] access: ${this.context.x0.readCString()}`);
    if(blacklist.includes(this.context.x0.readCString())){
        this.context.x0.writeUtf8String("/not/exist");
        console.log(`[-] Manipulating X0: ${this.context.x0.readCString()}`);
    }
});


var blacklist2 = ["/var/lib/filza", "/var/mobile/Library/Filza"];
Interceptor.attach(_module.base.add(0x47d4), function(){
    console.log(`[SVC] access: ${this.context.x0.readCString()}`);
    if(blacklist2.includes(this.context.x0.readCString())){
        this.context.x0.writeUtf8String("/not/exist");
        console.log(`[-] Manipulating X0: ${this.context.x0.readCString()}`);
    }
});

var blacklist3 = ["cy:com.saurik.substrated","org.coolstar.jailbreakd","jailbreakd","cy:com.opa334.jailbreakd"];
Interceptor.attach(Module.findExportByName(null,"bootstrap_look_up"),{
    onEnter: function(args){
        console.log(`[*] Hooked bootstrap_look_up: ${args[1].readCString()}`);
        if(blacklist3.includes(args[1].readCString())){
            args[1].writeUtf8String("not.exist");
            console.log(`[-] Manipulating X0: ${args[1].readCString()}`);
        }
    }
});

Interceptor.attach(_module.base.add(0x4b9c),function(){
    console.log(`[SVC] stat: ${this.context.x0.readCString()}`);
    this.context.x0.writeUtf8String("/not/exist");
    console.log(`Manipulating X0: ${this.context.x0.readCString()}`);
});

Interceptor.attach(_module.base.add(0x4c54),function(){
    console.log(`[SVC] stat2: ${this.context.x0.readCString()}`);
    this.context.x0.writeUtf8String("/not/exist");
    console.log(`Manipulating X0: ${this.context.x0.readCString()}`);
});