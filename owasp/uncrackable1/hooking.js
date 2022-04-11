/// <reference path="frida-gum.d.ts" />

function rootLib(){
    var b = Java.use("sg.vantagepoint.a.b");    
    var c = Java.use("sg.vantagepoint.a.c");
    
    b.a.overload('android.content.Context').implementation = function(v1){
        console.log("isDebuggable bypass");
        return false;
    }

    c.a.overload().implementation = function(){
        console.log("suExist bypass");
        return false;
    }

    c.b.overload().implementation = function(){
        console.log("signKey bypass");
        return false;
    }

    c.c.overload().implementation = function(){
        console.log("binariesExist bypass");
        return false;
    }
};

Java.perform(function () {
    rootLib();
})
