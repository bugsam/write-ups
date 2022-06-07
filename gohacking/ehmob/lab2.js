/// <reference path="frida-gum.d.ts" />

//bugsam
Java.perform(function() {  
    var Intent = Java.use('android.content.Intent');
    var login = Java.use('br.com.ehmob.lab002.MainActivity');
    var SucessoActivity = Java.use('br.com.ehmob.lab002.SucessoActivity');

    login.onCreate.implementation = function() {
        var intent = Intent.$new(this, SucessoActivity.class);
        this.startActivity(intent);

        return login.onCreate.apply(this, arguments);
    }
});

//oryon-farias
Java.perform(function(){
    var MainActivity = Java.use('br.com.ehmob.lab002.MainActivity');

    var boo = Java.use('java.lang.Boolean').$new('True');

    var object = MainActivity.class.getDeclaredField('redirectActivity');
    object.set(this, boo);

    return MainActivity.onCreate.apply(this, arguments);
});
