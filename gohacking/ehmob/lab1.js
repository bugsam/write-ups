/// <reference path="frida-gum.d.ts" />

//@bugsam
Java.perform(function() {  
    var Intent = Java.use('android.content.Intent');
    var login = Java.use('br.com.ehmob.lab001.LoginActivity');
    var sucesso = Java.use('br.com.ehmob.lab001.SucessoActivity');

    login.onCreate.implementation = function() {
        var intent = Intent.$new(this,sucesso.class); //context, class
        this.startActivity(intent);

        return login.onCreate.apply(this, arguments);
    }
});

//oryon-farias
Java.perform(function() {
    var LoginActivity = Java.use('br.com.ehmob.lab001.LoginActivity');
    var Intent = Java.use('android.content.Intent');
    var RegistroActivity = Java.use('br.com.ehmob.lab001.RegistroActivity');

    LoginActivity.doLogin.implementation = function () {
        var result = Intent.$new(this, RegistroActivity.class);
        this.startActivity(result);

        return LoginActivity.doLogin.apply(this, arguments);
    }

});


Java.perform(function() {
    var ExternalSynthetic = Java.use ('br.com.ehmob.lab001.LoginActivity$$ExternalSyntheticLambda0');
    var redirActivity = Java.use('br.com.ehmob.lab001.SucessoActivity');
    var intent = Java.use('android.content.Intent');

    ExternalSynthetic.implementation = function () {
        var currentApplication = Java.use('android.app.ActivityThread').currentApplication();

        var context = currentApplication.getApplicationContext();
        var newActivity = intent.$new(context, redirActivity.class);

        context.startActivity(newActivity);

        return ExternalSynthetic.onClick.apply(this, arguments);
    }
});
