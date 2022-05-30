# Exercises

## Lab 1
>  Objetivo do LAB: 
> - Alterar o AndroidManifest.xml para abrir a activity 
> RegistroActivity ao invés da Tela de login.

````
apktool decode lab001.apk
````

Change LoginActivity to RegistroActivity && RegistroActivity to LoginActivity on AndroidManifest.xml

````xml
<?xml version="1.0" encoding="utf-8" standalone="no"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" android:compileSdkVersion="31" android:compileSdkVersionCodename="12" package="br.com.ehmob.lab001" platformBuildVersionCode="31" platformBuildVersionName="12">
    <application android:allowBackup="true" android:appComponentFactory="androidx.core.app.CoreComponentFactory" android:icon="@mipmap/ic_launcher_go_hacking" android:label="@string/app_name" android:roundIcon="@mipmap/ic_launcher_go_hacking" android:supportsRtl="true" android:theme="@style/Theme.PontoEletrônico">
        <!--<activity android:exported="true" android:name="br.com.ehmob.lab001.LoginActivity">
             <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        <activity android:name="br.com.ehmob.lab001.RegistroActivity"/>
	-->
        <activity android:exported="true" android:name="br.com.ehmob.lab001.RegistroActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <activity android:name="br.com.ehmob.lab001.LoginActivity"/>
        <activity android:name="br.com.ehmob.lab001.SucessoActivity"/>
        <provider android:authorities="br.com.ehmob.lab001.androidx-startup" android:exported="false" android:name="androidx.startup.InitializationProvider">
            <meta-data android:name="androidx.emoji2.text.EmojiCompatInitializer" android:value="androidx.startup"/>
            <meta-data android:name="androidx.lifecycle.ProcessLifecycleInitializer" android:value="androidx.startup"/>
        </provider>
    </application>
</manifest>
````


````
$ apktool build exercise1/ -o exercise1_raw.apk

$ objection signapk exercise1_raw.apk

$ adb install exercise1_raw.objection.apk
`````
<img width="220" src="https://user-images.githubusercontent.com/44240720/170896297-ac7bf14f-ce31-4166-bfdb-bbb98803163d.png">


## Lab 2

> Objetivo do LAB parte 2: 
> - Alterar o evento do botão “login” para abrir a activity 
> RegistroActivity ao invés da Tela de login.

Patch the LoginActivity.smali 
Commenting two if-eqz
````smali
.method private doLogin()V
    .locals 3

    .line 25
    iget-object v0, p0, Lbr/com/ehmob/lab001/LoginActivity;->binding:Lbr/com/ehmob/lab001/databinding/ActivityLoginBinding;

    iget-object v0, v0, Lbr/com/ehmob/lab001/databinding/ActivityLoginBinding;->loginField:Lcom/google/android/material/textfield/TextInputEditText;

    invoke-virtual {v0}, Lcom/google/android/material/textfield/TextInputEditText;->getText()Landroid/text/Editable;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    .line 26
    iget-object v1, p0, Lbr/com/ehmob/lab001/LoginActivity;->binding:Lbr/com/ehmob/lab001/databinding/ActivityLoginBinding;

    iget-object v1, v1, Lbr/com/ehmob/lab001/databinding/ActivityLoginBinding;->passwordField:Lcom/google/android/material/textfield/TextInputEditText;

    invoke-virtual {v1}, Lcom/google/android/material/textfield/TextInputEditText;->getText()Landroid/text/Editable;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v1

    const-string v2, "root"

    .line 30
    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    #if-eqz v0, :cond_0

    const-string v0, "toor"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    #if-eqz v0, :cond_0

    .line 31
    new-instance v0, Landroid/content/Intent;

    const-class v1, Lbr/com/ehmob/lab001/RegistroActivity;

    invoke-direct {v0, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 32
    invoke-virtual {p0, v0}, Lbr/com/ehmob/lab001/LoginActivity;->startActivity(Landroid/content/Intent;)V
        
    goto :goto_0

    .line 34
    :cond_0
    iget-object v0, p0, Lbr/com/ehmob/lab001/LoginActivity;->binding:Lbr/com/ehmob/lab001/databinding/ActivityLoginBinding;

    invoke-virtual {v0}, Lbr/com/ehmob/lab001/databinding/ActivityLoginBinding;->getRoot()Landroidx/constraintlayout/widget/ConstraintLayout;

    move-result-object v0

    const/4 v1, 0x0

    const-string v2, "Usuario ou senha inv\u00e1lidos"

    invoke-static {v0, v2, v1}, Lcom/google/android/material/snackbar/Snackbar;->make(Landroid/view/View;Ljava/lang/CharSequence;I)Lcom/google/android/material/snackbar/Snackbar;

    move-result-object v0

    invoke-virtual {v0}, Lcom/google/android/material/snackbar/Snackbar;->show()V

    :goto_0
    return-void
.end method
````

## Lab 3

> Objetivo do LAB parte 3: 
> - Inserir um código no onCreate da Activity RegistroActivity 
> Código pra inserir: 
> Log.e(“ehmob”, “Registro criado com sucesso!”)

Patch the RegistroActivity.smali adding the following lines
(see patched comment)
````smali
.method public onCreate(Landroid/os/Bundle;)V
    .locals 2

    .line 26
    invoke-super {p0, p1}, Landroidx/appcompat/app/AppCompatActivity;->onCreate(Landroid/os/Bundle;)V

    .line 27
    invoke-virtual {p0}, Lbr/com/ehmob/lab001/RegistroActivity;->getLayoutInflater()Landroid/view/LayoutInflater;

    move-result-object p1

    invoke-static {p1}, Lbr/com/ehmob/lab001/databinding/ActivityRegistroBinding;->inflate(Landroid/view/LayoutInflater;)Lbr/com/ehmob/lab001/databinding/ActivityRegistroBinding;

    move-result-object p1

    iput-object p1, p0, Lbr/com/ehmob/lab001/RegistroActivity;->binding:Lbr/com/ehmob/lab001/databinding/ActivityRegistroBinding;

    .line 28
    invoke-virtual {p1}, Lbr/com/ehmob/lab001/databinding/ActivityRegistroBinding;->getRoot()Landroidx/constraintlayout/widget/ConstraintLayout;

    move-result-object p1

    invoke-virtual {p0, p1}, Lbr/com/ehmob/lab001/RegistroActivity;->setContentView(Landroid/view/View;)V

    .line 29
    iget-object p1, p0, Lbr/com/ehmob/lab001/RegistroActivity;->binding:Lbr/com/ehmob/lab001/databinding/ActivityRegistroBinding;

    iget-object p1, p1, Lbr/com/ehmob/lab001/databinding/ActivityRegistroBinding;->txvTimer:Landroid/widget/TextView;

    iget-object v0, p0, Lbr/com/ehmob/lab001/RegistroActivity;->sdfWatchTime:Ljava/text/SimpleDateFormat;

    new-instance v1, Ljava/util/Date;

    invoke-direct {v1}, Ljava/util/Date;-><init>()V

    invoke-virtual {v0, v1}, Ljava/text/SimpleDateFormat;->format(Ljava/util/Date;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 30
    iget-object p1, p0, Lbr/com/ehmob/lab001/RegistroActivity;->binding:Lbr/com/ehmob/lab001/databinding/ActivityRegistroBinding;

    iget-object p1, p1, Lbr/com/ehmob/lab001/databinding/ActivityRegistroBinding;->button:Landroid/widget/Button;

    new-instance v0, Lbr/com/ehmob/lab001/RegistroActivity$$ExternalSyntheticLambda0;

    invoke-direct {v0, p0}, Lbr/com/ehmob/lab001/RegistroActivity$$ExternalSyntheticLambda0;-><init>(Lbr/com/ehmob/lab001/RegistroActivity;)V

    invoke-virtual {p1, v0}, Landroid/widget/Button;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    # patch
    .line 31
    const-string v0, "ehmob"

    const-string v1, "Registro criado com sucesso!"

    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    # patch

    return-void
.end method
````

````
$ adb logcat -C ehmob:E *:S
--------- beginning of system
--------- beginning of main
--------- beginning of kernel
05-29 21:48:57.029 12439 12439 E ehmob   : Registro criado com sucesso!
````

