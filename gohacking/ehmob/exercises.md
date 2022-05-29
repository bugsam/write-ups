# Exercises

## Lab 1
>  Objetivo do LAB: 
> - Alterar o AndroidManifest.xml para abrir a activity 
> RegistroActivity ao invés da Tela de login.

````
apktool decode lab001.apk
````

Change LoginActivity to RegistroActivity and RegistroActivity to LoginActivity

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

<img width="320" alt="Screen Shot 2022-05-29 at 20 50 25" src="https://user-images.githubusercontent.com/44240720/170896297-ac7bf14f-ce31-4166-bfdb-bbb98803163d.png">


## Lab 2


