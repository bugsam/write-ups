# APKey

## 1. Verify the file smali\com\example\apkey\MainActivity$a.smali

````smali
    const-string v0, "admin"
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result p1
    const/4 v0, 0x0
    if-eqz p1, :cond_1
````

2. Add a jump before any check to the place where the FLAG will pump

````
    const-string v0, "admin"
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result p1
    const/4 v0, 0x0
    goto :goto_4
    if-eqz p1, :cond_1
....
   :goto_1
    const-string v1, "a2a3d412e92d896134d9c9126d756f"
    .line 2
    invoke-virtual {p1, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result p1
    if-eqz p1, :cond_1
    :goto_4
    iget-object p1, p0, Lcom/example/apkey/MainActivity$a;->b:Lcom/example/apkey/MainActivity;

````
3. Build and sign

````
$ apktool build base -o base4.apk
$ objection signapk base4.apk
````

4. Wherever word you insert in login and password would now just shows the FLAG

## Secrets
FLAG: HTB{m0r3_0bfusc4t1on_w0uld_n0t_hurt}
