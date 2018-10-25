mod_dosdetector_syslog
===============
このリポジトリはShinji Tanaka氏が制作されたApacheモジュール「mod_dosdetector」をforkさせて頂き、
個人的な好みでいくつかの機能を加えた私家版になります。ご需要に適いましたら、よろしければご利用くださいませ。
またこちらのリポジトリに関してのご質問は<gure@kasugasoft.daiwadaw.jp>まで
ご連絡頂けますと幸いです。

mod_dosdetectorについての簡易説明
-----------------------
単一ホストからの不自然な連続したリクエストを認識し、その数に応じてSuspectDoS、またはSuspectHardDoSという  
環境変数を設定するモジュールです。
この環境変数とmod_rewriteを連携することで、アクセス制限等を可能とします。

インストール方法
-------
```
make install
```
とコマンドを打つことで「mod_dosdetector_syslog」という名前でインストールされ、またhttpd.conf内に以下の行が追加されます。

```
LoadModule dosdetector_syslog_module libexec/apache24/mod_dosdetector_syslog.so
```

動作環境
-------
Apache2.2以上  
FreeBSD10.4R Apache2.4(event MPM) 上にて動作確認を行っています。

mod_dosdetector_syslogで追加されたディレクティブ
==================================

DoSForwardedCount
--------------------
```
DoSForwardedCount
<Context> server config, virtual host
```

X-Forwarded-Forヘッダに記録されるIPアドレスの何番目をリモートIPと認識するか
いわゆるホップ数を指定する形となります。
例えば

```
X-Forwarded-For 198.51.100.11, 198.51.100.12, 198.51.100.13
```

という状態でDoSForwardedCountに「0」を設定されますと、198.51.100.13をリモートIPと認識します。  
「1」を設定されると198.51.100.12、「2」または「-1」（初期値）を設定されると一番左の198.51.100.11になります。
この時指定されたIPアドレスがIPv4またはIPv6アドレスとして有効な文字列でなかった時は
接続IPアドレスをリモートIPアドレスとして認識します。

DoSForwardedHeader
--------------------
```
DoSForwardedHeader
<Context> server config, virtual host
```

標準では「X-Forwarded-For」を走査対象としますが、これを任意のヘッダ文字列に変更する
ことが可能となります。

```
DoSForwardedHeader X-Real-IP
```

と設定されると、X-Forwarded-Forの代わりにX-Real-IPというヘッダを参照するようになります。
こちらは複数設定することが可能です。
この設定を記述した場合、X-Forwarded-Forは見なくなりますので

```
DoSForwardedHeader X-Real-IP X-Forwarded-For
```

と続けて設定されることで、両方のヘッダを走査することが出来ます。
複数のヘッダを設定されている時は、記述した順番に探して（この場合はX-Real-IPを最初に見ます）
最初に見つかったヘッダの内容から判断する形となります。

> 【注釈】Apache2.4以降であればmod_remoteipという標準モジュールを活用されると、DoSForwarded系の設定をされるより
正確な認識が出来ると思います。mod_remoteipはヘッダ内のIPアドレスをリモートIPアドレスに上書きするため、
DoSForwarded系の設定は不要となります。

DoSSLogSelector
--------------------
```
DoSSLogSelector
<Context> server config, virtual host
```

SuspectDoSを検知した時に記録文字列を投げる、syslogのセレクタを指定します。
例えば

```
DoSSLogSelector "security.info"
```

とされるとSuspectDoSを検知した時にsecurity.infoに「一度だけ」以下のようなログ文字列を投げます。

```
Jun  9 08:07:14 My-HOST httpd[7661]: dosdetector: suspected as DoS attack! [ホストドメイン] from IPアドレス
```

DoSHLogSelector
--------------------
```
DoSHLogSelector
<Context> server config, virtual host
```

SuspectHardDoSを検知した時に記録文字列を投げる、syslogのセレクタを指定します。
例えば

```
DoSHLogSelector "security.warning"
```

SuspectHardDoSを検知した時はsecurity.warningに検知した瞬間から「DoSBanThreshold毎に」以下のようなログを投げます。

```
Jun  9 08:07:14 My-HOST httpd[7661]: dosdetector: suspected as Hard DoS attack! [ホストドメイン] from IPアドレス
```



DoSAllowReconfig
--------------------
```
DoSAllowReconfig
<Context> server config, virtual host, directory
```

指定ディレクトリ以下に対して、再設定の可不可を設定します。
初期値は on です。
on と設定されているディレクトリ内は.htaccessによる再設定も可能です。
例えば

```
<Directory /usr/home/>
    <IfModule mod_dosdetector_syslog.c>
        DoSDetection on
        DoSPeriod 10
        DoSAllowReconfig off
    </IfModule>
</Directory>
```

と設定された上で/usr/home/以下で.htaccessにDoS～の設定を書いたり、/usr/home/*/に対して<Directory>を書いた場合は
InternalServerErrorを返します。
Apacheを再起動したくないけども設定を変更したい時などに、.htaccessをご活用くださいませ。



その他の変更点
================

環境変数を設定する処理とDoS判定をする処理を分けました
----------------------------------------------------
SetEnvIfで設定された環境変数をDoSDetectionで受け取り、そして設定したSuspectDoS、SuspectHardDoSを  
逆にSetEnvIfで受け取ることが出来るようにしました。  
> DoS攻撃と判定された次以降のアクセスに対して有効となります。

また既にDoS攻撃と判定されている状態で.htaccess内でDoSDetectionをoffに設定された場合、カウントアップは停止しますが環境変数の設定はDoSBanPeriod経過を待ち解除される形となります。

仮想ホスト毎のテーブル及びミューテックスを作成するようにしました
----------------------------------------------------
但し&lt;VirtualHost&gt;ディレクティブ内に最低1つの設定値（DoSDetection等）を記述された場合に限ります。  
これを記述されない時はメインサーバの設定値が継承され、テーブル及びミューテックスは共通となります。


IPv6アドレスに対応しました
----------------------------------------------------
IPアドレスは共通でchar文字列として格納されます。

カウンタの減算処理を無くしました
----------------------------------------------------
動作原理は以下のようになります。

```
DoSPeriod        10
DoSThreshold     20
DoSHardThreshold 30
DoSBanPeriod     40
```

最後のアクセスから10秒以内に20回のアクセスがあった時にSuspectDoS環境変数に"1"を設定します。  
その状態で40秒以内に追加で10回アクセスがあった時にSuspectHardDoS環境変数に"1"を設定します。  
以降40秒間完全に無アクセスの状態になった時に、カウンターは初めて0に戻ります。  
最後のアクセスから40秒以内に再度アクセスがあった時は、カウンターは加算され続けます。  
SuspectDoS及びSuspectHardDoSにはその間常に"1"が設定されています。  

> 元々の処理では10秒（DoSPeriod）毎にカウンターが20（DoSThreshold）減算されます。  
> つまりDoSBanPeriodで40と設定していますが、10秒でSuspectHardDoSは解除され（30-20<30）、  
> 20秒でカウンターは0に戻り（10-20=-10 -> 0）、SuspectDoSのみ残りの20秒間残る形となります。

この変更により、特定のCGIに対する断続的なアクセスもSuspectHardDoSとして認識可能となります。  
例えば

```
DoSPeriod        10
DoSThreshold     2
DoSHardThreshold 3000
DoSBanPeriod     40
```

とすると「10秒間に2回のアクセスを1500回繰り返す」とSuspectHardDoSとして認識されます。

> 元々の処理では10秒毎にカウンターが0に戻り、SuspectHardDoSの判定は永遠にされない形となります。

DoSDetectionで環境変数を取れるようにしました
----------------------------------------------------

```
SetEnvIf Remote_Addr "^192\.168\." nochk
DoSDetection !nochk
```

等と設定されますと、指定されたアクセスに対してDoSDetectionをoffに設定出来ます。

DoSBanPeriodは常に一番大きな値を採るようにしました
----------------------------------------------------
ディレクトリ毎にDoSBanPeriodを設定すると、例えばこれが100の場所でSuspectDoSと判定された時に  
10と設定された場所に移動すれば10秒で解除されてしまうという問題があるためです。  
これではDoSBanPeriodの設定値の意味が無くなってしまうことから、常に今までアクセスした中での  
最大値を採るようにしました。

304 Not Modified応答が見込まれるリクエストをカウントしないようにしました
----------------------------------------------------
If-None-Match※及びIf-Modified-Sinceフィールドを取得してダウンロード対象と比較した結果、
304 Not Modified応答が見込まれるリクエストに対してはカウント処理を行わないようにしました。

> ※FileETag で Size のみ、または MTime を含めて指定されたEtagに対応しています。

設定値の継承につきまして
----------------------------------------------------

メインサーバの設定値が仮想ホストに対して継承されるように、ディレクトリ単位でも継承が行われます。  
継承とは「未設定の項目を、親サーバまたは親ディレクトリの設定から丸ごとコピーする」という動作となります。  

> DoSIgnoreContentType、DoSForwardedHeader、DoSSLogSelector、DoSHLogSelectorの設定値として  
"none"を指定された時、継承された値を空にすることが出来ます。

DoSShmemName（共有メモリ名の設定）につきまして
----------------------------------------------------

このディレクティブは本来他のモジュールと連携する為に設置されたものと思いますが、  
mod_dosdetector及びmod_dosdetector_syslogは単独で動作するため、設定不要な形にしています。  
また設定された場合でも他のモジュールからは見えない状態になります。  
もしも連携のために利用される際は

```
apr_shm_remove(cfg->shmname, p); // Just to set destroy flag.
```

という行をコメントアウトされると利用出来るようになります。
共有メモリ名の形式は

メインサーバ　->　dosdetector:設定値（未設定の時はホストドメイン）  
仮想ホスト　　->　dosdetector:設定値（未設定の時は仮想ホストドメイン）:defn_name文字列のSHA-1署名  
> defn_nameの内容はコマンド「apachectl -t -D DUMP_VHOSTS」で確認が可能です。

となります。

動作パフォーマンスにつきまして
----------------------------------------------------

かなり手を入れてしまっているためApache Benchにて本家との動作速度の差を確認しようとしたのですが、特殊な環境ゆえか有意差を認められませんでした。  
もしご利用をご検討くださるようでしたら、事前にご確認頂けましたら幸いです。

mod_ratelimit
----------------------------------------------------

公式の通りにmod_rewriteと連携する方法の他、Apache2.4以降であればmod_ratelimitも活用出来ます。
http://httpd.apache.org/docs/2.4/mod/mod_ratelimit.html

```
LoadModule ratelimit_module libexec/apache24/mod_ratelimit.so
```
```
<If "env('SuspectDoS') == '1'">
   SetOutputFilter RATE_LIMIT
   SetEnv rate-limit 512
</If>
```

という形にされると、通信速度を512KiB/secに制限することも可能です。

---

Configuration
---------------

```
DoSDetection [on|off|[!]env-variable] default: off
<Description> Enables or disables runtime dosdetector engine
<Context> server config, virtual host, directory, .htaccess
<Override> FileInfo
For example: DoSDetection on       - enable
           : DoSDetection doschk   - if `doschk' env-variable is non-null, it means `on'
```


```
DoSThreshold [1-65535] default: 10000
<Description> Number of contens downloaded within DoSPeriod seconds for detecting DoS attack
<Context> server config, virtual host, directory, .htaccess
<Override> FileInfo
For example: DoSThreshold 20       - 20 contents downloaded within DoSPeriod
```

When exceeded this value, `SuspectDoS' env-variable is set to "1".

```
DoSHardThreshold [1-65535] default: 10000
<Description> Number of contens downloaded within DoSPeriod seconds for detecting Hard DoS attack
<Context> server config, virtual host, directory, .htaccess
<Override> FileInfo
For example: DoSHardThreshold 50   - 50 contents downloaded within DoSPeriod
```

When exceeded this value, `SuspectHardDoS' env-variable is set to "1".

```
DoSPeriod [1-65535] default: 10
<Description> Time frame for detecting DoS attack
<Context> server config, virtual host, directory, .htaccess
<Override> FileInfo
For example: DoSPeriod 10          - Monitor the download count within 10 seconds for each host
```


```
DoSBanPeriod [1-65535] default: 300
<Description> Inactive time to spend for not be set `SuspectDoS' or `SuspectHardDoS'
<Context> server config, virtual host, directory, .htaccess
<Override> FileInfo
For example: DoSBanPeriod 60       - Must not to access anything for 60 seconds since detected
```


```
DoSShmemName [string] default: "dosdetector:<hostname>[:hash-string-per-vhosts]"
<Description> This option has no effect, there is left behind for backward compatibility
<Context> server config, virtual host
For example: DoSShmemName dosshm   - Naming shared memory as `dosdetector:dosshm' for keep with suspected IPs
```


```
DoSTableSize [1-65535] default: 100
<Description> Table size for keep with suspected IPs
<Context> server config, virtual host
For example: DoSTableSize 300      - Create table with capable of store 300 IPs
```


```
DoSForwarded [on|off] default: off
<Description> Extract IP address from defined header using DoSForwardedHeader or `X-Forwarded-For'
<Context> server config, virtual host, directory, .htaccess
<Override> FileInfo
For example: DoSForwarded on       - enable
```


```
DoSForwardedCount [-1-65535] default: -1
<Description> Count number of hops in defined header using DoSForwardedHeader or `X-Forwarded-For'
<Context> server config, virtual host
For example: DoSForwardedCount 0   - In the case of `X-Forwarded-For: 198.51.100.11, 198.51.100.12, 198.51.100.13', choose a 198.51.100.13
             DoSForwardedCount -1  - In the case of `X-Forwarded-For: 198.51.100.11, 198.51.100.12, 198.51.100.13', choose a 198.51.100.11
```


```
DoSForwardedHeader [none|string...] default: none
<Description> Names of custom header to override forwarded-header
<Context> server config, virtual host
For example: DoSForwardedHeader X-Real-IP                        - Using `X-Real-IP' instead of `X-Forwarded-For'
             DoSForwardedHeader CF-Connecting-IP X-Forwarded-For - Using `CF-Connecting-IP', but use `X-Forwarded-For' when not find
```


```
DoSIgnoreContentType [none|regex...] default: none
<Description> Name of content-types for exclude from download counts
<Context> server config, virtual host, directory, .htaccess
<Override> FileInfo
For example: DoSIgnoreContentType ^(image/|text/) - Ignoring image/* and text/* content-types from download counts
```

```
DoSSLogSelector [none|string] default: none
<Description> Name of syslog's selector for reporting `SuspectDoS' is set
<Context> server config, virtual host
For example: DoSSLogSelector "security.info"      - Going to report to "security.info" only once
```

```
Jun  9 08:07:14 My-HOST httpd[7661]: dosdetector: suspected as DoS attack! [vhost1.example.com] from 198.51.100.10
```


```
DoSHLogSelector [none|string] default: none
<Description> Name of syslog's selector for reporting `SuspectHardDoS' is set
<Context> server config, virtual host
For example: DoSHLogSelector "security.crit"      - Going to report to "security.crit" every over DoSBanThreshold
```

```
Jun  9 08:07:14 My-HOST httpd[7661]: dosdetector: suspected as Hard DoS attack! [vhost2.example.com] from 198.51.100.21
```


```
DoSAllowReconfig [on|off] default: on
<Description> Permission of overrides all DoS* options in subdirectories
<Context> server config, virtual host, directory
For example: DoSAllowReconfig off                 - forbid to set option on .htaccess in cur-dir and sub-dirs, but if set to `off' in parent directory, then, forbid with cur-dir's <Directory> directive too
```


Usage:

```
# Return the error code `503 Service Temporarily Unavailable' when `SuspectHardDoS' was set (using mod_rewrite)
<IfModule mod_rewrite.c>
RewriteEngine on
RewriteCond %{ENV:SuspectHardDoS} =1
RewriteRule .*  - [R=503,L]
</IfModule>
```

License
---------------
This module is licensed under the MIT License.

