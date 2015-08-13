# 使い方

証明書ファイルを %AppDir%/defaults/ 以下（Windowsであれば「C:\Program Files (x86)\Mozilla Firefox\defaults」など）に置いて下さい。
Firefoxを再起動すると、証明書が自動的にインポートされます。

このアドオンは法人利用を前提に開発されています。

## 対応している証明書ファイルの種類

DER X509形式から変換されたPEM形式のファイルにのみ対応しています。
（Internet ExplorerからFirefoxに既存の証明書を移行する場合であれば、「Base 64 encoded X.509」形式でエクスポートすればこの形式になります。）
ファイルの拡張子は「.crt」「.cer」「.pem」のいずれかである必要があります。
サンプルの証明書はリポジトリの「doc/*.pem」を参照して下さい。

証明書の種類は自動判別されますが、設定で上書きする事もできます。
サンプルの設定はリポジトリの「doc/sample.js」を参照して下さい。

## セキュリティ例外

セキュリティ例外の設定ファイルを「（証明書ファイルの名前）.override」という名前で証明書ファイルと同じ位置に置いておくと、ファイル内で定義されているセキュリティ例外を自動的に適用します。
サンプルの設定はリポジトリの「doc/newcert.pem.override」を参照して下さい。

## 試してみる

 1. 環境を整える。
    1. 古いバージョンのcertimporterを削除する。
    2. about:configを開く。
    3. "extensions.certimporter.certs.*.lastOverrideDate" で見つかる全ての項目をリセットする。
    4. "extensions.certimporter.debug" を "true" に設定する。
    5. 証明書マネージャを開く。
    6. 「認証局証明書」タブを選択する。
    7. 以下の2つの証明書が登録されていたら、削除する。
       * "!example" > "site.example.com"
       * "!example" > "example.com"
    8. 「サーバ証明書」タブを選択する。
    9. 以下の3つの例外が登録されていたら、削除する。
    10. Firefoxを再起動する。
    11. 証明書マネージャを開く。
    12. 「認証局証明書」タブ配下に以下のような項目がないことを確認する。
        * "!example"
    13. 「サーバ証明書」タブ配下に以下のような項目がないことを確認する。
        * "(Unknown)" > "(NotStored)" > "(something).example.com:443"
 2. certimporterをインストールする。
 3. 以下の3つのファイルを、Firefoxのインストールディレクトリ内の「defaults」以下に置く。
    * doc/cacert.pem
    * doc/newcert.pem
    * doc/newcert.pem.override
 4. Firefoxを再起動する。
 5. 証明書マネージャを開く。
 6. 以下の項目が認証局証明書として登録されていることを確認する。
    * "!example" > "site.example.com"
    * "!example" > "example.com"
 7. 以下の項目がサーバ証明書の例外として登録されていることを確認する。
    * "(Unknown)" > "(NotStored)" > "site.example.com:443"
    * "(Unknown)" > "(NotStored)" > "foo.example.com:443"
    * "(Unknown)" > "(NotStored)" > "bar.example.com:443"

