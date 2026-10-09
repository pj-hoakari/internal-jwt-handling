# サービス間経路の到達制御と環境別の実行契約

## 適用範囲と責務

本仕様はService Gatewayに到達するサービス間RPC、Gatewayから後段への転送、ObservationからFlow Control／Line Controlへの直接RPCに適用する。
外部クライアントのIdP認証・DPoP、AuthのHTTP API、Edge Bridge ServiceのFirestore認証、PubSubのブローカー認証は別の契約とする。

アプリはワークロード資格情報の取得・検証を行わない。
サービス間RPCを受けてよい呼び出し元の制限はプラットフォームが担い、Cloud Runではingressと専用SAへのInvoker IAM、Composeではコンテナネットワークの分離とホストへのポート非公開で行う。
呼び出し元サービスの識別は、文脈内部JWTの `aud`、または新規マシン起点の申告ヘッダで行う（後述）。内部JWTは処理文脈と宛先束縛、辺ポリシーはRPCの呼び出し可否を担う。

内部経路へ到達できる環境内のワークロードは、他のサービスを名乗ることができる。
この場合も、他サービス宛の文脈内部JWTは宛先束縛で、許可されていない呼び出しは辺ポリシーで拒否される。
到達制御の構成は信頼境界に含めて管理し、配備ごとに検査する。

## 到達制御

| 受信口 | 到達を許す呼び出し元 | Cloud Run | Compose |
|---|---|---|---|
| Gateway公開用 | 外部クライアント | Invoker IAM無効。外部Application Load BalancerとCloud Armorを入口とする | 公開用listenerだけをホストへ公開する |
| Gateway内部用 | サービスA（Gatewayを呼ぶ全サービス） | ingressを内部に限り、各サービスの実行SAにだけInvokerを付与する | 内部用listenerをホストへ公開せず、サービス用ネットワークにだけ接続する |
| 通常バックエンド | Gateway | ingressを内部に限り、Gateway公開用・内部用の実行SAにだけInvokerを付与する | Gatewayと同じネットワークにだけ接続し、ホストへ公開しない |
| Flow Control／Line Control | Observation | ingressを内部に限り、Observationの実行SAにだけInvokerを付与する | Observationとだけ共有するネットワークに接続し、ホストへ公開しない |

各サービスに専用の実行SAを割り当て、SA秘密鍵ファイルをイメージ・環境変数・配布用secretへ格納しない。
Cloud RunでIAMを有効にした宛先へ送る呼び出し元は、メタデータサーバまたは対応ライブラリから宛先用Google IDトークンを取得し、`X-Serverless-Authorization: Bearer <token>` で送る。
`Authorization` は内部JWT用に残し、Google IDトークンを入れない。アプリは `X-Serverless-Authorization` を検証せず、その内容を呼び出し元の識別に使わない。
Composeでは `X-Serverless-Authorization` を送らない。
開発・本番の実行SAとネットワークは分離する。

## 環境変数

| 環境変数 | 値 | 契約 |
|---|---|---|
| `TOLO_GATEWAY_LISTENER_MODE` | `split`、`public`、`internal` | Gatewayで必須。`split` はComposeで公開用と内部用の2listener、`public` と `internal` はCloud Runの各配備で1listenerを起動する |
| `TOLO_GATEWAY_PUBLIC_PORT` | 1〜65535の整数 | `split` で必須。公開用 |
| `TOLO_GATEWAY_INTERNAL_PORT` | 1〜65535の整数 | `split` で必須。PUBLIC_PORTと異なる番号で内部用 |
| `PORT` | 1〜65535の整数 | `public` と `internal` ではCloud Runが与える値を唯一の待受ポートとする |

`split` は2つの異なる待受を起動し、いずれかのbind失敗で正常起動としない。`public` と `internal` は1つのHTTPサーバーだけを起動し、split用の2変数が指定されていれば拒否する。
値は大文字小文字を含め表記どおりとし、未設定、空文字、未知の値では起動に失敗する。ポートの一致からmodeを推測しない。
旧 `TOLO_WORKLOAD_AUTH_MODE`、`TOLO_GATEWAY_ROLE`、`TOLO_GATEWAY_WORKLOAD_PORT` は廃止し、指定されていれば設定エラーとする。
Gateway固有のlistener変数を通常バックエンドの必須項目にはしない。

## 呼び出し元サービスの識別

Gatewayの内部用受信口は、次の規則で呼び出し元の論理サービスID（`tolo-observation` 等。内部JWTのaud・sub等と同じ名前体系）を決める。

| 要求 | 呼び出し元 |
|---|---|
| 文脈内部JWTあり | 検証に成功した文脈内部JWTの `aud` |
| 文脈内部JWTなし（新規マシン起点） | `tolo-caller-service` ヘッダで申告された論理サービスID |

文脈内部JWTと `tolo-caller-service` の両方がある要求、どちらもない要求、値が空・重複・未登録の論理サービスIDである要求は拒否する。
無効な文脈内部JWTを、申告ヘッダによる新規マシン起点へ読み替えない。
公開用受信口とバックエンドは `tolo-caller-service` を受け付けず、ヘッダがあれば拒否する。
Gatewayは受信した `tolo-caller-service` を後段へ引き継がない。

## 呼び出し経路ごとの検証

| 経路 | 呼び出し元の識別 | Authorizationの扱い |
|---|---|---|
| サービスA→Gateway内部用 | 文脈内部JWTの `aud`、または申告ヘッダ | A宛の文脈内部JWT。新規マシン起点だけ省略し、申告ヘッダを付ける |
| Gateway→通常バックエンドB | 到達制御によりGatewayに限られる | Gatewayが発行するB宛内部JWT。明示された匿名経路だけ省略 |
| Observation→Flow／Line | 到達制御によりObservationに限られる | 内部JWTを要求しない。直接呼び出し契約で処理する |

Gatewayは内部用受信口で呼び出し元を決めた後、辺ポリシーに従ってB宛内部JWTを再発行する。
期限切れ・不正な文脈JWTを、文脈なしの新規マシン起点へ読み替えない。
バックエンドBは内部JWTの署名・issuer・B宛aud・期限・RPC認可を検証する。内部JWTのsubはAになり得る。

匿名のStartTenantRegistrationとGuestの公開HTTPでも、Gatewayから後段への転送は到達制御を通る経路で行い、Authorizationの内部JWTだけを省略する。
各ホップでは、その時点の送信者が宛先に応じた内部JWTを新たに設定し、Cloud Runでは宛先用Google IDトークンも新たに設定する。受信した資格情報を後段へ転送しない。

## 実装位置

アプリ内で、HTTP受信、呼び出し元の識別、RPC認可、JWT処理、転送transportを分離する。
内部JWTの検証と呼び出し元の識別は、本文の展開・デコード前にHTTP middlewareで行う。
ConnectのInterceptorは認可・監査等の共有部品と接続し、認証を本文デコード後のInterceptorだけへ置かない。
業務RPCの通信サイドカーは前提にしない。

## 検証・運用の条件

起動時に、listener方式、論理サービスID、宛先URLの設定を検証し、矛盾があれば起動しない。
listener方式と論理サービスIDは監査可能な起動情報として記録し、トークン本体は記録しない。
Cloud Runでは、Gateway公開用・内部用と各サービスのingress、Invoker IAM、`X-Serverless-Authorization` と内部JWTの共存、h2cを実環境で確認する。
Composeでは、内部用listenerと各サービスのポートがホストへ公開されていないこと、ネットワークの分離どおりにしか到達できないことを確認する。
ComposeとCloud Run間でRPCを越境させる相互運用は対象外とする。移行は原則として呼び出しが環境内に閉じる単位で行う。

## 関連仕様

- service_gateway_spec.md
- internal_jwt.md
- service_map.md
- Flow Control
- Line Control
