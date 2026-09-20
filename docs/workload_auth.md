# ワークロード認証と環境別の実行契約

## 適用範囲と責務

本仕様はService Gatewayに到達するサービス間RPC、Gatewayから後段への転送、ObservationからFlow Control／Line Controlへの直接RPCに適用する。
外部クライアントのIdP認証・DPoP、AuthのHTTP API、Edge BridgeのFirestore認証、PubSubのブローカー認証は別の契約とする。
ワークロード認証は呼び出し元の識別、内部JWTは処理文脈と宛先束縛、辺ポリシーはRPCの呼び出し可否を担う。
内部JWTの所持だけで呼び出し元ワークロードとして認証しない。

ComposeはSPIREのX.509-SVIDを使うアプリ間mTLS、Cloud Run servicesはGoogle署名のサービスアカウントIDトークンを使う。
認証後の論理サービスID、RPC認可、内部JWTの発行・検証は共通化し、資格情報の取得・検証とHTTP transportは方式別に実装する。
業務RPCの通信サイドカーは前提にせず、アプリ自身が認証と転送を実装する。

## 環境変数によるフィーチャーフラグ

| 環境変数 | 値 | 契約 |
|---|---|---|
| `TOLO_WORKLOAD_AUTH_MODE` | `spire` または `cloud_run` | 適用対象プロセスで必須。受信認証と送信資格情報・transportを一体で選択する |
| `TOLO_ENVIRONMENT` | 環境の識別子 | 必須。principal対応表・信頼情報・宛先設定の環境と一致させる |
| `TOLO_GATEWAY_LISTENER_MODE` | `split` または `shared` | Gatewayで必須。初期はspire/splitまたはcloud_run/sharedのみ対応 |
| `TOLO_GATEWAY_PUBLIC_PORT` | 1〜65535の整数 | Gatewayのsplitで必須。外部受信・匿名JWKS用 |
| `TOLO_GATEWAY_WORKLOAD_PORT` | 1〜65535の整数 | Gatewayのsplitで必須。PUBLIC_PORTと異なる番号でmTLS必須受信 |
| `PORT` | 1〜65535の整数 | GatewayのsharedではCloud Runが与える値を唯一の待受ポートとする |

Gatewayのsplitは2つの異なる待受を起動し、いずれかのbind失敗で正常起動としない。sharedは1つのHTTPサーバーだけを起動し、split用の2変数が指定されていれば拒否する。
ポートの一致からmodeを推測しない。旧 `TOLO_GATEWAY_ROLE` は廃止し、Gatewayで指定されていれば設定エラーとする。Gateway固有のlistener変数を通常バックエンドの必須項目にはしない。

フラグは起動時に一度読み込み、プロセスの稼働中に変更しない。
値は大文字小文字を含め表記どおりとし、未設定、空文字、未知の値では起動に失敗する。
認証無効モード、環境の自動推測、接続・認証失敗による別方式へのフォールバックを設けない。
方式変更は設定変更と再配備で行い、同じ受信口で両方式を同時受理しない。
同一イメージに両アダプターを含め、選択した方式の設定だけを有効にする。

起動時に、選択した方式の設定、環境、論理サービスID、許可principal、宛先と期待identityの対応を検証する。
設定に矛盾があれば起動しない。
初回資格情報・必要な信頼情報をまだ取得できない間はreadinessを成功させない。
一時的な取得失敗の再試行でも、未認証の業務要求は通さない。
フラグ・論理ID・listener方式は監査可能な起動情報として記録し、資格情報と秘密鍵は記録しない。

フラグはワークロード認証だけを切り替え、外部DPoP、内部JWT署名、辺ポリシー、業務認可を無効化・変更しない。
Compose／Cloud Run間でRPCを越境させる相互運用はこのフラグでは実現しない。
移行は原則として呼び出しが環境内に閉じる単位で行い、越境通信は別の信頼・運搬契約を確定してから有効にする。

## 検証済みidentityの共通契約

アプリ内の認証部品だけが次の情報を持つ検証済みidentityを生成し、HTTP request context等を介して認可処理へ渡す。
この情報を送信者の自己申告ヘッダや本文から直接生成してはならない。

| 情報 | 内容 |
|---|---|
| `service_id` | `tolo-observation` 等の論理サービスID。内部JWTのaud・sub等と同じ名前体系 |
| `environment` | 検証した環境 |
| `credential_kind` | `spiffe_x509` または `google_id_token` |
| `verified_principal` | SPIFFE ID、またはGoogle issuerとSA unique IDの組 |
| `credential_expires_at` | 検証した資格情報の有効期限 |

各環境の完全なprincipalと論理サービスIDの対応を宣言的に管理する。
部分一致、名前の末尾一致、任意のGoogle主体、任意のSPIFFE trust domainを許可しない。
未登録のprincipalは拒否する。
開発・本番の資格情報と信頼情報は分離する。
Gatewayは環境内で1つのアプリ配備単位とし、そのSPIFFE IDまたはSAを論理Service Gatewayへ対応づける。開発・本番のprincipalは分離する。後段で許すGateway principalは明示し、旧principalの移行期間も無期限に許可しない。

## SPIREモード

SPIRE Serverを資格情報発行・登録管理の基盤とし、ホスト単位のSPIRE Agentから各アプリへWorkload APIでX.509-SVIDとtrust bundleを供給する。
Agentは業務RPCを中継しない。
アプリSDKが更新を購読し、TLS client／serverへ反映する。
SPIREの管理・署名基盤、ホスト管理者、AgentのDocker APIアクセスは信頼境界に含む。
アプリへDocker管理socket、SPIRE管理API、他サービスを登録する権限を渡さない。
node登録、Docker属性からworkloadへの対応、初回trust配布は管理者が制御し、アプリが任意のSPIFFE IDを自己申告して発行を受ける方式を採らない。

SPIRE Agentの初回node登録は管理者が発行する短時間有効・1回限りのjoin tokenとする。
初期のjoin token有効期間は10分とし、対象ホストへ管理された経路で渡す。イメージ・リポジトリ・通常ログへ格納せず、登録後は残存する投入用コピーを除去する。
Agentの鍵・SVID・登録に必要な状態をアクセス制限したホスト専用領域へ永続化し、別ホストへ複製して同じnode identityを使わない。
通常更新は自動化し、資格情報の期限切れ・失効・永続状態の消失で再登録が必要な場合は管理者が新しいjoin tokenで行う。参加トークンを自動再発行する権限をアプリへ渡さない。
初回のServer trust bundleは管理された別経路で配布し、Serverの真正性を検証する。検証省略による初回接続を認めない。

受信では証明書チェーン・有効期間・X.509-SVIDプロファイル・期待trust domainを検証し、検証済みSPIFFE IDを呼び出し元へ対応づける。
送信でも宛先に対応する完全なSPIFFE IDを検証し、同じCAの証明書というだけで接続先を許可しない。
HTTPヘッダで渡された証明書やSPIFFE IDは認証根拠としない。
TLS層の鍵所持証明を使い、Google token用の `workload-authorization` と `X-Serverless-Authorization` は送信しない。
適用対象の内部受信口にこれらのヘッダがあれば方式混在として拒否する。

小規模本番の基準はLinux上のDocker Composeとする。
開発用Docker Desktop／Linux VM、rootless構成等も、プロセス識別・socket配置・選択したattestorが成立することを確認して使う。
永続化、復旧、初回node登録、SVIDとbundleの更新を運用対象とする。
アプリ向けX.509-SVIDの有効期間は初期設定で1時間とし、SPIRE／SDKで期限前に自動更新する。
これは証明書の最大有効期間であり、発行基盤停止後に必ず1時間継続できる保証ではない。実際の残存期限に従う。
SVIDの期限とは独立して、許可撤回を新規RPCの認可へ反映する。

SVIDの更新・取得失敗時に固定証明書や認証省略へ切り替えない。

## Cloud Runモード

各サービスに専用の実行SAを割り当て、Googleのメタデータサーバまたは対応ライブラリから宛先用Google署名IDトークンを取得する。
SA秘密鍵ファイルをイメージ・環境変数・配布用secretへ格納して発行する方式を採らない。
OAuth access token、IdPの外部トークン、内部JWTをGoogleワークロードIDトークンとして受理しない。

Google tokenの署名、許可したアルゴリズム、`iss=https://accounts.google.com`、宛先aud、`iat`・`exp`と必要な時刻条件、SAのunique IDである`sub`を検証する。
Google公開鍵をキャッシュし、未検証のキーや未知のissuerへ自動的に信頼を拡張しない。
署名が正しくても未登録SAは拒否する。
SAのメールアドレスだけでprincipalを決めず、issuerとunique IDの完全な組を対応表で引く。
Google tokenの期限はGoogleが発行した値に従う。通常1時間であり、内部JWTの120秒とは別に扱う。
宛先別に期限内のtokenを再利用し、期限前に取得を更新する。

Google tokenのaudは宛先Cloud RunサービスURLを基本とし、内部JWTの論理audとは別の設定にする。
IAM必須の宛先でcustom audienceを使う場合はCloud Runとアプリの双方で受理値を明示する。
IAMを無効にしたGatewayの受理audはアプリの固定設定で検証し、Cloud Runのcustom audience設定だけに依存しない。開発・本番間で共有しない。
公開LB URLへの接続でもaudを暗黙に変えず、接続URLと期待audをそれぞれ設定する。
宛先URLとaudの組は認可済みのルーティング設定から選び、任意URL向けに資格情報を発行・転送しない。

| ヘッダ | 用途 |
|---|---|
| `Authorization` | 文脈内部JWT、またはGatewayから宛先への内部JWT。明示的な省略経路は下記に従う |
| `X-Serverless-Authorization` | Cloud Run IAMが検査する宛先用Google token |
| `workload-authorization` | アプリが独立に検証する完全な署名付きGoogle token |

IAM必須の宛先では、送信者は同じ宛先用Google tokenを後者2ヘッダへ `Bearer <token>` として設定する。
IAMを無効にしたGatewayへの業務RPCではworkload-authorizationを必須とし、X-Serverless-Authorizationは送信しなくてよい。匿名JWKS取得にこれらの資格情報は不要である。
基盤側のヘッダは署名が除去され得るため、アプリでは `workload-authorization` の完全な署名を検証する。
基盤側ヘッダをデコードした未検証claimをアプリidentityの根拠にしない。
内部JWTを保持するHTTP clientへGoogleのAuthorization自動付与を重ねず、token取得とヘッダ設定を分離する。
重複した認証ヘッダ・複数のBearer値・不正な形式を拒否し、署名を検証できない値を別方式で再解釈しない。
リダイレクトによる別宛先への資格情報転送を許さない。

Cloud RunでTLSを終端し、アプリはHTTPを受ける。HTTP/2経路のコンテナ受信はh2cとする。
TLS peer証明書をCloud Runアプリで取得できることを前提にしない。
通常のGoogle SA IDトークンはBearer資格情報として扱い、mTLSと同じ送信者拘束があるとは扱わない。
トークン単体の個別失効に依存せず、アプリのprincipal許可表と、IAMを有効にする宛先ではIAMで受理を制御する。
GatewayはInvoker IAMチェックを無効化するが、サービスAとして扱う業務RPCのGoogle token検証・辺認可を省略しない。

## 呼び出し経路ごとの検証

| 経路 | transportで認証する主体 | Authorizationの扱い |
|---|---|---|
| サービスA→Gatewayのサービス間RPC | サービスA | A宛の文脈内部JWT。新規マシン起点だけ省略可 |
| Gateway→通常バックエンドB | 許可されたGateway principal | Gatewayが発行するB宛内部JWT。明示された匿名経路だけ省略 |
| Observation→Flow／Line | Observationのみ | 内部JWTを要求しない。直接呼び出し契約で処理する |

Gatewayはサービス間RPCのワークロード認証後、Aと文脈JWTのaudを照合し、辺ポリシーに従ってB宛内部JWTを再発行する。
期限切れ・不正な文脈JWTを、文脈なしの新規マシン起点へ読み替えない。
バックエンドBのtransport identityはGatewayであり、内部JWTのsubはAになり得るため、両者の同一性を一律に要求しない。
backendではGatewayのprincipalを認証し、別に内部JWTの署名・issuer・B宛aud・期限・RPC認可を検証する。

匿名のStartTenantRegistrationとGuestの公開HTTPでも、匿名なのは外部クライアントである。
Gatewayから後段への転送にはワークロード認証を必須とし、Authorizationの内部JWTだけを省略する。
Gatewayで未検証の資格情報・identityヘッダを信用しない。shared受信口のworkload-authorizationはGoogle署名と許可主体を検証するためにだけ使用し、そのまま後段へ引き継がない。
各ホップで現在の送信者の資格情報を新たに設定する。

## 認証・認可の実装位置

アプリ内で、TLS／HTTP認証、検証済みidentity、RPC認可、JWT処理、転送transportを分離する。
Composeの認証はTLSとHTTP middleware、Cloud Runの認証はHTTP middlewareで、本文の展開・デコード前に行う。
ConnectのInterceptorは認可・監査等の共有部品と接続し、認証を本文デコード後のInterceptorだけへ置かない。
Gatewayは再利用するサービスprotoと必要な独自protoの生成ハンドラー／クライアントで型付き委譲する。認証はHTTP層で共通化し、受信側・後段送信側・バックエンド側で認証設定を分離する。
shared入口では完全修飾RPCと資格情報の受理規則を明示し、無効・重複・混在した資格情報を別認証や匿名へ読み替えない。詳細はGateway仕様に従う。
公開JWKSは認証不要の独立した経路とし、業務RPCの認証middlewareを一律適用しない。認証不要の経路があることをワークロード認証の無効モードとは扱わない。

## 検証・運用の条件

資格情報・文脈・RPC許可は新規RPCの開始時に確認し、HTTP/2接続の再利用だけで以前の認可を使い続けない。
SVID・bundle更新、接続再開、既存TLS接続上の新規RPCにも期限・現在の許可が適用されるようにする。
初回の認証に必要な情報がない場合、または資格情報の期限が切れた場合は拒否する。
取得先が停止しても、有効な資格情報と許可された信頼情報が揃う範囲だけで処理する。
鍵が未知の要求を未検証のまま受理しない。

許可撤回が受信側へ反映された後は、既存接続上の要求も含め新規RPCを拒否する。
すでに開始したRPCは許可撤回を理由に打ち切らず、既定のタイムアウト・deadline・クライアントキャンセルに従って完了させる。
通常の資格情報の期限切れも新規RPCの開始条件として判定し、開始済みRPCをその期限だけで打ち切らない。
許可撤回の完了は対象の全受信配備への反映を確認して判定し、SPIREの発行停止やSA設定変更だけで完了したとは扱わない。

両方式で、別サービス・別環境・別宛先・期限切れ・偽造資格情報・文脈aud不一致・未許可RPCを拒否する。
Cloud RunではIAM、独自ヘッダの保持、完全なGoogle署名の検証、内部JWTとの共存、h2c、ingressを実環境で確認する。
Composeでは採用するDocker環境のattestation、取得更新、再登録、接続寿命と障害復旧を確認する。
認証依存先の不達で許可条件を緩めない。

## 関連仕様

- service_gateway_spec.md
- internal_jwt.md
- service_map.md
- Flow Control
- Line Control
