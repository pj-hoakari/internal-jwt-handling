# Service Gateway 入出力仕様

作成日: 2026-07-03
位置づけ: デプロイ単位。サービスprotoの再利用と必要な独自protoを併用するConnect-RPCサーバー兼クライアント（同期 RPC の原則経由点。例外は Auth、Edge Bridge Service、Observation → Flow／Line）
役割: 外部資格情報の検証と内部 JWT への変換（トークン変換点）、および宛先サービスへの転送

## 公開面と転送

- 同一契約のRPCは各サービスのprotoを再利用し、Gatewayの生成サーバーハンドラーから後段の生成Connectクライアントへ型付き委譲する。公開用の型・版管理が異なるRPCは独自protoと明示的な対応・変換を持つ
- 再利用RPCは入出力の意味を維持するが、再シリアライズ後のバイト一致は保証しない。業務処理と永続化は後段の責務とする
- 認証経路では`authorization`メタデータの外部トークンを検証し、内部JWTへ差し替えて宛先サービスを呼び出す
- 明示した未認証経路では内部JWTを発行せず、authorizationを省略する。ただしGatewayから宛先へのワークロード認証は必須とする
- ストリーミング RPC はストリーム開始時に検証する
- PubSub の publish／購読と Firestore 変更通知は経由しない（ブローカー仲介）
- マイクロサービスへ Service Gateway を迂回して到達できないことをインフラ層（ネットワーク構成）で保証する
  例外は2つある。Edge Bridge Service は完全に独立した位置に置き、本 Gateway の後ろに配置しない（Edge Bridge Service。認証・認可は Firestore のアクセス制御による）。Flow Control と Line Control は Observation からの直接呼び出しのみを受け、本 Gateway を経由しない（Flow Control、Line Control。到達制御はインフラ層とワークロード資格情報の直接検証で保証する）
  例外を認める基準は「Service Gateway がペイロードに関与せず、呼び出し元が単一のサービス間経路」に限る

## アプリ内実装と入口の配備

Gatewayは1つのアプリ配備単位とし、Composeでは1コンテナ、Cloud Runでは1サービスとして配備する。Cloud Runの最大インスタンス数を1に固定する意味ではない。
アプリ自身のTLS・HTTP middleware・RPC認可・内部JWT処理・生成Connectサーバー／クライアントで実装し、Envoy等の通信サイドカーを前提にしない。
認証が必要な業務RPCは本文デコード前に認証し、Connect Interceptor等へ検証済みidentityを渡す。
サーバー側をGateway受信側（外部向け）、クライアント側をバックエンド送信側（内部向け）と呼ぶ。サービスAもGateway受信側を呼ぶため、方向の名称と呼び出し元の認証を混同しない。

設定は workload_auth.md に従う。
Composeは `TOLO_WORKLOAD_AUTH_MODE=spire` と `TOLO_GATEWAY_LISTENER_MODE=split` で、外部用とSPIFFE mTLS必須のworkload用の2listenerを起動する。
外部用は外部IdP／DPoP・明示匿名RPC・Guest HTTP・公開JWKSを扱う。workload用はサービス間RPCを扱い、外部資格情報へのフォールバックは設けない。
同じServiceにサービス専用メソッドが含まれる場合も、外部用listenerではその実行を拒否する。
workloadポートはホストへ公開せず必要なコンテナネットワークから接続するが、非公開ポートを認証根拠にはしない。

Cloud Runは `TOLO_WORKLOAD_AUTH_MODE=cloud_run` と `TOLO_GATEWAY_LISTENER_MODE=shared` で、`0.0.0.0:$PORT` に1つのHTTPサーバーを起動する。必要なHTTP/2経路はh2cとする。
Invoker IAMチェックを無効化し、全経路を公開入口から到達可能にする。サービス専用RPCもパスが非公開という意味ではなく、アプリが認証済みサービスにだけ実行を許す。
Gatewayの実行SA・SPIFFE IDは環境内の論理Gatewayに対応づける。通常バックエンドはGatewayのprincipalだけを許可し、Cloud RunではInvoker IAMとアプリ検証を維持する。Observation→Flow／Line等の直接例外は別に設定する。
全Gatewayインスタンスが同じ内部JWT issuerと論理ID体系を用い、共通JWKSへ検証に必要な鍵集合を公開する。

Cloud Run本番は外部Application Load BalancerとCloud Armorを入口とし、インターネットから既定URL等へ直接到達してArmorを迂回できないようingress等を設定する。
外部利用者・サービスA・JWKS取得者は公開LB URLを基準とする。内部直通を追加する場合はArmor適用外の経路を別途定義し、同じアプリ認可を必須にする。
`internal-and-cloud-load-balancing` は内部ネットワーク経路も許すため、設定だけで全通信のArmor通過が保証されるとは扱わない。既定URL・別domain mapping・内部直通を含め到達経路を検査する。
宛先URLとGoogle audは別設定とし、LB導入だけでaudを暗黙に変更しない。DPoPは信頼した転送情報から確定する実際の公開URLで検証し、任意のHost／転送ヘッダを信頼しない。

## shared入口の業務RPC受理規則

最上位ルーターでRPC・Guest・JWKS・限定した監視を識別し、未知経路を拒否する。公開JWKSは以下の業務RPC認証処理から外す。
完全修飾RPCごとに受理する主体種別を宣言し、同じパスへ別認証用ハンドラーを重複登録しない。

| 入力 | 処理 |
|---|---|
| workload-authorizationあり | 完全なGoogle tokenを検証し、許可SAから論理サービスAを得る。その後にA宛の文脈内部JWTと許可辺を確認する |
| workload資格情報なし、外部資格情報あり | IdP token・必要なDPoPを検証し、client・scope・RPC公開区分を確認する。内部JWTやGoogle tokenをIdP tokenとして代用しない |
| 資格情報なし | 明示匿名RPCのみを受理する。サービス専用RPC・認証必須RPCを実行しない |

空・不正・重複・混在した認証情報は拒否し、失敗した方式から外部認証や匿名へフォールバックしない。
サービス間のAuthorizationは文脈内部JWT用であり、省略は当該サービスとRPCの辺が新規マシン起点を許す場合だけ認める。無効な文脈JWTを文脈なしとして再解釈しない。
サービスAとして処理する業務RPCのワークロード認証は維持する。Gatewayの公開・匿名JWKSを理由にAのidentityを省略しない。
認証済み接続でも各新規RPCで現在の辺許可を検査する。実行中RPCと許可撤回の扱いは共通認証仕様に従う。

## 公開 proto と宛先サービスのマッピング

同じ型・RPC意味・公開可能性・エラー・streaming・互換性方針を持つ契約は、サービスprotoを単一の定義元として再利用する。
認証の違いだけではprotoを分けない。再利用する場合もGatewayとバックエンドの実装・認証設定は別にする。
現時点で下表にあるConnect RPCは再利用対象とし、受信と宛先のpackage・Service・Methodを一致させる。
独自の入出力や版管理が必要なRPCは独自protoに定義し、対応表へ受信RPC・宛先RPC・変換契約を追加する。現時点では固有の追加RPCを定義しない。
Guest HTTPはproto再利用の対象外で、限定HTTP例外として扱う。

再利用・独自を通じて完全修飾RPCパスを一意にし、宛先URL・論理ID・公開区分・client／scope／辺の対応を起動時に検証する。
表の「全RPC」は列挙した現行メソッドだけを意味し、将来の追加メソッドを自動公開しない。未登録RPC・パス重複・任意宛先・Gateway自身への誤転送は拒否する。
protoの採用版を固定し、更新時は機械的な互換性と、追加フィールド等の外部公開範囲を確認する。
内部専用の型を外部利用者へ返す用途ではそのまま再利用せず、公開用の型と明示変換を設ける。
表の「公開区分」は Service Gateway がどのクライアントへ公開するかを示す

- 公開: Web（BFF 経由）・スタッフアプリ・エッジ端末・ゲスト等のクライアントが呼べる
- 内部オンリー: サービス間呼び出し専用。Service Gateway は token_use=service（後述「サービス間経路の検証と再発行」で発行）のみ許可し、外部利用者には実行を許可しない（違反は permission_denied）。Cloud Runの公開入口からパスへ到達できることとは区別する

各 RPC の認可の正本は各サービス仕様（本表は導出）

| 宛先サービス | proto service | RPC | 公開区分 |
|---|---|---|---|
| Tenant Management | `tolo.tenant.v1.TenantService` | StartTenantRegistration | 公開（管理 UI。未認証） |
| 〃 | 〃 | ClaimTenantOwnership | 公開（管理 UI。registration） |
| 〃 | 〃 | ChangeTenantContract、ArchiveTenant、CreateEvent、AssignEventType、TransitionEventStatus、ListEvents | 公開（管理 UI、ListEvents はスタッフアプリも） |
| 〃 | 〃 | GetEvent | 内部オンリー（Graph Authoring の参照整合） |
| 〃 | 〃 | GetObservationSettings | 内部オンリー（Observation の設定値取得） |
| 〃 | 〃 | UpdateObservationSettings | 公開（管理 UI） |
| 〃 | `tolo.relation.v1.RelationAdminService` | AddTenantMember、ChangeTenantRole、GrantEventRole、RevokeRole、ListMemberships | 公開（管理 UI。関係参照は Tenant Management が実装） |
| Graph Authoring | `tolo.graph.v1.GraphAuthoringService` | SaveGraph、MapObservationPoint、AddQrLocation、UpdateQrLocation、RemoveQrLocation、GetGraph、PublishRevision | 公開（管理・設計 UI） |
| 〃 | `tolo.graph.v1.GraphSupplyService` | 全 RPC（GetCurrentRevision、GetObservationPointMappings、GetDisplayNames、GetGatePoints、GetQrLocations） | 内部オンリー（Observation・Guest Service） |
| Observation | `tolo.observation.v1.MeasurementIngestService` | ReportMeasurements | 公開（エッジ端末）＋内部（Guest Service の QR 計上由来） |
| 〃 | `tolo.observation.v1.EdgeDeviceService` | RegisterEdgeDevice、UnregisterEdgeDevice、ListEdgeDevices | 公開（管理・設計 UI） |
| 〃 | 〃 | Heartbeat | 公開（エッジ端末） |
| 〃 | 〃 | UpdateObservationPointConfig | 公開（スタッフアプリ） |
| 〃 | `tolo.observation.v1.ManualInterventionService` | 全 RPC（OperateGate、ToggleDangerFlag、RegisterScheduleEvent、ReportCongestion、CorrectQueue） | 公開（スタッフアプリ） |
| 〃 | `tolo.observation.v1.StatusQueryService` | GetEventOverview | 公開（スタッフアプリ） |
| 〃 | 〃 | GetGuestSnapshot | 内部オンリー（Guest Service の復旧 pull） |
| Operation | `tolo.operation.v1.StaffCommunicationService` | SendStaffMessage、RevokeStaffMessage、ShareGuidanceInfo | 公開（スタッフアプリ） |
| 〃 | 〃 | ListStaffMessages | 公開（スタッフアプリ）＋内部（Guest Service の復旧 pull） |
| 〃 | `tolo.operation.v1.OperationControlService` | 全 RPC（DirectReassignment、ApplyReassignment、ListReassignments） | 公開（スタッフアプリ、ListReassignments は管理・設計 UI も） |
| 〃 | `tolo.operation.v1.DeliveryCoordinationService` | UpdateConnectionState | 公開（スタッフアプリ） |
| 〃 | 〃 | RequestProposalDelivery、RecordFeedbackValues | 内部オンリー（Observation） |
| 〃 | `tolo.operation.v1.DigestService` | GetHistoryDigest | 公開（スタッフアプリ） |
| Realtime | `tolo.realtime.v1.RealtimeFetchService` | FetchDeliveries、IssueFirestoreToken | 公開（スタッフアプリ） |
| Notification | `tolo.notification.v1.NotificationService` | SendPush | 内部オンリー（Operation） |
| 〃 | `tolo.notification.v1.DeviceTokenService` | RegisterDeviceToken、UnregisterDeviceToken | 公開（スタッフアプリ） |
| Reference Aggregation | `tolo.refagg.v1.ReferenceAggregationService` | SubmitAnonymizedFeedback、GetReferenceValues | 内部オンリー（Operation 投入、Observation 取得） |
| Guest Service | —（proto なし。ゲスト向け HTTP） | ゲスト用ページ・コンポーネント API | 公開（ゲスト。未認証でパススルー） |

補足

- 同一 RPC が公開と内部の両方を持つもの（ReportMeasurements、ListStaffMessages）は、Service Gateway が経路ごとに許可を判定する
  いずれも公開側＝認可表の token_use、内部側＝service
- PubSub 3トピック、Firestore 変更通知、Observation からの Flow Control／Line Control 呼び出し（Flow Control、Line Control）は Service Gateway を経由しないため本表の対象外

## 経路の分類

| 経路 | 外部資格情報 | 動作 |
|---|---|---|
| ユーザー（テナント文脈） | `tenant_access`（IdP 発行） | 検証＋内部 JWT へ変換 |
| ユーザー（イベント文脈） | `event_access`（IdP 発行） | 検証＋内部 JWT へ変換。エッジ端末（観測ページ）もこの経路 |
| 仮テナント作成 | なし（未認証） | パススルー。StartTenantRegistrationだけを許可し、匿名作成の保護を適用 |
| 仮テナントの所有権取得 | 所有権取得専用の最小トークン（IdP 発行） | 検証＋内部 JWT へ変換 |
| サービス間の同期 RPC | ワークロード資格情報＋文脈トークン（新規マシン起点だけ省略可。後述「サービス間経路の検証と再発行」） | 辺ポリシー照合＋token_use=service の内部 JWT を再発行 |
| ゲスト | なし（未認証） | パススルー（Guest Service のゲスト向け HTTP） |

ユーザー経路の外部トークンが鍵束縛（`cnf`）を持つ場合、検証には DPoP proof の検証を含む（後述「外部トークンの検証」）。

## 外部トークンの検証

- IdP の issuer または Discovery URL を設定し、OIDC Provider Configuration と Authorization Server Metadata から `issuer`、`jwks_uri`、`introspection_endpoint` を解決する。起動時に metadata と設定値を照合し、不一致または必須 endpoint の欠落があれば起動しない
- 署名は Discovery の `jwks_uri` から取得した JWKS でローカル検証する。IdP の JWKS を参照するのは原則 Service Gateway のみで、明示例外は Edge Bridge Service（`event_access` の直接検証。Edge Bridge Service）
- claim 検証: iss（IdP）、aud（バックエンド API 全体の論理 audience。例 `backend-api`。値は1つで、Edge Bridge Service も同じ値を検証する）、exp／nbf（clock skew 許容 ±30 秒）、token_use、client_id（発行先 client）
- 送信者拘束（DPoP。RFC 9449）: `cnf`（`jkt`）を持つ外部トークンには DPoP proof を要求し検証する。検証項目は、proof の署名、トークンの `cnf`（`jkt`）と proof の公開鍵の一致、アクセストークンのハッシュの一致、HTTP メソッドと対象 URI の一致、発行時刻の許容窓、および proof 識別子の再生防止とする
- 束縛を要求するのは public client（スタッフアプリ、エッジ端末の観測ページ）へ発行されたトークンに限る。移行中は `cnf` を持たないトークンを従来どおり扱い、public client の対応完了後に、public client へ発行された束縛のないトークンを拒否へ切り替える（発行先は `client_id` claim で判定する）。BFF（confidential client）へ発行されたトークンには束縛を要求しない
- proof 識別子の再生防止は短命の保持を要する。JWT 発行処理をステートレスに保つ方針の明示的な例外とする
- 送信者拘束は外部トークンの層で完結させ、内部 JWT へ `cnf` 等の束縛クレームを持ち込まない
- メソッド単位の要求 token_use を認可表（後述）で強制する。scope は発行時点の権限スナップショットであり、各サービスが主判定に用いる。Service Gateway は値を変更せず内部 JWT へ転記する
- 失効照会（introspection。RFC 7662）は metadata の `introspection_endpoint` を使用し、管理系の書き込み 6 RPC（ArchiveTenant、ChangeTenantContract、AddTenantMember、ChangeTenantRole、GrantEventRole、RevokeRole）に限って行う。結果は jti 単位で60秒キャッシュし、将来の追加はこの一覧への追記で行う
- introspection が確認するのはトークンの active／revoked であり、現在の membership／permission ではない。6 RPC の現在権限は Tenant Management が同一 DB で別に確認する
- その他の RPC は失効照会を行わず、TTL による自然失効に委ねる（外部トークンは自身の exp。既定は `tenant_access` 15 分・`event_access` 10 分（Auth（IdP））、内部 JWT 120 秒）。IdP の可用性が全 API の可用性を規定しないようにするためである
- introspection 不達時は当該 6 RPC のみ fail closed とする（トークンを有効扱いしない）

## サービス間経路の検証と再発行

サービス間の同期 RPC も Service Gateway を経由する。
この経路ではワークロード資格情報を必ず検証し、新規マシン起点を除いて文脈トークンも検証して、`token_use=service` の内部 JWT をホップごとに再発行する。
役割分離の原則: 呼び出し元の識別はワークロード資格情報が担い、内部 JWT は処理文脈の運搬と宛先束縛に使う（トークンの提示はワークロードの認証にならない）。呼び出し可否は辺ポリシーが決める。

### ワークロード資格情報の検証

- 取得・検証・運搬・環境変数の契約は workload_auth.md を正本とする
- `TOLO_WORKLOAD_AUTH_MODE=spire|cloud_run` を起動時に検証し、受信と送信の方式を一体で選択する。未設定・不正値では起動しない。認証失敗による別方式へのフォールバックは行わない
- SPIREモードではアプリが相手のX.509-SVIDと鍵所持をTLSで検証する。Cloud RunモードではIAMに加えてworkload-authorizationの完全なGoogle署名IDトークンをアプリで検証する
- 検証済みSPIFFE ID、またはGoogle issuer＋SA unique IDを環境別の完全一致対応表で論理サービスIDに変換し、文脈検証と辺認可へ渡す。未登録principalは拒否する
- IdPはサービスidentityに関与しない。内部JWTとワークロード資格情報の検証パスを分離し、文脈JWTの所持をワークロード認証とみなさない
- 文脈JWTはauthorization、Cloud Runの完全なGoogle tokenはworkload-authorization、IAM用はX-Serverless-Authorizationで運ぶ。SPIREモードはTLSで認証し、Google用の2ヘッダを使わない

### 文脈トークンの検証

- 文脈トークンは、呼び出し元サービスが処理中のリクエストで受領した内部 JWT である。ユーザー起点の文脈に加え、マシン起点チェーンの `token_use=service` も次ホップの文脈として提示できる
- Service Gateway の署名鍵で検証し、提示時点で有効（exp 内）であることを確認する
- 提示者 = aud の突合: 文脈トークンを提示できるのは、その aud に指名されたワークロードだけである。ワークロード資格情報で識別した呼び出し元と aud が一致しなければ拒否する
- ユーザー起点は、入口の `tenant_access`／`event_access`／`registration`、または `origin_sub` を持つ `token_use=service` とする。ユーザー起点の `service` は `scope`、`src_jti`、`origin_sub`、`txn` を必須とする
- マシン起点チェーンは `token_use=service` とし、`txn` を必須とする。`scope`、`src_jti`、`origin_sub`、`tenant_id`、`event_id` を持つ場合は拒否する
- 新規マシン起点は文脈トークンを提示しない。文脈トークンを省略できるのはこの分岐だけである

### 辺ポリシーの照合

- 辺ポリシーは、許可するサービス間呼び出しの静的な一覧（重要構成としてコードと同期管理し、実装用の宣言的設定と CI で突合する）
- 辺の形式: ユーザー起点は「(呼び出し元ワークロード, 文脈トークンの token_use と aud) → 宛先メソッド」、マシン起点は「呼び出し元ワークロード → 宛先メソッド」とする。マシン起点チェーンで提示する `service` 文脈は処理チェーンの継続を示すが、呼び出し権限は付与しない
- 辺が許可一覧になければ permission_denied。token_use=service の発行根拠はこの辺ポリシーの照合であり、ユーザーの権限からは導出しない

### 再発行する内部 JWT

- すべての分岐で `token_use=service`、`aud=宛先サービス`、`sub=呼び出し元サービス`、`client_id=呼び出し元サービス` とし、発行ごとに新しい `jti` を生成する
- ユーザー起点では、`scope` と `txn` を文脈トークンから透過し、`src_jti` を文脈トークンの `jti` とする。`origin_sub` は文脈トークンにあれば透過し、最初のサービス間再発行では文脈トークンの `sub` を設定する
- ユーザー起点の文脈トークンが `tenant_id` または `event_id` を持つ場合は、同じ値を再発行するトークンへ引き写す
- マシン起点チェーンでは、文脈トークンの `txn` だけを透過する。`scope`、`src_jti`、`origin_sub`、`tenant_id`、`event_id` は付与しない
- 新規マシン起点では UUIDv7 の `txn` を生成する。`scope`、`src_jti`、`origin_sub`、`tenant_id`、`event_id` は付与しない
- `txn` は監査とトレースの相関にのみ用い、認可、冪等性、業務識別子には用いない
- クレームの役割は2つに分かれる。`tenant_id`／`event_id` は保護境界の強制に用いてよい（どのデータ区画かを表すため）。`origin_sub`／`txn` は監査専用であり、認可判定に使ってはならない（ユーザーの権限からサービス間の呼び出し可否を導出しないため）
- TTL は独立の 120 秒とし、入口トークンの exp で cap しない（認可根拠が辺ポリシーにあり、ユーザー権限は認可に用いないため）

## 内部 JWT

外部トークンの検証成功後、以下の内部 JWT を発行する
scope は外部トークンの値を転記し、拡大も暗黙の縮小もしない

### クレーム一覧

クレーム構造の正本は internal_jwt.md（共通必須クレームと起点別クレーム）。`txn` は共通必須クレームであり、`scope`、`src_jti`、`origin_sub` は起点別とする。

| claim | 内容 |
|---|---|
| iss | Service Gateway の発行者識別子（IdP の iss と別値にし、取り違えを防ぐ） |
| sub | ユーザー系は user_id、サービス系は呼び出し元サービスの識別子（マシン起点では検証済みワークロード identity のサービス識別子） |
| aud | 宛先マイクロサービスの論理識別子（宛先サービス単位。1 token 1 audience を踏襲し、サービス間のトークン転用を防ぐ） |
| token_use | 下表の4種別 |
| scope | 外部トークンの scope の転記（起点別。マシン起点の service では持たない） |
| client_id | ユーザー系は外部トークンの `client_id`（発行先 client。BFF、スタッフアプリ等）の転記。サービス系は呼び出し元サービスの識別子（sub と同値） |
| src_jti | 変換元トークンの jti（入口変換では外部トークン、サービス間再発行では文脈トークン。監査相関用。マシン起点の service では持たない） |
| iat／nbf／exp | TTL は 120 秒。入口変換の exp は「発行時刻＋120 秒」と「元トークンの exp」の小さい方。サービス間再発行は独立の 120 秒 |
| jti | 内部 JWT 自体の識別子（サービス側監査ログ用） |
| txn | UUIDv7 の処理チェーン識別子（監査・トレース専用）。外部トークンの入口変換または新規マシン起点で生成し、後続ホップへ透過 |

### token_use 別の追加クレーム

| token_use | 由来する外部トークン | 追加必須 claim |
|---|---|---|
| tenant_access | `tenant_access` | tenant_id |
| event_access | `event_access` | tenant_id、event_id |
| service | 辺ポリシーに基づく再発行（前述「サービス間経路の検証と再発行」） | ユーザー起点は origin_sub（監査専用）と scope・src_jti を持つ。マシン起点はこれらを持たない |
| registration | 所有権取得専用最小トークン | なし（tenant_idを持たない。scopeは`tenant.claim`のみでClaimTenantOwnershipに限定） |

- origin_sub: 処理の起点となったユーザーの user_id（ユーザー起点のみ）。監査専用であり、認可判定に使ってはならない
- txn: 外部トークンの入口変換または新規マシン起点で UUIDv7 を生成し、同一処理チェーンの全ホップへ透過する。認可、冪等性、業務識別子には用いない

### 含めないクレーム

| claim | 理由 |
|---|---|
| role／tenant_role／event_role | scope 発行判定にのみ使用し、JWT claim に載せない方針のため |
| resource | 外部トークン向けの表現。サービス側は tenant_id／event_id と RPC で判定できる |

### TTL と再利用

- TTL 120 秒。制約は2段に分かれ、いずれも RPC の「開始」に対して働く（完了期限は課さない）
  (1) サービス入口で検証済みのローカル処理は、その内部 JWT の失効後も継続してよい。検証は入口の一度きりで、ローカル処理の長さは TTL を要求しない
  (2) その入口内部 JWT を文脈トークンとして新しい後段 RPC を開始できるのは、提示時点で実際の `exp` より前の場合に限る（「サービス間経路の検証と再発行」）。入口変換の `exp` は元トークンの残存時間で短縮されるため、固定120秒では判定しない
  開始済みの RPC の完了は、再発行された内部 JWT（独立の 120 秒）と各 RPC のタイムアウト設定に従う。入口 JWT の exp を完了期限（deadline）として伝搬・強制はしない
- TTL が規定するのはリプレイの窓と、鍵漏えい時の残存トークンの寿命
- 変換と再発行のたびに新しい内部 JWT と `jti` を生成し、発行済み JWT を再利用しない。発行キャッシュまたは採番ストアを持たず、JWT 発行処理をステートレスに保つ
- 内部 JWT は denylist を持たない。失効は TTL での自然失効に委ねる

### 署名鍵

- 方式: ES256、kid 必須。Service Gateway 専用鍵とし、IdP の鍵と共有しない
- 保管: 秘密鍵は KMS／Secret Manager に置き、Service Gateway のみがアクセスする
- 配布: Service Gatewayが認証不要のHTTPS GETによるJWKSで署名検証用公開鍵を公開する。各サービスのキャッシュTTLは5分。未知kidの再取得は並行要求をまとめ、頻度と失敗時の再試行を制限する
- 定期ローテーション（30 日周期。自動化）: (1) 新鍵を JWKS へ追加（署名は旧鍵のまま）→ (2) JWKS キャッシュ TTL＋余裕（15 分）経過後に新鍵で署名開始 → (3) 「内部 JWT TTL＋キャッシュ TTL」経過後に旧鍵を JWKS から削除
- 緊急ローテーション（漏えい時）: 新鍵を全配布経路へ公開したうえで署名を切り替え、漏えい鍵を配布集合から除去する。追加した共有キャッシュはpurge等で更新する。未知kidの再取得だけでは既知の漏えい鍵は失効せず、取得側キャッシュの残存と内部JWT TTLを含めて失効反映を評価する。originからの削除による即時失効は保証しない

## 公開JWKSとHTTP例外

JWKSはworkload資格情報・内部JWT・IdP tokenを要求せず、全利用者へ同じ公開鍵集合を返す。不要な認証ヘッダで内容を変えたりidentityを生成したりしない。
通常のHTTP構文・サイズ制限は適用する。署名用のES256公開鍵と検証情報だけを含め、秘密鍵・共通鍵・テナントや運用者の情報は含めない。
取得側は設定済みissuerとHTTPSのJWKS URLを使い、token内の任意jku等を取得先にしない。署名・issuer・aud・期限の検証は維持する。
JWKSのURLと必要ならHEAD対応、ETag・HTTPキャッシュの具体値は実装フェーズで確定する。共有キャッシュ追加時は取得側と合わせた鮮度上限を定義し、既存の通常ローテーション待機時間を超えないよう整合させる。
全インスタンスは同じ鍵集合を返し、新鍵の全配布経路への反映を確認してから署名を開始する。署名用秘密鍵の保管権限は配布機能から分離する。

Guest HTTPは既知のパス・method・固定Guest宛先に限定し、未知RPCをGuestへ転送しない。匿名要求でもGateway→Guestのworkload認証は必須とする。
IdPのDiscovery・JWKS・検証要求、Google metadata／公開鍵、SPIFFE Workload API、CORS・必要な監視はConnect業務RPC外の限定例外とする。
例外ごとに受理規則を設け、任意HTTP転送を追加しない。CORS応答の許可を業務RPCの認証成功として扱わない。

## 型付き委譲の通信契約

再利用RPCは意味上の入出力、独自RPCは定義した変換を保証する。業務処理やDBをGatewayへ移さない。
受信deadline・cancelを後段へ伝え、残存時間を増やさない。公開可能なConnectエラー・許可metadata・必要なheaders／trailers・streaming終了状態を伝搬する。
streamingの全件bufferingをせず、backpressureと切断を扱う。非冪等更新を自動再試行しない。
認証ヘッダとidentityを外部から丸ごと転送せず、現在の要求と宛先に応じた内部JWT・workload資格情報を生成クライアントへ設定する。
接続プールは共有できるが、利用者の認証文脈は要求間で共有しない。後段クライアントはBへ直接接続する設定とし、通常サービスのGateway経由クライアント設定を誤って使わない。

## メソッド認可表

各サービス仕様の認可欄からの導出（各仕様が正。食い違う場合は各仕様に従う）

### token_use = event_access を要求（Token Exchange を経たトークンが必要）

| サービス | RPC | scope |
|---|---|---|
| Graph Authoring | SaveGraph、MapObservationPoint、AddQrLocation／UpdateQrLocation／RemoveQrLocation、PublishRevision | events.manage |
| Graph Authoring | GetGraph | events.read |
| Observation | RegisterEdgeDevice、UnregisterEdgeDevice | events.manage |
| Observation | OperateGate、UpdateObservationPointConfig、ToggleDangerFlag、RegisterScheduleEvent、ReportCongestion、CorrectQueue | events.operate |
| Observation | ReportMeasurements、Heartbeat | events.report |
| Observation | ListEdgeDevices、GetEventOverview | events.read |
| Operation | SendStaffMessage、RevokeStaffMessage、ShareGuidanceInfo、DirectReassignment、ApplyReassignment | events.operate |
| Operation | ListStaffMessages、ListReassignments、GetHistoryDigest、UpdateConnectionState | events.read |
| Realtime | FetchDeliveries、IssueFirestoreToken | events.read |

### token_use = tenant_access を要求

| サービス | RPC | scope |
|---|---|---|
| Tenant Management | ChangeTenantContract、ArchiveTenant | tenant.write |
| Tenant Management | CreateEvent、AssignEventType、TransitionEventStatus、UpdateObservationSettings | events.manage |
| Tenant Management | ListEvents | events.read |
| Tenant Management（RelationAdminService） | AddTenantMember、ChangeTenantRole、GrantEventRole、RevokeRole | tenant.write |
| Tenant Management（RelationAdminService） | ListMemberships | tenant.read |
| Notification | RegisterDeviceToken、UnregisterDeviceToken | tenant.read（自デバイス限定） |

### token_use = service を要求（サービス間）

Tenant.GetEvent（テナント文脈必須）、Tenant.GetObservationSettings、Graph 供給系（GetCurrentRevision／GetObservationPointMappings／GetGatePoints／GetDisplayNames／GetQrLocations）、Observation の GetGuestSnapshot、Operation の RequestProposalDelivery／RecordFeedbackValues／ListStaffMessages（Guest Service の復旧時）、Notification.SendPush、Reference Aggregation の SubmitAnonymizedFeedback／GetReferenceValues、Observation.ReportMeasurements（Guest Service 由来）

Flow.Optimize と Line.GuideQueues は Service Gateway を経由しないため本表にない（ワークロード資格情報の直接検証。Flow Control、Line Control）

### token_use = registration を要求

Tenant.ClaimTenantOwnership（scopeは`tenant.claim`）

### パススルー

- Tenant.StartTenantRegistration（未認証の仮テナント作成）
- Guest Serviceのゲスト向けHTTP（未認証）

StartTenantRegistrationには、送信元単位のレート制限、ボット対策、リクエストサイズ上限を適用する。
具体値と方式は実装フェーズで確定する。

## サービス側の検証規約

- workload_auth.md に従い、transportの呼び出し元が許可されたGatewayであることを確認する。匿名の外部要求でもこの確認は省略しない。Flow／Lineは同仕様に定めるObservationの直接認証を行う
- 内部JWTが必須の経路ではService GatewayのJWKSで署名を検証し、iss・aud・exp・nbfを確認する（clock skew 許容 ±30 秒）
- tenant_id／event_id claim とリクエスト対象の一致を確認する（保護境界の強制）
  claim もリクエストの識別子も公開 ID のため、値をそのまま突合する（internal_jwt.md）
  token_use=service で claim を持たない場合（マシン起点）は突合できない。この場合に処理を続けてよいのは、境界の強制を要さないと各仕様が明示したメソッドに限る
- `tenant_access`／`event_access`／`registration` の主判定は、発行時点のスナップショットである scope とする。通常 RPC は現在の membership／permission を都度参照せず、既発行 scope を外部トークンの TTL まで許容する
- 例外は Tenant Management の管理系書き込み6 RPC（ArchiveTenant、ChangeTenantContract、AddTenantMember、ChangeTenantRole、GrantEventRole、RevokeRole）とする。Tenant Management は同一 DB の現在の membership／permission をローカルに再確認し、Service Gateway の introspection は別に active／revoked を確認する
- `token_use=service` のメソッド可否は scope ではなく、Service Gateway が照合済みの辺ポリシーを根拠とする
- StartTenantRegistrationは内部JWTなしで受理する唯一のTenant Management RPCとし、ほかの同サービスRPCへ未認証要求を転送しない

## エラー方針

外部レスポンスの本文に tenant／event／membership／失効の詳細を漏らさない
エラーコードによる区別は禁じない。存在しない識別子と権限のない識別子を別のコードで返してよい（識別子は推測できないため。Tenant Management のエラー節）

| 事象 | Connect エラーコード |
|---|---|
| トークンなし、無効、期限切れ、失効済み、token_use 不一致 | unauthenticated |
| DPoP proof の欠落、無効、再生、または鍵の不一致（`cnf` を持つトークンのみ） | unauthenticated |
| token_use は満たすが認可表で当該メソッドに許可されない | permission_denied |
| introspection 不達（対象 6 RPC のみ fail closed） | unauthenticated |
| 宛先サービス不達 | unavailable（透過） |

## 監査ログ

- 記録項目: timestamp、request_id、メソッド（サービス＋RPC）、client_id、sub、token_use、txn、発行した内部 JWT の jti、result、failure_reason、source_ip。`src_jti` と `origin_sub` はユーザー起点の場合だけ記録する
- サービス間再発行では、呼び出し元ワークロード、照合した辺、origin_sub の有無も記録する
- 外部トークン本体・内部JWT本体・Googleワークロードトークン・SVID秘密鍵をログへ出してはならない
- request_id は宛先サービスへ伝播し、IdP 監査ログ（src_jti）・サービス側ログと突き合わせ可能にする

## 未確定事項

- アプリ内プロキシの言語・ライブラリ。DPoP proofの検証と短命状態の保持を実装できること
- 鍵保管（KMS／Secret Manager）の製品選定、公開JWKSのURL・キャッシュ実装・鍵集合の同期と緊急切替の具体手順
- introspection キャッシュ TTL（60 秒）と失効反映遅れの許容値の最終確認
- DPoP の nonce の要否、proof 識別子の保持方式と再生防止の窓、プロキシ配下での対象 URI の正規化規則、bearer 併存の打ち切り時期
- DPoP が HTTP 層で用いるエラー表現と Connect エラーコードの対応づけの詳細
