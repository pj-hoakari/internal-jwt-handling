# Service Gateway 入出力仕様

作成日: 2026-07-03
位置づけ: デプロイ単位。自身の proto を持たず、各サービスの proto を透過的に公開するプロキシ（同期 RPC の原則経由点。例外は Auth、Edge Bridge Service、Observation → Flow／Line）
役割: 外部資格情報の検証と内部 JWT への変換（トークン変換点）、および宛先サービスへの転送

## 公開面と転送

- 公開面は各サービスの proto（Connect-RPC）をメソッド単位でそのまま公開する。リクエスト・レスポンスのペイロードは変換しない
- 認証経路では`authorization`メタデータの外部トークンを検証し、内部JWTへ差し替えて宛先サービスを呼び出す
- 明示した未認証経路では内部JWTを発行せず、認証メタデータを付与しないまま宛先へ転送する
- ストリーミング RPC はストリーム開始時に検証する
- PubSub の publish／購読と Firestore 変更通知は経由しない（ブローカー仲介）
- マイクロサービスへ Service Gateway を迂回して到達できないことをインフラ層（ネットワーク構成）で保証する
  例外は2つある。Edge Bridge Service は完全に独立した位置に置き、本 Gateway の後ろに配置しない（Edge Bridge Service。認証・認可は Firestore のアクセス制御による）。Flow Control と Line Control は Observation からの直接呼び出しのみを受け、本 Gateway を経由しない（Flow Control、Line Control。到達制御はインフラ層とワークロード資格情報の直接検証で保証する）
  例外を認める基準は「Service Gateway がペイロードに関与せず、呼び出し元が単一のサービス間経路」に限る

## 公開 proto と宛先サービスのマッピング

Service Gateway は各サービスの proto をメソッド単位で透過公開するため、公開 proto と宛先 proto は同一（変換なし）
表の「公開区分」は Service Gateway がどのクライアントへ公開するかを示す

- 公開: Web（BFF 経由）・スタッフアプリ・エッジ端末・ゲスト等のクライアントが呼べる
- 内部オンリー: サービス間呼び出し専用。Service Gateway は token_use=service（後述「サービス間経路の検証と再発行」で発行）のみ許可し、クライアントへは公開しない（違反は permission_denied）

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
| Graph Authoring | `tolo.graph.v1.GraphAuthoringService` | CreateGraph、AddPoint、UpdatePoint、RemovePoint、AddRoute、UpdateRoute、RemoveRoute、MapObservationPoint、AddQrLocation、UpdateQrLocation、RemoveQrLocation、GetGraph、PublishRevision | 公開（管理・設計 UI） |
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

## 外部トークンの検証

- IdP の issuer または Discovery URL を設定し、OIDC Provider Configuration と Authorization Server Metadata から `issuer`、`jwks_uri`、`introspection_endpoint` を解決する。起動時に metadata と設定値を照合し、不一致または必須 endpoint の欠落があれば起動しない
- 署名は Discovery の `jwks_uri` から取得した JWKS でローカル検証する。IdP の JWKS を参照するのは原則 Service Gateway のみで、明示例外は Edge Bridge Service（`event_access` の直接検証。Edge Bridge Service）
- claim 検証: iss（IdP）、aud（バックエンド API 全体の論理 audience。例 `backend-api`。値は1つで、Edge Bridge Service も同じ値を検証する）、exp／nbf（clock skew 許容 ±30 秒）、token_use
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

- 形式は「audience 束縛のワークロード JWT（aud = Service Gateway）を JWKS で検証」に固定し、デプロイ段階で発行者のみ差し替える
  Docker Compose 期: 各サービスが自身の鍵ペアで自己署名する短命 JWT（iss = サービス名）。Service Gateway の静的 JWKS 構成（サービス名と公開鍵の対応表）で検証し、鍵は compose の secrets で配布する
  Google Cloud 期: Cloud Run のメタデータサーバが発行する Google 署名の ID トークン（Service Account 単位。GKE の場合は Workload Identity）。Google（またはクラスタ）の JWKS をキャッシュして検証し、Service Account をワークロード名へ対応付ける
- 「呼び出し元ワークロード identity の検証」は一点の抽象に切り出し、差し替えを局所化する。増えるのはキャッシュのみでステートレス性を保つ
- IdP はサービスの identity に関与しない（サービスは IdP のクライアントにならない）。全サービス共通の共有シークレットは用いない
- ワークロード JWT は内部 JWT とは別形式のシンプルな JWT とする（OAuth のクライアント認証（RFC 7523 private_key_jwt）と同じ位置づけ。提示者の証明のみを担い、認可情報を運ばない）
  必須クレーム: iss（サービス名。Google Cloud 期は発行者固有の値）、sub（サービス識別。iss と同値でよい）、aud（Service Gateway）、iat／exp（短命。数分以下）、ヘッダ kid。任意: jti（リプレイ検知を強める場合）
  token_use・scope・tenant_id 等、内部 JWT のクレーム体系は持たない
- 内部 JWT との混同防止: iss と署名鍵を内部 JWT と別にし、検証パスを分離する（aud も Gateway 宛と宛先サービス宛で異なるため、取り違えは構造的にも弾かれる）
- 運搬チャネルの分離: 文脈トークンは `authorization` メタデータ、ワークロード JWT は別のメタデータキー `workload-authorization` で送る

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
| client_id | ユーザー系は外部トークンを提示した client（BFF、スタッフアプリ等）。サービス系は呼び出し元サービスの識別子（sub と同値） |
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
- 配布: Service Gateway が内部向け JWKS エンドポイントで公開鍵を公開する。各サービスは JWKS をキャッシュし（TTL 5 分）、未知の kid を受けたら即時再取得する（再取得にはレート制限を付ける）
- 定期ローテーション（30 日周期。自動化）: (1) 新鍵を JWKS へ追加（署名は旧鍵のまま）→ (2) JWKS キャッシュ TTL＋余裕（15 分）経過後に新鍵で署名開始 → (3) 「内部 JWT TTL＋キャッシュ TTL」経過後に旧鍵を JWKS から削除
- 緊急ローテーション（漏えい時）: 新鍵で即時署名開始＋漏えい鍵を JWKS から即時削除。各サービスは未知 kid の再取得で自動追従し、被害の窓は「JWKS キャッシュ TTL＋内部 JWT TTL」で規定される

## メソッド認可表

各サービス仕様の認可欄からの導出（各仕様が正。食い違う場合は各仕様に従う）

### token_use = event_access を要求（Token Exchange を経たトークンが必要）

| サービス | RPC | scope |
|---|---|---|
| Graph Authoring | CreateGraph、AddPoint／UpdatePoint／RemovePoint、AddRoute／UpdateRoute／RemoveRoute、MapObservationPoint、AddQrLocation／UpdateQrLocation／RemoveQrLocation、PublishRevision | events.write |
| Graph Authoring | GetGraph | events.read |
| Observation | ReportMeasurements、Heartbeat、RegisterEdgeDevice、UnregisterEdgeDevice、OperateGate、UpdateObservationPointConfig、ToggleDangerFlag、RegisterScheduleEvent、ReportCongestion、CorrectQueue | events.write |
| Observation | ListEdgeDevices、GetEventOverview | events.read |
| Operation | SendStaffMessage、RevokeStaffMessage、ShareGuidanceInfo、DirectReassignment、ApplyReassignment | events.write |
| Operation | ListStaffMessages、ListReassignments、GetHistoryDigest、UpdateConnectionState | events.read |
| Realtime | FetchDeliveries、IssueFirestoreToken | events.read |

### token_use = tenant_access を要求

| サービス | RPC | scope |
|---|---|---|
| Tenant Management | ChangeTenantContract、ArchiveTenant | tenant.write |
| Tenant Management | CreateEvent、AssignEventType、TransitionEventStatus、UpdateObservationSettings | events.write |
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

- Service Gateway の JWKS で署名を検証し、iss・aud・exp・nbf を確認する（clock skew 許容 ±30 秒）
- tenant_id／event_id claim とリクエスト対象の一致を確認する（保護境界の強制）
  claim もリクエストの識別子も公開 ID のため、値をそのまま突合する（internal_jwt.md）
  token_use=service で claim を持たない場合（マシン起点）は突合できない。この場合に処理を続けてよいのは、境界の強制を要さないと各仕様が明示したメソッドに限る
- `tenant_access`／`event_access`／`registration` の主判定は、発行時点のスナップショットである scope とする。通常 RPC は現在の membership／permission を都度参照せず、既発行 scope を外部トークンの TTL まで許容する
- 例外は Tenant Management の管理系書き込み6 RPC（ArchiveTenant、ChangeTenantContract、AddTenantMember、ChangeTenantRole、GrantEventRole、RevokeRole）とする。Tenant Management は同一 DB の現在の membership／permission をローカルに再確認し、Service Gateway の introspection は別に active／revoked を確認する
- `token_use=service` のメソッド可否は scope ではなく、Service Gateway が照合済みの辺ポリシーを根拠とする
- StartTenantRegistrationは内部JWTなしで受理する唯一のTenant Management RPCとし、ほかの同サービスRPCへ未認証要求を転送しない

## エラー方針

外部レスポンスの本文に tenant／event／membership／失効の詳細を漏らさない
エラーコードによる区別は禁じない。存在しない識別子と権限のない識別子を別のコードで返してよい（識別子は推測できないため。tenant_management_spec.md のエラー節）

| 事象 | Connect エラーコード |
|---|---|
| トークンなし、無効、期限切れ、失効済み、token_use 不一致 | unauthenticated |
| token_use は満たすが認可表で当該メソッドに許可されない | permission_denied |
| introspection 不達（対象 6 RPC のみ fail closed） | unauthenticated |
| 宛先サービス不達 | unavailable（透過） |

## 監査ログ

- 記録項目: timestamp、request_id、メソッド（サービス＋RPC）、client_id、sub、token_use、txn、発行した内部 JWT の jti、result、failure_reason、source_ip。`src_jti` と `origin_sub` はユーザー起点の場合だけ記録する
- サービス間再発行では、呼び出し元ワークロード、照合した辺、origin_sub の有無も記録する
- 外部トークン本体・内部 JWT 本体をログへ出してはならない
- request_id は宛先サービスへ伝播し、IdP 監査ログ（src_jti）・サービス側ログと突き合わせ可能にする

## 未確定事項

- 実装形態の製品選定（Envoy＋ext_authz、自前 Connect プロキシ等）
- 鍵保管（KMS／Secret Manager）の製品選定と内部 JWKS エンドポイントの公開範囲の実装詳細
- introspection キャッシュ TTL（60 秒）と失効反映遅れの許容値の最終確認
