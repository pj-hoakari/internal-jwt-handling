# サービス間の関係と主要なやり取り（図）

作成日: 2026-07-02
位置づけ: サービス（デプロイ単位）視点の図。ドメイン（コンテキスト）視点は domain/context_map.md が正本
内容の根拠: spec-base/README.md（通信規約・索引）と service/ 各仕様。図と本文が食い違う場合は各仕様が正

前提（凡例に共通）

- Auth、Edge Bridge Service、および Observation → Flow／Line（直接呼び出し）以外の同期 RPC はすべて Service Gateway を経由する。図では見やすさのためサービス間の GW を省略
- Edge Bridge Service は WebRTC のシグナリングのみを担い、Service Gateway の後ろに置かない。映像はページ間で直接やりとりする
- PubSub は情報更新 push の3トピックのみ。at-least-once・イベント単位の順序キー・受信側冪等
- 実線＝同期 RPC（gRPC／Connect）または HTTP、太線（==>）＝PubSub、点線＝リスナー・参照系・外部プッシュ
- BFF は図では省略（管理・設計 UI の Auth・GW への接続は BFF 経由）
  スタッフアプリはログインのみ直接 Auth と接続し、Token Exchange は BFF が代行（アプリ→BFF→Auth。構成B）。API 呼び出しはアプリ→GW のまま

## 1. サービス間の関係全体図

```mermaid
flowchart LR
  subgraph CL["クライアント"]
    StaffApp["スタッフアプリ"]
    AdminUI["管理・設計 UI（オーナー／スタッフ）"]
    EdgeDev["エッジ端末（ブラウザ）"]
    GuestBr["ゲスト（ブラウザ／サイネージ）"]
  end

  Auth["Auth（IdP）<br/>OIDC 標準 HTTP"]
  EB["Edge Bridge Service<br/>WebRTC シグナリング（GW を経由しない）"]
  GW["Service Gateway<br/>（Auth 以外の呼び出しが経由）"]

  subgraph SV["マイクロサービス（gRPC / Connect）"]
    direction TB
    TM["Tenant Management<br/>（関係参照 Relation を実装）"]
    GA["Graph Authoring"]
    OBS["Observation"]
    FLOW["Flow Control<br/>（ステートレス）"]
    LINE["Line Control<br/>（ステートレス）"]
    OP["Operation"]
    RT["Realtime"]
    NT["Notification"]
    RA["Reference Aggregation<br/>（保護境界外）"]
    GS["Guest Service"]
  end

  subgraph MSG["メッセージング・変更通知（GW 非経由）"]
    PS["PubSub<br/>guest-status / guest-messages / realtime-delivery"]
    FS["Firestore<br/>最終更新ID（イベント単位）"]
  end

  subgraph EXT["外部"]
    FCM["FCM"]
    WX["天気 API"]
  end

  %% 認証（OIDC。GW を経由しない唯一の HTTP）
  StaffApp -. "ログイン（認可コード＋PKCE）" .-> Auth
  AdminUI -. "アカウント登録／ログイン／所有権取得専用トークン" .-> Auth

  %% クライアント → GW → 各サービス
  StaffApp -- "全 RPC（Operation・Observation・Realtime.Fetch・Notification.トークン管理 等）" --> GW
  AdminUI -- "匿名の仮テナント作成・所有権取得・Tenant管理・Graph編集・エッジ登録" --> GW
  EdgeDev -- "計測値送信・Heartbeat（event_access）" --> GW
  EdgeDev -. "シグナリング" .- EB
  AdminUI -. "シグナリング" .- EB
  EdgeDev -. "映像（P2P。サービスを介さない）" .- AdminUI
  GuestBr -- "ゲスト用ページ（HTTP・未認証）" --> GW
  GW --> SV

  %% サービス間（同期 RPC。GW は省略表記）
  OBS -- "グラフ版・紐づけ・ゲート指定" --> GA
  OBS -- "Optimize（GW 非経由の直接呼び出し）" --> FLOW
  OBS -- "GuideQueues（GW 非経由の直接呼び出し）" --> LINE
  OBS -- "配信依頼・フィードバック引き渡し" --> OP
  OBS -- "参照値取得" --> RA
  OBS -- "GetObservationSettings（設定値）" --> TM
  OP -- "SendPush（閉デバイス）" --> NT
  OP -- "匿名化済みフィードバック投入（内部バッチ）" --> RA
  GS -- "QR 計上・復旧 pull" --> OBS
  GS -- "復旧 pull（メッセージ）" --> OP
  GS -- "表示名・QR 設置箇所" --> GA
  GA -- "参照整合（GetEvent）" --> TM
  Auth -. "所属・ロール参照（内部 I/F。仕様対象外）" .- TM

  %% PubSub（情報更新 push）
  OBS == "publish: guest-status" ==> PS
  OP == "publish: guest-messages / realtime-delivery" ==> PS
  PS == "購読: guest-status / guest-messages" ==> GS
  PS == "購読: realtime-delivery" ==> RT

  %% 変更通知と外部
  RT -- "最終更新IDを更新" --> FS
  FS -. "リアルタイムリスナー（変更検知）" .-> StaffApp
  NT -- "プッシュ送信" --> FCM
  FCM -. "プッシュ通知" .-> StaffApp
  GS -- "周期取得" --> WX
```

補足

- IdP 発行トークンは Service Gateway が検証し、内部 JWT へ変換して各サービスへ転送する。JWKS と introspection の endpoint は OIDC Discovery と Authorization Server Metadata から解決する（service_gateway.md）
  各サービスは Service Gateway の JWKS で内部 JWT をローカル検証する（図では省略）
- introspection は管理系書き込み6 RPCの active／revoked 確認に限定し、同じ6 RPCの現在権限は Tenant Management が同一 DB で確認する
- Flow／Line の呼び出し元は観測のみで、この呼び出しは Service Gateway を経由しない（各仕様参照）。Realtime・Notification は Operation の支援機構（独立コンテキストではない）
- Firestore の読み取り（Realtime の変更検知、WebRTC シグナリング）は Firebase Auth カスタムトークンによるアクセス制御を伴う（realtime.md、edge_bridge.md）
- 関係参照（RelationAdminService）はTenant Managementが実装する。ClaimTenantOwnershipのオーナー所属作成はサービス内部で完結し、サービス間RPCを経ない
- ゲート開閉（OperateGate）・観測点設定変更（UpdateObservationPointConfig）はスタッフアプリ→Observation の直接呼び出し。Operation→Observation の同期 RPC はない
- Reference Aggregation はどのテナント保護境界にも属さず、入出力に テナント識別子を持たない

## 2. やり取りの図（シーケンス）

### 2.1 主系統: 計測 → 最適化 → スタッフ配信・ゲスト状況更新

計測値の受信から、スタッフへの提案配信（開＝Realtime／閉＝Notification）とゲスト向け状況の更新までの一連の流れ
グラフ・紐づけ・ゲート指定の取得は毎回ではなく版の更新に応じて行う（図では1回で代表）

```mermaid
sequenceDiagram
  autonumber
  participant Edge as エッジ端末
  participant Obs as Observation
  participant GA as Graph Authoring
  participant Flow as Flow Control
  participant Line as Line Control
  participant Op as Operation
  participant PS as PubSub
  participant RT as Realtime
  participant FS as Firestore
  participant NT as Notification
  participant App as スタッフアプリ
  participant GS as Guest Service

  Edge->>Obs: 計測値送信（event_access）
  Obs->>Obs: 正規化（人/分）・観測スナップショット確定
  Obs->>GA: 現在のグラフ版・紐づけ・ゲート指定を取得
  Obs->>Flow: Optimize（グラフ＋スコア＋履歴＋検知状態＋手動介入＋参照値）
  Flow-->>Obs: 提案＋更新後の検知状態（観測が解釈せず永続化）
  Obs->>Line: GuideQueues（グラフ＋局所スコア＋ゲート状態＋前回行列状態＋履歴）
  Line-->>Obs: 更新後行列状態＋検知＋案内＋guest_digest＋形状提案
  Obs->>Obs: 結果を DWH へ永続化
  Obs->>Op: RequestProposalDelivery（提案・案内。宛先はスタッフのみ）
  Op->>Op: 接続状態で配送を振り分け（DeliveryRouted）
  Op->>PS: realtime-delivery へ publish（DeliveryOrder。delivery_id 採番）
  PS->>RT: 配信（at-least-once）
  RT->>RT: 配信ログへ永続化（delivery_id で重複排除）
  RT->>FS: 最終更新IDを更新
  FS-->>App: リスナーが変更を検知（フォールバックはロングポーリング）
  App->>RT: FetchDeliveries（resume_after_delivery_id）
  RT-->>App: Envelope 一式（提案・案内・メッセージ）
  Op->>NT: SendPush（閉デバイス宛。到着を伝えるのみ）
  NT->>App: FCM プッシュ通知（開いて Fetch・参照系で本文取得）
  Obs->>PS: guest-status へ publish（ID と数値のみ。sequence 付与）
  PS->>GS: 配信 → 読み取りモデル更新（sequence の新旧判定で冪等）
```

### 2.2 ゲスト向けメッセージとゲストアクセス

スタッフの手動配信がゲストに届くまでと、ゲストのアクセス時応答（自 DB のみで完結）

```mermaid
sequenceDiagram
  autonumber
  participant App as スタッフアプリ
  participant Op as Operation
  participant PS as PubSub
  participant GS as Guest Service
  participant GA as Graph Authoring
  participant Wx as 天気 API
  participant Guest as ゲスト
  participant Obs as Observation

  Note over GS: 事前準備（起動時・周期）
  GS->>GA: GetDisplayNames／GetQrLocations（表示名＋端点、QR 設置箇所）
  GS->>Wx: 天候を周期取得（所在地は自サービスの設定）

  App->>Op: SendStaffMessage（audience=GUEST）
  Op->>PS: guest-messages へ publish（GuestMessagesUpdate）
  PS->>GS: 配信 → 自 DB に保持（message_id で冪等。GuestMessageUpdated）

  Guest->>GS: QR（設置箇所×種類の発行 URL）からアクセス
  GS-->>Guest: ページ構成（コンポーネントの組み合わせ）
  loop ページを構成する各コンポーネント
    Guest->>GS: コンポーネント API（混雑／行列／天候／メッセージ）
    GS-->>Guest: 読み取りモデルから応答（表示名を付与。外部問い合わせなし）
  end
  GS->>Obs: ReportMeasurements（source=QR。ページ表示時に設置箇所単位で1回・バッチ）

  Note over GS,Op: 復旧突き合わせ（起動時・低頻度定期）: GetGuestSnapshot／ListStaffMessages を pull
```

### 2.3 匿名の仮テナント作成と所有権取得

```mermaid
sequenceDiagram
  autonumber
  participant User as 未認証ユーザー
  participant GW as Service Gateway
  participant TM as Tenant Management
  participant IdP as Auth（IdP）

  User->>GW: StartTenantRegistration（未認証）
  GW->>GW: レート制限・ボット対策
  GW->>TM: 認証メタデータなしで転送
  TM->>TM: pending_ownerの仮テナント作成<br/>取得トークンのハッシュを保存
  TM-->>User: tenant_id・所有権取得トークン・expires_at
  User->>IdP: POST /api/signup
  User->>IdP: テナント未指定のAuthorization Code Flow
  IdP-->>User: registration Access Token（scope=tenant.claim）
  User->>GW: ClaimTenantOwnership<br/>registration Token＋所有権取得トークン
  GW->>TM: 主体を維持した内部JWTへ変換して転送
  TM->>TM: トークン検証・オーナー所属・owned遷移・取得トークン消費
  TM-->>User: ownedのTenant
  User->>IdP: tenantId指定で再認可
  IdP-->>User: tenant_access
```
