# 認証・認可コンテキスト

## 責務

- ユーザーアカウントのセルフ登録（テナント紐づけ前のアカウント作成）
- ユーザー認証とテナント／イベント文脈のアクセストークン発行
- 関係参照（Relation）が所属・ロールの真実の源として読み書き所有
- テナント／イベント識別子はテナントが正本で本コンテキストは参照整合

## ドメインモデル

| 語 | 内容 |
|---|---|
| ユーザー / User | IdP の認証主体 |
| 所属 / Membership | どのテナント／イベントにどのロールで属すか<br>Relation が読み書き所有 |
| `tenant_access` token | テナント文脈の JWT |
| `event_access` token | Token Exchange で発行するイベント文脈トークン |
| Token Exchange | tenant_access→event_access の一方向のみ |
| scope | tenant.read/write／events.read/write |
| resource / audience | 対象イベント（URI）／バックエンド API 全体の論理 audience（例 backend-api。登録は1つ）<br>検証は Service Gateway と Edge Bridge Service が行う |
| 所有権取得専用の最小トークン / registration token | テナント文脈なしで仮テナントの所有権を取得するためのトークン<br>scope は `tenant.claim` のみで、ClaimTenantOwnership に限定 |
| 関係参照サービス / relation service | 所属とロールを所有し参照を返す |

ロール→scope：オーナー＝全scope／スタッフ＝read系／管理者（予約）＝オーナー相当
ロールは JWT claim に載せない

## ドメインイベント

| イベント | 英語 | 契機 |
|---|---|---|
| ユーザー登録された | UserRegistered | セルフサインアップのアカウント作成（テナント紐づけ前） |
| ログインした | UserLoggedIn | ログイン成功 |
| ログイン失敗した | LoginFailed | 認証失敗 |
| ログアウトした | UserLoggedOut | ログアウト |
| テナントアクセストークン発行された | TenantAccessTokenIssued | 認可コードフロー |
| 所有権取得専用トークン発行された | RegistrationTokenIssued | テナント未指定の認可コードフロー（仮テナントの所有権取得） |
| イベントアクセストークン発行された | EventAccessTokenIssued | Token Exchange 成功 |
| トークン交換拒否された | TokenExchangeDenied | 遷移／audience／scope 違反 |
| トークン失効された | TokenRevoked | 失効要求 |
| 監査ログ記録された | AuditLogRecorded | ログイン／ログアウト／発行／交換／失効の成否 |
| ユーザーがテナントに所属した | UserJoinedTenant | メンバー追加 |
| テナントロール変更された | TenantRoleChanged | テナントロール付与・変更 |
| イベントロール付与された | EventRoleGranted | 割り当て |
| ロール剥奪された | RoleRevoked | メンバー削除／ロール解除 |
| 関係参照キャッシュ更新された | RelationCacheUpdated | 参照成功 |
| 関係参照キャッシュパージされた | RelationCachePurged | 所属変更時 |

## 不変条件

- relation model 制約：1ユーザーは複数テナントに所属しうる／event∈tenant／event-role⇒tenant-role／tenant-role と event-role は独立
- Token Exchange は tenant→event の一方向のみ
- ロールは scope 発行判定のみに使用（claim に載せない）
- 識別子はテナントが正本で存在しないIDへ所属を作らない
- イベント状態はテナントが所有し本コンテキストは持たない
