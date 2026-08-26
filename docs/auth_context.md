# 認証・認可コンテキスト 入出力整理

ドメイン定義: auth_domain.md
デプロイ単位: Auth（IdP）（IdP、OIDC 標準 HTTP）。関係参照（`tolo.relation.v1`）は tenant_management_spec.md が実装する
対象外: Auth と関係参照の間の内部インタフェース

## ドメインイベント↔入出力 対応

| ドメインイベント | 対応 |
|---|---|
| UserRegistered | Auth 独自 API: `POST /api/signup`（アカウント作成。テナント紐づけ前） |
| UserLoggedIn／LoginFailed | Auth: Discovery の `authorization_endpoint` |
| UserLoggedOut | Auth: Discovery の `end_session_endpoint` |
| TenantAccessTokenIssued | Auth: Discovery の `token_endpoint`（authorization_code） |
| RegistrationTokenIssued | Auth: Discovery の `token_endpoint`（authorization_code、テナント未指定。所有権取得専用の最小トークン） |
| EventAccessTokenIssued／TokenExchangeDenied | Auth: Discovery の `token_endpoint`（token-exchange） |
| TokenRevoked | Auth: Authorization Server Metadata の `revocation_endpoint` |
| AuditLogRecorded | Auth 内部（全操作の成否で記録） |
| UserJoinedTenant | Tenant Management: RelationAdminService.AddTenantMember |
| TenantRoleChanged | Tenant Management: RelationAdminService.ChangeTenantRole |
| EventRoleGranted | Tenant Management: RelationAdminService.GrantEventRole |
| RoleRevoked | Tenant Management: RelationAdminService.RevokeRole |
| RelationCacheUpdated／RelationCachePurged | 対象外（Auth と関係参照の間） |

## 他コンテキストとの接点

| 接点 | 対応 |
|---|---|
| 全サービスの認可 | JWT（`tenant_access`／`event_access`）＋ scope。IdP 発行 JWT は原則 Service Gateway が検証して内部 JWT へ変換し、各サービスは Service Gateway の JWKS で内部 JWT をローカル検証する（service_gateway.md）。明示例外は Edge Bridge Service で、`event_access` を直接検証する（Edge Bridge Service） |
| 識別子の参照整合（テナントが正本） | 関係参照は同一サービス（Tenant Management）内の参照で存在確認する（RPC を経ない） |
