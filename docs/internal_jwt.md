# 内部用 JWT 構造

内部用 JWT は、外部資格情報を検証した後に発行され、サービス間の同期呼び出しで受け渡される署名付きトークン

## 認可の軸

内部 JWT による認可は、次の 3 つの独立した軸で表す。各軸は役割が異なり、同じ概念を複数の軸へ重複して載せない。

| 軸 | 役割 | 表現 | 値の例 |
|---|---|---|---|
| 公開面 | 外部公開の可否（サービス間専用か） | `level`（メソッド宣言） | public / authenticated / internal |
| 資格情報の種別 | 出自（grant type）と付随する束縛クレーム | `token_use`（クレーム） | tenant_access / event_access / service / registration |
| 権限 | ユーザー起点の外部公開操作で実行できる操作の粒度 | `scope`（クレーム） | tenant.write / events.write / events.read |

- `token_use` は資格情報が「どう発行されたか（出自）」と、どの束縛クレーム（`tenant_id` 等）を伴うかを表す。
- `scope` は `tenant_access`、`event_access`、`registration` で「何ができるか」を表す。`service` のメソッド可否は辺ポリシーが表す。
- `token_use` の値（`tenant_access` 等）を scope 文字列として重複表現しない。
- `tenant_access`、`event_access`、`registration` の権限判定は scope、資格情報の種別判定は `token_use` が担う。
- `token_use = service` の認可は、呼び出し元ワークロードと宛先メソッドに対する Service Gateway の辺ポリシーが担う。

## 署名

- 方式: ES256（ECDSA / P-256 / SHA-256）。他の署名方式は認めない。
- 鍵: 楕円曲線 P-256 の鍵ペア。公開鍵は JWKS で配布する。
- 鍵の識別: JWT ヘッダに `kid`（鍵 ID）を必須とし、署名検証に用いる公開鍵を一意に指す。

### JWT ヘッダ

| ヘッダ | 値 | 内容 |
|---|---|---|
| `alg` | `ES256` | 署名アルゴリズム |
| `kid` | 鍵 ID（非空） | 署名鍵の識別子。対応する公開鍵を JWKS から引く |
| `typ` | `JWT` | トークン種別 |

### 公開鍵（JWKS の JWK）

公開鍵は JWKS の JWK として次の形で表現する。

| JWK メンバ | 値 | 内容 |
|---|---|---|
| `kty` | `EC` | 鍵種別（楕円曲線） |
| `crv` | `P-256` | 曲線 |
| `alg` | `ES256` | 対応署名アルゴリズム |
| `use` | `sig` | 用途（署名検証） |
| `kid` | 鍵 ID（非空） | JWT ヘッダの `kid` と対応 |
| `x` / `y` | base64url（パディングなし） | 公開鍵の座標 |

## クレーム構造

### 共通必須クレーム

すべての内部 JWT が持つクレーム。

| claim | 型 | 内容 |
|---|---|---|
| `iss` | string | 発行者識別子 |
| `sub` | string | 主体。ユーザー系は user_id、サービス系は呼び出し元サービスの識別子（マシン起点では検証済みワークロード identity のサービス識別子） |
| `aud` | string | 宛先の論理識別子（宛先サービス単位。1 トークン 1 audience） |
| `iat` | NumericDate | 発行時刻 |
| `nbf` | NumericDate | 有効化時刻 |
| `exp` | NumericDate | 失効時刻 |
| `jti` | string | 内部 JWT 自体の識別子 |
| `txn` | string | UUIDv7 の処理チェーン識別子。監査とトレースの相関専用 |
| `token_use` | string | 用途種別（下表の 4 種） |
| `client_id` | string | ユーザー系は外部トークンを提示した client。サービス系は呼び出し元サービスの識別子（`sub` と同値） |

### 起点別クレーム

`scope`、`src_jti`、`origin_sub` の要否は、トークンの起点で決まる。
持たないクレームは空文字にせず省略する。

| claim | 外部トークンの入口変換 | ユーザー起点の `service` 再発行 | マシン起点の `service` 再発行 |
|---|---|---|---|
| `scope` | 必須。外部トークンの値を転記 | 必須。文脈トークンの値を透過 | 持たない |
| `src_jti` | 必須。外部トークンの `jti` | 必須。文脈トークンの `jti` | 持たない |
| `origin_sub` | 持たない。`sub` が起点ユーザーを表す | 必須。文脈トークンにあれば透過し、最初の再発行では文脈トークンの `sub` を設定 | 持たない |

- `txn` は外部トークンの入口変換または新規マシン起点で Service Gateway が UUIDv7 を生成し、後続ホップへ透過する。
- マシン起点チェーンのサービスは、受領した `token_use = service` の内部 JWT を次ホップの文脈トークンとして提示する。
- マシン起点チェーンの次ホップでは `txn` だけを透過し、`sub` と `client_id` は現在の呼び出し元サービスへ更新する。
- マシン起点の `token_use = service` の認可根拠は辺ポリシーのみであり、`scope` を持たない。
- ユーザー起点の `service` に透過される `scope` もメソッド可否の判定には用いず、辺ポリシーが可否を決める。

### token_use と追加クレーム

`token_use` は内部 JWT の用途を表し、値に応じて追加クレームの要否が決まる。

| `token_use` | 用途 | 追加クレーム |
|---|---|---|
| `tenant_access` | テナント文脈での操作 | `tenant_id`（必須） |
| `event_access` | イベント文脈での操作 | `tenant_id`、`event_id`（いずれも必須） |
| `service` | サービス間呼び出し | ユーザー起点: `tenant_id`（および `event_id`）を文脈トークンから引き写す。マシン起点: `tenant_id`／`event_id` を持たない |
| `registration` | 仮テナントの所有権取得 | なし（`tenant_id`を持たない） |

### tenant_id／event_id クレーム

| claim | 型 | 内容 |
|---|---|---|
| `tenant_id` | string | テナント公開 ID（16 桁の　Hex　文字列）。内部 ID ではない |
| `event_id` | string | イベント公開 ID（16 桁の　Hex　文字列）。内部 ID ではない |

- `tenant_id` は `token_use = tenant_access` および `event_access` の内部 JWT に含まれ、値が非空であることを要する。
- `event_id` は `token_use = event_access` の内部 JWT に含まれ、値が非空であることを要する。
- ユーザー起点の `token_use = service` は、変換元の文脈トークンが持つ `tenant_id`／`event_id` を引き写す。
- マシン起点の `token_use = service` は文脈トークンの有無にかかわらず、`tenant_id`／`event_id` を持たない。
- 公開 ID はいずれもランダムな 16 桁十六進の文字列であり、内部で用いる UUIDv7 等の内部 ID ではない。テナント・イベント操作の識別にはこの公開 ID を用いる。
- 全サービスの proto の `tenant_id`／`event_id` フィールドも公開 ID を値に取る。クレームとフィールドは同名かつ同義であり、そのまま突合できる。内部主キー（UUIDv7）は各サービスの内部に閉じ、proto にも本クレームにも現れない。
- `registration`の内部JWTは`tenant_id`／`event_id`を持たない。
  対象テナントはClaimTenantOwnershipのリクエストと一回限りの所有権取得トークンで指定し、IdPのAccess Tokenにはテナント文脈を持たせない。

### 認可に用いてよいクレーム

- `token_use`、`tenant_id`、`event_id` は認可判定に用いる。
- `scope` は `tenant_access`、`event_access`、`registration` のメソッド認可に用いる。`token_use = service` の可否は辺ポリシーが決めるため、ユーザー起点から透過された `scope` をメソッド認可に用いない。
- `origin_sub`（起点ユーザー。ユーザー起点の `service` のみ）と `txn` は監査専用である。認可判定に用いてはならない。
- この区別は、サービス間の呼び出し可否をユーザーの権限から導出しないという方針に基づく。`tenant_id`／`event_id` は「どのデータ区画か」を表し、ユーザーの権限を表さないため認可に用いてよい。

### scope

- `scope` は空白区切りの文字列で、複数の scope を並べる。
- 内部 JWT の scope は変換元の外部トークンの scope を転記した値であり、内部で拡大・縮小しない。
- マシン起点の `token_use = service` は変換元を持たないため `scope` クレーム自体を持たない（前述「起点別クレーム」）。

## 有効期間

- 内部 JWT は短命であり、`exp` により有効期間が定まる。
- 有効期間はリプレイの窓と、鍵漏えい時に残存するトークンの寿命を規定する。
- 内部 JWT はデナイリストを持たず、失効は `exp` による自然失効に委ねる。
- Service Gateway は変換と再発行のたびに新しい `jti` を生成し、発行済み内部 JWT を再利用しない。
- `txn` の生成に永続ストアまたは中央シーケンスを使用せず、JWT 発行処理をステートレスに保つ。
- `txn` は認可、冪等性、業務識別子に使用しない。
