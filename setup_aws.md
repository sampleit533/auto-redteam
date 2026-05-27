# Setup AWS — chạy red-team trên cloud thật (kill chain: recon → privesc → exfil)

Tài liệu này hướng dẫn dựng phần **Release → Deploy** còn thiếu của pipeline:
chạy một **chuỗi tấn công cloud (kill chain)** trên **AWS thật** và xác nhận
phát hiện bằng **CloudTrail thật**, với CI xác thực qua **GitHub OIDC — không
dùng key tĩnh**. Ba kịch bản được deploy (`--scenario cloud`):

| Bước | Kịch bản | MITRE | Phát hiện bằng |
|---|---|---|---|
| **Discovery** | `t8_cloud_recon` | T1580 | CloudTrail **management** events (ListUsers/Roles/Policies, GetAccountAuthorizationDetails) |
| **Privilege Escalation** | `t2_privilege_escalation` | T1078.004 | CloudTrail **management** events (CreateRole→AttachRolePolicy→CreateAccessKey) |
| **Exfiltration** | `t4_data_exfiltration` | T1530 | CloudTrail **data** events (S3 GetObject) qua CloudWatch Logs |

> Tại sao đúng 3 kịch bản? Chúng tạo thành một **kill chain** hoàn chỉnh
> (do thám → leo thang → lấy cắp dữ liệu) và cho thấy **cả hai** loại CloudTrail
> event: *management* (miễn phí, qua Event history) và *data* (cần trail + selector).

> Triết lý: chỉ **một lần** nâng quyền để dựng nền (OIDC + role + trail). Sau đó
> CI chạy hoàn toàn bằng token ngắn hạn. Mọi IAM principal T2 tạo ra đều bị một
> *permissions boundary* (Deny tất cả) vô hiệu hóa, recon chỉ **đọc**, và T4 chỉ
> đụng bucket `redteam-sandbox-*` → các API call là **thật** nhưng **bán kính
> nổ = 0**, và tự dọn sau mỗi run.

---

## 0. Kiến trúc tổng quan

```
root (Console + MFA)
   │  ① cấp AdministratorAccess TẠM cho IAM user của bạn
   ▼
IAM user (AWS CLI local)
   │  ② terraform apply infra/aws-bootstrap
   │     → OIDC provider + redteam-deploy role + redteam-sandbox-boundary
   │     + CloudTrail trail (S3 data events) → CloudWatch Logs (cho T4)
   ▼
GitHub Actions ── OIDC (web-identity token, không key) ──► assume redteam-deploy
   │  ③ workflow chạy --scenario cloud (recon → T2 → exfil) trên AWS thật
   │     → t8/t2: đọc CloudTrail lookup-events (management, us-east-1)
   │     → t4:    đọc CloudWatch Logs (S3 data events) → evaluate
   │     → runner tự cleanup IAM principals + S3 bucket
   ▼
   ④ (tùy chọn) gỡ AdministratorAccess → về zero static key
```

**CI vs CD:** ①② là chuẩn bị hạ tầng (IaC). ③ chính là **CD** — pipeline tự
deploy lên môi trường cloud thật, chạy, kiểm chứng, rồi teardown.

---

## 1. Yêu cầu trước

| Công cụ | Cài đặt |
|---|---|
| Tài khoản AWS | có quyền **root** (chủ account) |
| AWS CLI v2 | `curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o a.zip && unzip a.zip && sudo ./aws/install` |
| Terraform ≥ 1.5 | tải binary từ releases.hashicorp.com, đặt vào PATH |

Cấu hình CLI (1 lần): `aws configure` → nhập Access Key, region, output.
Kiểm tra: `aws sts get-caller-identity` ra đúng Account ID.

> ⚠️ **Không bao giờ dán Secret Access Key vào chat/log/commit.** Nếu lỡ lộ:
> `aws iam create-access-key` (tạo key mới) → `aws configure` → `aws iam
> delete-access-key --access-key-id <key-cũ>`.

---

## 2. Hardening IAM (làm trước khi bootstrap)

1. **Root**: bật MFA, **xóa hết access key của root** (root chỉ dùng Console).
2. **IAM user của bạn**: bật MFA.
3. Giữ **tối đa 1** access key đang dùng cho CLI; key nào không nhớ secret / lâu
   không dùng → xóa.

---

## 3. Bootstrap (một lần, bằng quyền admin)

### 3.1. Nâng quyền tạm

Console (đăng nhập root) → **IAM → Users → \<user của bạn\> → Add permissions →
Attach policies directly → `AdministratorAccess`**.

### 3.2. Apply Terraform

```bash
cd infra/aws-bootstrap
terraform init
terraform plan      # review các resource sẽ tạo (~12)
terraform apply     # gõ 'yes'
terraform output
```

Output (copy lại để dùng ở bước 4):

```
deploy_role_arn           = arn:aws:iam::<ACCOUNT>:role/redteam-deploy
oidc_provider_arn         = arn:aws:iam::<ACCOUNT>:oidc-provider/token.actions.githubusercontent.com
sandbox_boundary_arn      = arn:aws:iam::<ACCOUNT>:policy/redteam-sandbox-boundary
sandbox_path              = /redteam-sandbox/
cloudtrail_log_group_name = /aws/cloudtrail/redteam-sandbox
trail_arn                 = arn:aws:cloudtrail:us-east-1:<ACCOUNT>:trail/redteam-sandbox-trail
trail_bucket              = redteam-trail-logs-<ACCOUNT>
```

Bootstrap gồm 2 file: `main.tf` (nền OIDC + role + boundary) và
`cloud_scenarios.tf` (quyền recon + hạ tầng data-event cho T4). Cùng tạo:
- **OIDC provider** `token.actions.githubusercontent.com` (thumbprint lấy động).
- **Role `redteam-deploy`**: trust khóa cứng vào `repo:sampleit533/auto-redteam:*`;
  quyền scoped chặt — IAM principal dưới `/redteam-sandbox/`,
  `cloudtrail:LookupEvents`, bucket `redteam-sandbox-*`, **recon read-only**
  (ListUsers/Roles/Policies, GetAccountAuthorizationDetails), và đọc log group.
- **Permissions boundary `redteam-sandbox-boundary`** (Deny `*`).
- **CloudTrail trail `redteam-sandbox-trail`** (single-region us-east-1): advanced
  event selector bắt **S3 data events** của bucket `redteam-sandbox-*`, đẩy sang
  **CloudWatch Logs** `/aws/cloudtrail/redteam-sandbox` để T4 đọc lại gần real-time.
  Trail ghi vào bucket riêng `redteam-trail-logs-<ACCOUNT>` (không trùng prefix
  `redteam-sandbox-` để tránh tự log chính nó).

> Nếu `plan/apply` báo `AccessDenied` → chưa gắn AdministratorAccess (bước 3.1),
> hoặc IAM chưa propagate (đợi ~10s rồi chạy lại).

---

## 4. Cấu hình GitHub repo

### 4.1. Repo variables (không phải secret)

**Settings → Secrets and variables → Actions → Variables → New variable:**

| Name | Value |
|---|---|
| `AWS_DEPLOY_ROLE_ARN` | giá trị `deploy_role_arn` ở trên |
| `REDTEAM_SANDBOX_BOUNDARY_ARN` | giá trị `sandbox_boundary_arn` ở trên |

> Workflow đã có **fallback** trỏ tới ARN của account `406953137587`. Nếu bạn
> dùng đúng account đó thì có thể bỏ qua bước này; account khác thì phải set.

### 4.2. (Tùy chọn) Cổng phê duyệt thủ công

**Settings → Environments → New environment → `aws-sandbox`** → bật
**Required reviewers** (chọn chính bạn). Mỗi lần chạy real-cloud sẽ phải bấm
approve — rất hợp với câu chuyện DevSecOps "deploy lên prod cần gate".

---

## 5. Chạy

### 5.1. Tự động — pipeline CI/CD liên tục (khuyến nghị)

Workflow **`RedTeam — CI/CD Pipeline`** (`redteam-pipeline.yml`) chạy **tự động**
mỗi khi `push` / mở `pull_request` vào `main`:

```
push / PR ─► Code (lint + gitleaks) ─► Build & Test (cloud chain trên LocalStack, gate 100%)
                                              │
                              push vào main ──┘─► Deploy (cloud chain trên AWS thật)
```

- **Code**: `flake8` (chặn lỗi syntax/undefined) + quét secret bằng `gitleaks`.
- **Build & Test**: dựng LocalStack, chạy `--scenario cloud` (**recon → T2 → exfil**)
  trên **cloud giả**, `evaluate`, và **gate**: cả 3 kịch bản phải đạt coverage =
  100% mới qua. Phản hồi nhanh, **$0**, không đụng AWS.
- **Deploy**: **chỉ khi push vào `main`** và Test đã xanh → gọi lại workflow
  `redteam-cloud-deploy.yml` (reusable) để **promote đúng 3 kịch bản đó lên AWS
  thật**, qua cổng phê duyệt `aws-sandbox` (mục 4.2).

> Triết lý "shift-left → promote": cùng một chuỗi kịch bản được kiểm trên cloud
> **giả** ở mọi thay đổi, rồi mới lên cloud **thật** khi merge — đúng mô hình CI→CD.

> ⚠️ Vì vậy **mỗi lần push vào `main` sẽ kích hoạt deploy lên AWS thật**. Muốn
> chặn lại bằng tay → bật **Required reviewers** cho environment `aws-sandbox`
> (mục 4.2); khi đó deploy sẽ đợi bạn bấm *approve*.

### 5.2. Thủ công — chỉ chạy riêng stage Deploy

**Actions → "RedTeam — Cloud Deploy (real AWS, OIDC)" → Run workflow:**
- `approval_ticket`: mã ticket bất kỳ (bắt buộc, để audit).
- `cloudtrail_timeout`: mặc định `900` (giây) — CloudTrail trễ ~5–15 phút.

Stage Deploy (dù chạy tự động hay thủ công) sẽ:
1. Assume `redteam-deploy` qua OIDC → `aws sts get-caller-identity` xác nhận.
2. Chạy `--scenario cloud` trên AWS thật (`REDTEAM_CLOUD_MODE=aws`):
   **t8** (recon read-only) → **t2** (privesc) → **t4** (bulk S3 read).
3. Đọc lại observable **thật**:
   - t8/t2 → CloudTrail `lookup-events` (management, us-east-1).
   - t4 → CloudWatch Logs `/aws/cloudtrail/redteam-sandbox` (S3 data events).
4. `evaluate_results.py` tính coverage từ observable **thật**.
5. Runner tự cleanup (IAM principals + S3 bucket); step "Sweep" dọn nốt
   principals **và** bucket `redteam-sandbox-*` nếu job bị hủy giữa chừng.

---

## 6. Chạy thử ở local (không qua CI)

```bash
export REDTEAM_CLOUD_MODE=aws
export REDTEAM_SANDBOX_BOUNDARY_ARN=arn:aws:iam::<ACCOUNT>:policy/redteam-sandbox-boundary
export AWS_REGION=us-east-1
export REDTEAM_TRAIL_LOG_GROUP=/aws/cloudtrail/redteam-sandbox   # cho t4 data events
export REDTEAM_CLOUDTRAIL_TIMEOUT=900     # tùy chỉnh
# Cả chuỗi (recon → T2 → exfil); hoặc thay 'cloud' bằng 1 ID để chạy riêng.
python runners/simulate.py --scenario cloud \
  --mode safe --run-id local-$(date +%s) --output artifacts/results.json
python evaluation/evaluate_results.py --results artifacts/results.json \
  --mappings evaluation/expected_mappings.yaml --out artifacts/evaluation.json
```

> 💡 Chạy local bằng IAM user admin (vd. `huy.ngovinh`) cũng được — khi đó recon
> tự scope CloudTrail theo **username** thay vì session name `redteam-<run_id>`
> (CI). Mọi thứ vẫn tự dọn và bán kính nổ vẫn = 0.

Các biến môi trường cloud-mode đọc:

| Biến | Ý nghĩa | Mặc định |
|---|---|---|
| `REDTEAM_CLOUD_MODE` | `aws` → AWS thật; khác → LocalStack | (LocalStack) |
| `REDTEAM_SANDBOX_BOUNDARY_ARN` | **bắt buộc** cho T2 ở cloud mode | — |
| `REDTEAM_SANDBOX_PATH` | path tạo principal (T2) | `/redteam-sandbox/` |
| `REDTEAM_TRAIL_LOG_GROUP` | log group đọc S3 data events (T4) | `/aws/cloudtrail/redteam-sandbox` |
| `REDTEAM_CLOUDTRAIL_REGION` | region đọc CloudTrail | `us-east-1` |
| `REDTEAM_CLOUDTRAIL_TIMEOUT` | tổng thời gian chờ (giây) | `900` |
| `REDTEAM_CLOUDTRAIL_INTERVAL` | nhịp poll (giây) | `30` |

> **Tại sao us-east-1?** IAM/STS là *global service*; CloudTrail ghi event của
> chúng ở `us-east-1` bất kể bạn ở region nào. Query nhầm region → không thấy event.

---

## 7. Chi phí & an toàn

| Hạng mục | Chi phí |
|---|---|
| OIDC provider, IAM role/policy/boundary | **$0** |
| Management events (t8 recon + t2) + `lookup-events` | **$0** (CloudTrail Event history miễn phí, lưu 90 ngày) |
| t8 + t2 mỗi run | **$0** (chỉ đọc / tạo-xóa IAM, không tốn) |
| **Data events (t4)** + CloudWatch Logs | ~**$0.10 / 100k** event; ~200 event/run + log nhỏ ≈ **$0** |
| S3 trong t4 | **$0** (tạo/đọc/xóa vài trăm object 256B trong cùng run) |

> ⚠️ Khác T2: trail data-event là **dịch vụ trả phí theo lượng**. Quy mô ở đây
> (~200 event/run, log lưu 7 ngày) gần như $0, nhưng đừng nhân read_count lên
> hàng triệu. Trail là single-region (us-east-1) nên không nhân chi phí đa vùng.

**Bật cảnh báo ngân sách** (rất nên, vì bạn chỉ có $100 credit):

```bash
# Console: Billing → Budgets → Create budget → Zero spend / Monthly $5
```

An toàn:
- **t8 (recon)**: chỉ các call **read-only** (List/Get); không tạo/sửa/xóa gì.
- **t2 (privesc)**: mọi principal tạo ra mang **boundary Deny-all** + path
  `/redteam-sandbox/`; deploy role **chỉ** đụng được path này → vô hại cả khi lộ key.
- **t4 (exfil)**: chỉ đụng bucket `redteam-sandbox-*` của chính nó; dữ liệu là
  object rác sinh tại chỗ, **không** rời sandbox (sink = chính bucket đó).
- Runner cleanup + workflow sweep (principals **và** bucket) → không để lại rác.
- Runner **không in/không trả về** secret access key.

---

## 8. Data events — T4 (S3 GetObject) [đã làm ✓]

T4 đọc/ghi S3. Khác T2 ở chỗ **`GetObject`/`PutObject` là *data events***:
CloudTrail **không** ghi mặc định và `lookup-events` **không** trả về. Để
detection của T4 cũng **thật** như T2, hạ tầng đã dựng:

1. **CloudTrail trail** `redteam-sandbox-trail` với **advanced event selector**
   `resources.ARN starts_with arn:aws:s3:::redteam-sandbox-` bắt S3 data events
   (cả read lẫn write). Dùng *advanced* vì basic selector chỉ nhận ARN bucket
   đầy đủ, không nhận prefix tên bucket.
2. Trail đẩy data events sang **CloudWatch Logs** `/aws/cloudtrail/redteam-sandbox`
   (gần real-time, thường < vài phút).
3. `runners/scenarios/s3log_util.py` đọc lại bằng `logs:FilterLogEvents`, lọc
   theo tên bucket của run (data event không mang `run_id`), trả về observable
   `s3_access_log` — **derive từ AWS, không self-report** (giống `cloudtrail_util`).

Trail là **single-region us-east-1** → T4 runner luôn tạo bucket ở us-east-1.
Bucket log của trail (`redteam-trail-logs-<ACCOUNT>`) cố tình **không** mang
prefix `redteam-sandbox-` để selector không tự log chính nó.

**Recon (t8)** dùng cùng cơ chế T2 (management events, `lookup-events`) nhưng
vì các call read-only **không nhúng `run_id`** vào tài nguyên nào, nó scope theo
**định danh phiên của caller** (`redteam-<run_id>` trong CI, hoặc username khi
chạy local) — xem `runners/scenarios/t8_cloud_recon.py`.

---

## 9. Teardown

```bash
# Xóa toàn bộ hạ tầng bootstrap (OIDC + role + boundary + trail + log group + bucket)
cd infra/aws-bootstrap && terraform destroy

# (tùy chọn) gỡ AdministratorAccess khỏi IAM user của bạn — về zero static key
aws iam detach-user-policy --user-name <user> \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```
