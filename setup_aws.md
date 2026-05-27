# Setup AWS — chạy red-team trên cloud thật (T2 IAM + CloudTrail)

Tài liệu này hướng dẫn dựng phần **Release → Deploy** còn thiếu của pipeline:
chạy kịch bản **T2 (privilege escalation)** trên **AWS IAM thật** và xác nhận
phát hiện bằng **CloudTrail thật**, với CI xác thực qua **GitHub OIDC — không
dùng key tĩnh**.

> Triết lý: chỉ **một lần** nâng quyền để dựng nền (OIDC + role). Sau đó CI
> chạy hoàn toàn bằng token ngắn hạn. Mọi resource T2 tạo ra đều bị một
> *permissions boundary* (Deny tất cả) vô hiệu hóa → "leo thang đặc quyền" là
> chuỗi API call **thật** nhưng **bán kính nổ = 0**, và tự dọn sau mỗi run.

---

## 0. Kiến trúc tổng quan

```
root (Console + MFA)
   │  ① cấp AdministratorAccess TẠM cho IAM user của bạn
   ▼
IAM user (AWS CLI local)
   │  ② terraform apply infra/aws-bootstrap
   │     → OIDC provider + redteam-deploy role + redteam-sandbox-boundary
   ▼
GitHub Actions ── OIDC (web-identity token, không key) ──► assume redteam-deploy
   │  ③ workflow chạy T2: CreateRole→AttachRolePolicy→CreateAccessKey (IAM thật)
   │     → đọc CloudTrail lookup-events (us-east-1) → evaluate
   │     → runner tự cleanup IAM resources
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
terraform plan      # review: 4 resource sẽ tạo
terraform apply     # gõ 'yes'
terraform output
```

Output (copy lại để dùng ở bước 4):

```
deploy_role_arn      = arn:aws:iam::<ACCOUNT>:role/redteam-deploy
oidc_provider_arn    = arn:aws:iam::<ACCOUNT>:oidc-provider/token.actions.githubusercontent.com
sandbox_boundary_arn = arn:aws:iam::<ACCOUNT>:policy/redteam-sandbox-boundary
sandbox_path         = /redteam-sandbox/
```

Module này tạo:
- **OIDC provider** `token.actions.githubusercontent.com` (thumbprint lấy động).
- **Role `redteam-deploy`**: trust khóa cứng vào `repo:sampleit533/auto-redteam:*`;
  quyền scoped chặt — chỉ IAM principal dưới `/redteam-sandbox/`,
  `cloudtrail:LookupEvents`, và bucket `redteam-sandbox-*`.
- **Permissions boundary `redteam-sandbox-boundary`** (Deny `*`).

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

**Actions → "RedTeam — Cloud Deploy (real AWS, OIDC)" → Run workflow:**
- `approval_ticket`: mã ticket bất kỳ (bắt buộc, để audit).
- `cloudtrail_timeout`: mặc định `900` (giây) — CloudTrail trễ ~5–15 phút.

Workflow sẽ:
1. Assume `redteam-deploy` qua OIDC → `aws sts get-caller-identity` xác nhận.
2. Chạy T2 trên IAM thật (`REDTEAM_CLOUD_MODE=aws`).
3. Poll CloudTrail `lookup-events` (us-east-1) tới khi đủ 3 event
   (CreateRole / AttachRolePolicy / CreateAccessKey) hoặc hết timeout.
4. `evaluate_results.py` tính coverage từ observable **thật**.
5. Runner tự cleanup; step "Sweep" dọn nốt nếu job bị hủy giữa chừng.

---

## 6. Chạy thử ở local (không qua CI)

```bash
export REDTEAM_CLOUD_MODE=aws
export REDTEAM_SANDBOX_BOUNDARY_ARN=arn:aws:iam::<ACCOUNT>:policy/redteam-sandbox-boundary
export AWS_REGION=us-east-1
export REDTEAM_CLOUDTRAIL_TIMEOUT=900     # tùy chỉnh
python runners/simulate.py --scenario t2_privilege_escalation \
  --mode safe --run-id local-$(date +%s) --output artifacts/results.json
python evaluation/evaluate_results.py --results artifacts/results.json \
  --mappings evaluation/expected_mappings.yaml --out artifacts/evaluation.json
```

Các biến môi trường T2 cloud-mode đọc:

| Biến | Ý nghĩa | Mặc định |
|---|---|---|
| `REDTEAM_CLOUD_MODE` | `aws` → IAM thật; khác → LocalStack | (LocalStack) |
| `REDTEAM_SANDBOX_BOUNDARY_ARN` | **bắt buộc** ở cloud mode | — |
| `REDTEAM_SANDBOX_PATH` | path tạo principal | `/redteam-sandbox/` |
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
| Management events (T2) + `lookup-events` | **$0** (CloudTrail Event history miễn phí, lưu 90 ngày) |
| T2 mỗi run | **$0** (tạo/xóa IAM, không tốn) |

**Bật cảnh báo ngân sách** (rất nên, vì bạn chỉ có $100 credit):

```bash
# Console: Billing → Budgets → Create budget → Zero spend / Monthly $5
```

An toàn:
- Mọi principal T2 tạo đều mang **boundary Deny-all** → vô hại kể cả nếu key lộ.
- Tạo dưới path `/redteam-sandbox/`; deploy role **chỉ** đụng được path này.
- Runner cleanup + workflow sweep → không để lại rác.
- T2 runner **không in/không trả về** secret access key.

---

## 8. Phase 2 — T4 (S3 data events) [chưa làm]

T4 đọc/ghi S3. Khác T2 ở chỗ **`GetObject`/`PutObject` là *data events***:
CloudTrail **không** ghi mặc định và `lookup-events` **không** trả về. Muốn
detection thật cho T4 cần:

1. Một **CloudTrail trail** bật *S3 data event selector* trỏ vào bucket
   `redteam-sandbox-*` (giá ~$0.10/100k event — 200 event/run ≈ $0).
2. Đẩy data event sang **CloudWatch Logs** rồi query Logs Insights (gần
   real-time), hoặc parse file log trong S3 đích (trễ vài phút).
3. Viết `runners/scenarios/s3log_util.py` tương tự `cloudtrail_util.py`.

Deploy role đã có sẵn quyền `s3:*` trên `redteam-sandbox-*` để chạy phần này.
Terraform cho trail sẽ đặt ở `infra/aws-bootstrap` (hoặc module riêng).

---

## 9. Teardown

```bash
# Xóa toàn bộ hạ tầng bootstrap (OIDC + role + boundary)
cd infra/aws-bootstrap && terraform destroy

# (tùy chọn) gỡ AdministratorAccess khỏi IAM user của bạn — về zero static key
aws iam detach-user-policy --user-name <user> \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```
