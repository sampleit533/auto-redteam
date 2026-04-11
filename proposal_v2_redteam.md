# PROPOSAL ĐỒ ÁN TỐT NGHIỆP

---

## I. Tên Đề Tài

**Red Team Automation trong Pipeline CI/CD — Tích hợp kiểm thử tấn công tự động và báo cáo DevSecOps**

---

## II. Mục Tiêu

### 2.1 Mục tiêu tổng quát

Xây dựng một hệ thống tự động hóa kiểm thử bảo mật theo phong cách red team, tích hợp trực tiếp vào pipeline CI/CD ở mức mô phỏng học thuật, nhằm kiểm chứng khả năng phát hiện tấn công (detection validation) trong môi trường sandbox/lab cách ly. Mục tiêu của đồ án là minh họa tư duy DevSecOps và Scenario-as-Code, không nhắm tới triển khai production.

### 2.2 Mục tiêu cụ thể

**Về kỹ thuật:**

- Thiết kế và triển khai pipeline CI/CD có khả năng tự động khởi chạy, giám sát và dọn dẹp các kịch bản tấn công mô phỏng trên môi trường sandbox cách ly.
- Tích hợp tối thiểu 2 kịch bản TTP theo chuẩn MITRE ATT&CK ở mức end-to-end; các kịch bản còn lại được mô tả như hướng mở rộng học thuật.
- Xây dựng evaluator tự động so khớp telemetry/observables thu được với expected detections, tính toán detection coverage và cửa sổ phát hiện của chuỗi sự kiện.
- Tạo báo cáo HTML tự động sau mỗi lần chạy; các tích hợp như Slack/JIRA chỉ được xem là phần mở rộng, không phải hạng mục bắt buộc của đồ án.
- Đảm bảo hạ tầng sandbox có thể tạo và dọn dẹp tự động bằng Docker Compose và Terraform ở mức lab.

**Về học thuật:**

- Giúp sinh viên hiểu và vận dụng thực tế khung MITRE ATT&CK trong detection engineering.
- Trải nghiệm mô hình DevSecOps shift-left: đưa kiểm thử bảo mật vào sớm trong vòng đời phát triển phần mềm.
- Rèn luyện kỹ năng vận hành cloud infrastructure ở mức mô phỏng (Terraform), container orchestration (Docker), viết automation scripts (Python, Bash) và tổ chức artifacts đánh giá phục vụ học tập.

---

## III. Giải Pháp Đề Xuất

### 3.1 Vấn đề cần giải quyết

Trong mô hình DevSecOps hiện đại, các tổ chức liên tục deploy phần mềm mới nhưng hiếm khi kiểm chứng xem những thay đổi đó có làm hỏng các detection rules hay EDR signatures hiện có hay không. Red teaming thủ công tốn kém, không reproducible và không thể chạy liên tục theo từng sprint. Hậu quả là detection gap âm thầm tồn tại sau mỗi lần cập nhật hạ tầng mà không ai biết cho đến khi bị tấn công thật.

### 3.2 Hướng tiếp cận

Giải pháp đề xuất là mô hình **Continuous Detection Validation** — tức là đưa việc kiểm chứng khả năng phát hiện tấn công vào pipeline CI/CD như một giai đoạn tự động, song song với các bước test và deploy thông thường. Cụ thể:

- **Shift-left detection testing**: Thay vì chờ đến khi có sự cố, hệ thống chủ động tạo ra các tín hiệu tấn công có kiểm soát trong môi trường sandbox để kiểm chứng logic phát hiện.
- **Infrastructure as Code cho sandbox**: Môi trường thử nghiệm được tạo và dọn dẹp tự động bằng Terraform hoặc Docker Compose ở mức lab, đảm bảo cách ly và dễ tái lập.
- **Scenario-as-Code**: Mỗi kịch bản tấn công được định nghĩa bằng file YAML có version control, đảm bảo reproducibility và auditability.
- **Automated evaluation**: Một Python evaluator tự động đọc artifacts sinh ra sau mỗi lần chạy, so khớp observables với expected mapping, và tính toán coverage metrics.

### 3.3 Phạm vi

| | Chi tiết |
|---|---|
| **Trong phạm vi** | Môi trường sandbox/test cách ly, 2 kịch bản TTP triển khai hoàn chỉnh, pipeline GitHub Actions, báo cáo HTML tự động, evaluator dựa trên observables |
| **Ngoài phạm vi** | Production environment, khai thác lỗ hổng thật, external network targets, malware, Slack/JIRA production integration, SIEM enterprise hoàn chỉnh |

### 3.4 Giới hạn theo phạm vi học phần

Vì đây là đồ án phục vụ môn học đại học, đề tài được giới hạn ở mức **prototype học thuật có thể demo được**, thay vì một nền tảng red team automation hoàn chỉnh cho doanh nghiệp. Do đó:

- Trọng tâm là minh họa kiến trúc, quy trình CI/CD, cách mô tả kịch bản bằng YAML, cơ chế cleanup, và cách đánh giá kết quả tự động.
- Mức hoàn thành cốt lõi của đồ án là **2 kịch bản chạy end-to-end**: `T1` và `T2`.
- Các thành phần như ELK đầy đủ, Kibana dashboard, Slack/JIRA, Vault, private registry, image scanning, Zeek/Suricata được xem là **hướng mở rộng tham khảo**, không phải tiêu chí bắt buộc để chấm đạt.
- Đánh giá detection trong bản đồ án tập trung vào **simulation observables** và **mapping logic**, thay vì yêu cầu tích hợp SIEM production-grade.

---

## IV. Phương Pháp Thực Hiện

### 4.1 Kiến trúc tổng thể

Hệ thống được thiết kế theo mô hình pipeline tuyến tính gồm các giai đoạn tuần tự:

```
[Trigger] → [Provision Infra] → [Deploy Targets] → [Simulate Attacks]
         → [Collect Telemetry] → [Evaluate Detections] → [Report + Teardown]
```

Trong prototype hiện tại, phần orchestration chính được thực hiện bằng GitHub Actions với chế độ chạy thủ công (`workflow_dispatch`) và chạy theo lịch (`nightly`). Một số giai đoạn có thể gộp trong cùng một job để đơn giản hóa triển khai trong phạm vi môn học.

### 4.2 Các bước triển khai

**Bước 1 — Chính sách & phê duyệt**

Trước khi viết bất kỳ dòng code nào, cần thiết lập quy trình phê duyệt: danh sách kịch bản được phép chạy, mẫu approval form có chữ ký của instructor và lab owner, cửa sổ thời gian cho phép, và cơ chế kill-switch để dừng khẩn cấp. Đây là yêu cầu bắt buộc về đạo đức và pháp lý.

**Bước 2 — Hạ tầng sandbox**

Thiết kế môi trường cách ly bằng Terraform: isolated VPC/VLAN, ephemeral namespaces trong Docker network, test accounts với quyền hạn tối thiểu, không có public endpoint. Toàn bộ hạ tầng được tạo mới trước mỗi phiên chạy và xóa hoàn toàn sau khi xong.

```hcl
# Ví dụ cấu hình Terraform cho sandbox network
resource "docker_network" "redteam_sandbox" {
  name     = "rt-sandbox-${var.run_id}"
  internal = true   # Không có internet access
}
```

**Bước 3 — Target workloads**

Deploy các dịch vụ mục tiêu bằng Docker Compose: SSH server và mock IAM service. Các target khác như mock S3 hay dịch vụ phục vụ T3-T6 được xem là phần mở rộng.

**Bước 4 — Containerized simulation runners**

Build Docker image từ base Kali Linux hoặc dùng Python runner cục bộ trong CI, chỉ cài đặt các công cụ đã được phê duyệt cho mục đích mô phỏng học thuật. Mỗi kịch bản chỉ sinh ra observable telemetry, không exploit lỗ hổng thật.

**Bước 5 — Orchestration pipeline**

GitHub Actions thực hiện các bước: validate-approval → start sandbox targets → simulate → evaluate → report → teardown. Job teardown luôn chạy dù các bước trước có fail hay không (`if: always()`).

**Bước 6 — Thu thập telemetry**

Filebeat được giữ như thành phần tham khảo cho hướng mở rộng telemetry. Trong phiên bản hiện tại của đồ án, evaluator chủ yếu sử dụng các observables được runner ghi nhận trực tiếp; các nguồn như Elasticsearch, Zeek hay tshark không phải điều kiện bắt buộc để demo thành công.

**Bước 7 — Evaluation & mapping**

Python evaluator đọc file `expected_mappings.yaml`, so khớp observables trong `results.json`, và tính detection coverage cho từng scenario. Với các kịch bản dạng chuỗi như T2, evaluator còn kiểm tra cửa sổ thời gian và principal của các event trong cùng một sequence.

**Bước 8 — Báo cáo & thông báo**

Script Python dùng Jinja2 render HTML report từ `evaluation.json`. Trong phạm vi đồ án môn học, báo cáo HTML artifact là đầu ra chính; các tích hợp thông báo tự động như Slack/JIRA chỉ được nêu như khả năng mở rộng trong tương lai.

**Bước 9 — Dọn dẹp**

`terraform destroy` hoặc bước teardown trong GitHub Actions xóa các tài nguyên sandbox. Docker resources tạm thời bị dọn dẹp sau khi chạy. Artifacts chỉ chứa dữ liệu mô phỏng và không bao gồm thông tin nhạy cảm thật.

### 4.3 Cấu trúc repository

```
redteam-automation/
├── .github/workflows/
│   ├── redteam-on-demand.yml       # Manual trigger + approval gate
│   └── redteam-scheduled.yml       # Nightly baseline
├── scenarios/                       # Kịch bản YAML (versioned)
│   ├── T1_bruteforce_ssh.yaml
│   ├── T2_privilege_escalation.yaml
│   └── ...
├── runners/
│   ├── Dockerfile                   # Kali-based simulation image
│   └── simulate.py                  # Entry point
├── infra/                           # Terraform sandbox templates
├── targets/
│   └── docker-compose.yml           # Target workloads
├── collection/
│   └── filebeat.yml
├── evaluation/
│   ├── evaluate_results.py
│   └── expected_mappings.yaml       # TTP → SIEM alert mapping
├── reporting/
│   ├── generate_report.py
│   └── templates/report.html.j2
└── docs/
    ├── approval_form.md
    ├── runbook.md
    └── kill_switch.md
```

### 4.4 Tám giai đoạn thực hiện chi tiết

Thay vì chia theo tuần, đồ án được trình bày theo **8 giai đoạn triển khai**. Mỗi giai đoạn đều nêu rõ mục tiêu, phần code tương ứng trong repo, và trạng thái hiện tại của codebase.

| Giai đoạn | Nội dung chính | Phần code tương ứng trong repo | Trạng thái hiện tại |
|---|---|---|---|
| **1. Xác định phạm vi và an toàn** | Xác định đây là đồ án học thuật, chỉ chạy trong sandbox/lab; xây dựng approval form, runbook, kill-switch; xác định nguyên tắc non-destructive | `docs/approval_form.md`, `docs/runbook.md`, `docs/kill_switch.md`, `README.md`, `proposal_v2_redteam.md` | **Đã hoàn thành** |
| **2. Thiết kế kiến trúc và tổ chức repo** | Thiết kế pipeline tổng quát, cấu trúc thư mục, chuẩn Scenario-as-Code, format artifacts | `README.md`, `runners/simulate.py`, `scenarios/`, `evaluation/`, `reporting/`, `.github/workflows/` | **Đã hoàn thành** |
| **3. Xây dựng môi trường sandbox** | Tạo môi trường cô lập cho SSH và IAM; thiết lập Docker Compose và Terraform ở mức lab; hỗ trợ teardown | `targets/docker-compose.yml`, `infra/main.tf`, `collection/filebeat.yml` | **Đã hoàn thành ở mức prototype** |
| **4. Xây dựng simulation runners** | Xây dựng runner chung và các runner riêng cho T1, T2; chuẩn hóa observables đầu ra | `runners/simulate.py`, `runners/scenarios/t1_bruteforce.py`, `runners/scenarios/t2_priv_escalation.py`, `scenarios/T1_bruteforce_ssh.yaml`, `scenarios/T2_privilege_escalation.yaml` | **Đã hoàn thành cho T1 và T2** |
| **5. Xây dựng mapping và evaluator** | Xây dựng expected mappings; đánh giá detection coverage; kiểm tra event sequence cho T2 | `evaluation/expected_mappings.yaml`, `evaluation/evaluate_results.py` | **Đã hoàn thành cho T1 và T2** |
| **6. Xây dựng reporting và artifacts** | Sinh `results.json`, `evaluation.json`, `report.html`; chuẩn hóa nội dung báo cáo HTML | `reporting/generate_report.py`, `reporting/templates/report.html.j2`, `reporting/make_eval_stub.py`, `docs/reports/` | **Đã hoàn thành** |
| **7. Tích hợp CI/CD và chạy thực nghiệm** | Tạo workflow on-demand và scheduled; tích hợp simulate → evaluate → report → upload artifacts → teardown; chạy thử safe-mode | `.github/workflows/redteam-on-demand.yml`, `.github/workflows/redteam-scheduled.yml`, `docs/reports/t2-safe-run-2026-04-08.md` | **Đã hoàn thành cho luồng T1/T2** |
| **8. Hoàn thiện tài liệu và định hướng mở rộng** | Đồng bộ proposal với implementation; ghi rõ phần đã làm, phần mở rộng; chuẩn bị cho báo cáo/slide/demo | `proposal_v2_redteam.md`, `docs/reports/proposal-gap-review-2026-04-08.md`, `README.md` | **Đang ở giai đoạn này** |

#### Diễn giải chi tiết từng giai đoạn

**Giai đoạn 1 — Xác định phạm vi và an toàn**

- Mục tiêu là đặt ranh giới rõ ràng: chỉ làm trong sandbox, chỉ mô phỏng non-destructive, không hướng tới production.
- Giai đoạn này tạo nền cho toàn bộ đồ án vì giúp proposal, code và demo đi cùng một phạm vi.
- Phần code/tài liệu tương ứng:
  - `docs/approval_form.md`
  - `docs/runbook.md`
  - `docs/kill_switch.md`
  - `README.md`
  - `proposal_v2_redteam.md`

**Giai đoạn 2 — Thiết kế kiến trúc và tổ chức repo**

- Mục tiêu là xác định luồng làm việc chính: trigger → simulate → evaluate → report → teardown.
- Chuẩn hóa cách tổ chức repo để mỗi thành phần có trách nhiệm riêng, dễ trình bày và dễ mở rộng.
- Phần code tương ứng:
  - `runners/simulate.py`
  - `scenarios/`
  - `evaluation/`
  - `reporting/`
  - `.github/workflows/`
  - `README.md`

**Giai đoạn 3 — Xây dựng môi trường sandbox**

- Mục tiêu là tạo hạ tầng thử nghiệm đủ cho T1 và T2, nhưng vẫn gọn trong phạm vi môn học.
- SSH target phục vụ brute-force simulation; LocalStack IAM phục vụ chuỗi API của T2.
- Phần code tương ứng:
  - `targets/docker-compose.yml`
  - `infra/main.tf`
  - `collection/filebeat.yml`

**Giai đoạn 4 — Xây dựng simulation runners**

- Đây là giai đoạn biến ý tưởng thành logic mô phỏng có thể chạy được.
- Một runner chung tải scenario YAML và gọi runner tương ứng; mỗi scenario có module riêng.
- Phần code tương ứng:
  - `runners/simulate.py`
  - `runners/scenarios/t1_bruteforce.py`
  - `runners/scenarios/t2_priv_escalation.py`
  - `scenarios/T1_bruteforce_ssh.yaml`
  - `scenarios/T2_privilege_escalation.yaml`

**Giai đoạn 5 — Xây dựng mapping và evaluator**

- Mục tiêu là đánh giá được kết quả mô phỏng bằng quy tắc rõ ràng, thay vì chỉ chạy xong rồi dừng lại.
- T2 yêu cầu evaluator kiểm tra cả event sequence, principal, và cửa sổ thời gian.
- Phần code tương ứng:
  - `evaluation/expected_mappings.yaml`
  - `evaluation/evaluate_results.py`

**Giai đoạn 6 — Xây dựng reporting và artifacts**

- Mục tiêu là tạo đầu ra dễ đọc cho giảng viên và nhóm thực hiện: JSON để máy xử lý, HTML để con người xem.
- Các artifact cũng là bằng chứng thực nghiệm cho phần demo và viết báo cáo môn học.
- Phần code tương ứng:
  - `reporting/generate_report.py`
  - `reporting/templates/report.html.j2`
  - `reporting/make_eval_stub.py`
  - `docs/reports/`

**Giai đoạn 7 — Tích hợp CI/CD và chạy thực nghiệm**

- Giai đoạn này nối toàn bộ các phần trước thành một luồng CI/CD hoàn chỉnh.
- Đây cũng là nơi kiểm chứng thực tế xem proposal có khớp với implementation hay không.
- Phần code tương ứng:
  - `.github/workflows/redteam-on-demand.yml`
  - `.github/workflows/redteam-scheduled.yml`
  - `docs/reports/t2-safe-run-2026-04-08.md`

**Giai đoạn 8 — Hoàn thiện tài liệu và định hướng mở rộng**

- Mục tiêu là làm cho proposal, README và trạng thái implementation thống nhất với nhau.
- Đồng thời phân tách rõ những gì đã hoàn thành và những gì chỉ là hướng nghiên cứu tiếp theo.
- Phần code/tài liệu tương ứng:
  - `proposal_v2_redteam.md`
  - `README.md`
  - `docs/reports/proposal-gap-review-2026-04-08.md`

#### Codebase hiện tại đang ở giai đoạn nào

Tại thời điểm hiện tại, codebase đã **hoàn thành giai đoạn 1 đến 7** và đang ở **giai đoạn 8**:

- Về triển khai kỹ thuật: đã có pipeline, sandbox, runners, evaluator, reporting, và ít nhất một lần chạy `safe-mode` thành công cho `T2`.
- Về tài liệu: đang hoàn thiện proposal theo đúng phạm vi học thuật, đồng bộ với repo hiện tại.
- Về mở rộng: `T3` đến `T6` vẫn nên được giữ ở mức đề xuất, không nên trình bày như phần đã làm xong.

---

## V. Các Kịch Bản

Tất cả các kịch bản đều **non-destructive** — chỉ tạo ra observable telemetry mà không gây hại thực tế. Trong phạm vi bản đồ án hiện tại, `T1` và `T2` đã được triển khai end-to-end; `T3` đến `T6` là danh mục mở rộng được đề xuất để phát triển tiếp nếu còn thời gian.

---

### Kịch bản T1 — SSH Brute-force Simulation

| Trường | Nội dung |
|---|---|
| **MITRE TTP** | T1110.001 — Brute Force: Password Guessing |
| **Mô tả** | Gửi 50 lần xác thực SSH thất bại liên tiếp, sau đó 1 lần thành công bằng test account đã được tạo sẵn. |
| **Mục tiêu phát hiện** | SIEM phải trigger rule SSH brute-force detection trong vòng 10 phút. |
| **Expected telemetry** | `Failed password` xuất hiện ≥ 40 lần trong auth.log; `Accepted password` xuất hiện 1 lần; SIEM alert rule `SSH_BRUTEFORCE_DETECTION` được kích hoạt. |
| **Phương pháp** | Script Python dùng Paramiko gửi auth attempts với interval 2 giây, không làm gián đoạn dịch vụ. |

---

### Kịch bản T2 — Privilege Escalation (IAM)

| Trường | Nội dung |
|---|---|
| **MITRE TTP** | T1078.004 — Valid Accounts: Cloud Accounts |
| **Mô tả** | Mô phỏng chuỗi API calls đặc trưng của privilege escalation: create-role → attach-policy → create-access-key, thực hiện trên sandbox IAM không có quyền thật. |
| **Mục tiêu phát hiện** | SIEM/CloudTrail phải phát hiện chuỗi API calls bất thường trong thời gian ngắn. |
| **Expected telemetry** | CloudTrail logs ghi 3 events liên tiếp: `CreateRole`, `AttachRolePolicy`, `CreateAccessKey` từ cùng một principal trong < 5 phút. |
| **Phương pháp** | Boto3 (AWS SDK) gọi API trên sandbox IAM account với synthetic credentials. |

---

### Kịch bản T3 — Lateral Movement Pattern

| Trường | Nội dung |
|---|---|
| **MITRE TTP** | T1021 — Remote Services |
| **Mô tả** | Từ một container, thực hiện kết nối tuần tự đến nhiều hosts trong cùng subnet để mô phỏng hành vi di chuyển ngang. |
| **Mục tiêu phát hiện** | NIDS phát hiện một nguồn kết nối đến nhiều đích trong thời gian ngắn (nhiều connection events từ một IP). |
| **Expected telemetry** | Zeek logs ghi ≥ 5 connection events từ cùng source IP đến các destination IPs khác nhau trong subnet trong < 3 phút. |
| **Phương pháp** | Script Bash dùng `nc` hoặc `curl` kết nối tuần tự đến các container targets trong Docker network nội bộ. |

---

### Kịch bản T4 — Data Access / Exfiltration Pattern

| Trường | Nội dung |
|---|---|
| **MITRE TTP** | T1530 — Data from Cloud Storage Object |
| **Mô tả** | Mô phỏng hành vi đọc số lượng lớn objects từ S3 (mock) trong thời gian ngắn — đặc trưng của data staging trước khi exfil. Không có dữ liệu thật nào bị chuyển ra ngoài. |
| **Mục tiêu phát hiện** | SIEM phát hiện bất thường về volume S3 GetObject calls vượt ngưỡng. |
| **Expected telemetry** | S3 access logs ghi ≥ 100 `GetObject` events từ cùng principal trong 2 phút; SIEM alert `S3_BULK_READ_ANOMALY` được kích hoạt. |
| **Phương pháp** | Script Python dùng Boto3 đọc liên tiếp các synthetic objects từ mock S3 (MinIO container), sink là internal bucket khác trong sandbox. |

---

### Kịch bản T5 — Supply-chain / CI Compromise Pattern

| Trường | Nội dung |
|---|---|
| **MITRE TTP** | T1195.001 — Supply Chain Compromise: Compromise Software Dependencies |
| **Mô tả** | Mô phỏng một CI runner chạy một job không được định nghĩa trong pipeline chính thức, và sử dụng repository secret theo cách bất thường (đọc và ghi log, không sử dụng vào mục đích thật). |
| **Mục tiêu phát hiện** | Hệ thống phát hiện CI runner thực thi job ngoài danh sách approved workflows. |
| **Expected telemetry** | GitHub Actions audit log ghi event `workflow_run.unauthorized_job`; secret access log ghi `SECRET_READ` từ unexpected context. |
| **Phương pháp** | Tạo một test workflow tách biệt trong sandbox repo, trigger thủ công, validate rằng hệ thống monitoring bắt được event. |

---

### Kịch bản T6 — Reconnaissance / Discovery

| Trường | Nội dung |
|---|---|
| **MITRE TTP** | T1046 — Network Service Discovery |
| **Mô tả** | Thực hiện port scan nội bộ trong sandbox network để kiểm tra khả năng phát hiện của NIDS. |
| **Mục tiêu phát hiện** | Zeek/Suricata phát hiện SYN scan pattern từ một source trong subnet. |
| **Expected telemetry** | Zeek `conn.log` ghi nhiều connection attempts đến các ports khác nhau trên cùng target; Suricata alert `SCAN SYN` được tạo. |
| **Phương pháp** | `nmap -sS` với tham số giới hạn tốc độ (`--max-rate 50`) chỉ trong Docker network nội bộ. |

---

### Tổng hợp kịch bản

| ID | Kịch bản | MITRE TTP | Detection target |
|---|---|---|---|
| T1 | SSH Brute-force | T1110.001 | SIEM alert SSH_BRUTEFORCE |
| T2 | Privilege Escalation (IAM) | T1078.004 | CloudTrail anomaly |
| T3 | Lateral Movement | T1021 | NIDS multi-connection |
| T4 | Data Access Pattern | T1530 | S3 bulk read anomaly |
| T5 | CI Compromise Pattern | T1195.001 | Audit log unauthorized job |
| T6 | Reconnaissance | T1046 | Suricata SYN scan alert |

---

## VI. Các Công Cụ Sử Dụng

### 6.1 CI/CD & Orchestration

**GitHub Actions** là nền tảng CI/CD chính, đảm nhận toàn bộ orchestration pipeline từ trigger đến teardown. Lý do chọn: tích hợp sẵn với GitHub repository, hỗ trợ `workflow_dispatch` với custom inputs (approval ticket, scenario ID), có environment protection rules để yêu cầu reviewer trước khi chạy các job nhạy cảm.

**Terraform** quản lý hạ tầng sandbox dưới dạng code (Infrastructure as Code). Mỗi phiên chạy tạo ra một sandbox mới với run ID riêng biệt, đảm bảo không có state chồng chéo giữa các lần chạy.

### 6.2 Attack Simulation

Trong phạm vi bản prototype hiện tại, công cụ mô phỏng chính là **custom benign scripts** viết bằng Python/Bash, sử dụng Paramiko (SSH), Boto3 (IAM) và các công cụ mạng cơ bản. Atomic Red Team hoặc CALDERA có thể được tham khảo ở phần nghiên cứu liên quan, nhưng chưa phải thành phần bắt buộc của bản triển khai hiện tại.

### 6.3 Containerization & Infrastructure

**Docker / Docker Compose** dùng để đóng gói attack runners và deploy target workloads. Base image cho attack runner là Kali Linux, chỉ cài đặt các công cụ đã được phê duyệt.

Các thành phần như MinIO hay image scanning có thể được bổ sung trong giai đoạn mở rộng nếu nhóm phát triển thêm các kịch bản T4 trở đi.

### 6.4 Telemetry & SIEM

**Filebeat** được giữ như một lựa chọn tham khảo cho việc thu thập logs trong sandbox. Trong phiên bản hiện tại, nguồn đánh giá chính là observables sinh ra từ simulation runner và artifacts trong CI.

Các thành phần như Zeek, Elasticsearch, Kibana hay Suricata được xem là hướng mở rộng phù hợp với nghiên cứu tiếp theo, không phải yêu cầu cốt lõi của bản đồ án môn học.

### 6.5 Detection Rules

`expected_mappings.yaml` đóng vai trò là lớp mapping học thuật giữa từng kịch bản và các detection kỳ vọng. Sigma có thể được tham khảo như một định dạng chuẩn trong phần lý thuyết, nhưng không bắt buộc phải tích hợp đầy đủ trong phiên bản hiện tại.

```yaml
# Ví dụ Sigma rule cho T1
title: SSH Brute Force Detection
id: a3f2c1d4-...
status: test
logsource:
  product: linux
  service: auth
detection:
  selection:
    type: syslog
    message|contains: 'Failed password'
  condition: selection | count() by src_ip > 10
falsepositives:
  - Legitimate automation with bad credentials
level: medium
tags:
  - attack.credential_access
  - attack.t1110.001
```

### 6.6 Reporting & Notification

**Python + Jinja2** render HTML reports từ dữ liệu đánh giá. Đây là thành phần reporting cốt lõi đã phù hợp với phạm vi học thuật.

Slack hoặc JIRA chỉ nên được nhắc tới như ý tưởng mở rộng, không nên xem là tiêu chí hoàn thiện bắt buộc cho đồ án môn học.

### 6.7 Secrets Management

Trong phạm vi đồ án, **GitHub Actions Secrets** là đủ cho việc quản lý biến môi trường thử nghiệm. Vault là lựa chọn mở rộng nếu đề tài được phát triển thành nghiên cứu sâu hơn.

### 6.8 Tổng hợp tech stack

| Lớp | Công cụ |
|---|---|
| CI/CD | GitHub Actions, Terraform |
| Simulation | Custom Python/Bash scripts, Paramiko, Boto3 |
| Container | Docker, Docker Compose |
| Telemetry | Observables/artifacts, Filebeat (tham khảo) |
| SIEM | Không bắt buộc trong bản prototype môn học |
| Detection rules | YAML expected mappings |
| Evaluation | Python, requests, PyYAML |
| Reporting | Python, Jinja2 |
| Secrets | GitHub Actions Secrets |
| Ngôn ngữ | Python, Bash, YAML, HCL (Terraform) |

---

## VII. Kết Quả Dự Kiến

### 7.1 Sản phẩm kỹ thuật

Kết thúc đồ án, nhóm sẽ bàn giao một hệ thống prototype học thuật gồm:

- **Git repository** chứa toàn bộ source code: scenario definitions (YAML), simulation runner, CI pipeline configs, Terraform templates, Python evaluator và report generator.
- **Hai kịch bản TTP hoạt động end-to-end** trong CI pipeline: `T1` và `T2`.
- **Chế độ chạy an toàn** trong sandbox và chế độ `dry-run` để phục vụ demo, kiểm thử, và minh họa nguyên lý hoạt động.
- **Hệ thống báo cáo tự động** dưới dạng HTML artifact và JSON artifacts phục vụ đối chiếu kết quả.
- **Tài liệu học thuật** mô tả kiến trúc, phạm vi, hướng mở rộng và báo cáo thực nghiệm của từng lần chạy.

### 7.2 Chỉ số đo lường thành công

| Metric | Mục tiêu |
|---|---|
| Detection Coverage | Các detection bắt buộc trong mapping của T1/T2 đạt ≥ 80% |
| Sequence Validation | T2 xác nhận đủ chuỗi 3 event từ cùng principal trong cửa sổ quy định |
| Pipeline runtime | Một run đơn lẻ hoàn thành trong thời gian phù hợp để demo trên GitHub Actions |
| Reproducibility | Cùng kịch bản chạy lặp lại cho kết quả nhất quán trong sandbox |
| Safety | Không tạo tác động thật ra ngoài môi trường lab/sandbox |

### 7.3 Kiến thức và kỹ năng đạt được

Sau khi hoàn thành đề tài, sinh viên sẽ có khả năng:

- Vận dụng MITRE ATT&CK framework để thiết kế và phân loại kịch bản kiểm thử bảo mật.
- Xây dựng và vận hành pipeline CI/CD tích hợp kiểm thử bảo mật tự động.
- Thiết kế expected mappings và evaluate hiệu quả của từng kịch bản bằng Python.
- Thiết kế hạ tầng sandbox ephemeral bằng Terraform, đảm bảo cách ly và an toàn.
- Trình bày được mô hình DevSecOps và giải thích vị trí của detection validation trong SDLC.

### 7.4 Tài liệu bàn giao

- **Runbook** đầy đủ: quy trình approval, hướng dẫn chạy an toàn, kill-switch procedure.
- **Final report** (15–25 trang): kiến trúc, metrics thực đo, lessons learned, recommendations.
- **Demo video** (5–10 phút): một end-to-end run — từ trigger đến report — được quay và chú thích.
- **Báo cáo thực nghiệm** của các lần chạy tiêu biểu, ví dụ báo cáo T2 safe-mode trên GitHub Actions.

## VIII. Đối chiếu với trạng thái triển khai hiện tại

Tại thời điểm hoàn thiện bản đồ án này, repository đã đạt được các hạng mục sau:

- Có 2 workflow GitHub Actions: chạy theo yêu cầu và chạy theo lịch.
- Có 2 kịch bản đã triển khai đầy đủ: `T1` và `T2`.
- Có evaluator tự động dựa trên `expected_mappings.yaml`.
- Có report generator tạo `report.html` từ kết quả đánh giá.
- Có tài liệu vận hành cơ bản: `runbook`, `approval_form`, `kill_switch`.
- Đã có ít nhất một lần chạy `T2` ở chế độ `safe` thành công trên GitHub Actions và được lưu báo cáo trong repo.

Các hạng mục chưa triển khai và được xem là hướng mở rộng:

- T3 đến T6.
- Tích hợp SIEM hoàn chỉnh với ELK/Kibana.
- Slack/JIRA notification.
- Vault, private registry, image scanning, replay mode, dashboard nhiều tuần.

---

*Mọi kịch bản trong đề tài đều phi phá hoại và chỉ được thực thi trong môi trường sandbox đã được phê duyệt bởi instructor và lab owner.*
