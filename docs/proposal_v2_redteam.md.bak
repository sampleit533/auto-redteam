# PROPOSAL 

---

## I. Tên Đề Tài

**Red Team Automation trong Pipeline CI/CD — Tích hợp kiểm thử tấn công tự động và báo cáo DevSecOps**

---

## II. Mục Tiêu

### 2.1 Mục tiêu tổng quát

Xây dựng một hệ thống tự động hóa kiểm thử bảo mật theo phong cách red team, tích hợp trực tiếp vào pipeline CI/CD, nhằm liên tục kiểm chứng khả năng phát hiện tấn công (detection validation) của hệ thống phòng thủ trong môi trường staging — từ đó tạo ra vòng phản hồi (feedback loop) khép kín giữa đội phát triển và đội bảo mật.

### 2.2 Mục tiêu cụ thể

**Về kỹ thuật:**

- Thiết kế và triển khai pipeline CI/CD có khả năng tự động khởi chạy, giám sát và dọn dẹp các kịch bản tấn công mô phỏng trên môi trường sandbox cách ly.
- Tích hợp ít nhất 6 kịch bản TTP (Tactics, Techniques, and Procedures) theo chuẩn MITRE ATT&CK, đảm bảo hoàn toàn non-destructive.
- Xây dựng evaluator tự động so khớp telemetry thu được với expected detections, tính toán các chỉ số: detection coverage, time-to-detect (TTD), false negative rate.
- Tạo báo cáo HTML tự động sau mỗi lần chạy và gửi thông báo qua Slack/JIRA khi phát hiện detection gap.
- Đảm bảo hạ tầng ephemeral: tự động provision và teardown bằng Terraform sau mỗi phiên chạy.

**Về học thuật:**

- Giúp sinh viên hiểu và vận dụng thực tế khung MITRE ATT&CK trong detection engineering.
- Trải nghiệm mô hình DevSecOps shift-left: đưa kiểm thử bảo mật vào sớm trong vòng đời phát triển phần mềm.
- Rèn luyện kỹ năng vận hành cloud infrastructure (Terraform), container orchestration (Docker), log management (ELK stack) và viết automation scripts (Python, Bash).

---

## III. Giải Pháp Đề Xuất

### 3.1 Vấn đề cần giải quyết

Trong mô hình DevSecOps hiện đại, các tổ chức liên tục deploy phần mềm mới nhưng hiếm khi kiểm chứng xem những thay đổi đó có làm hỏng các detection rules hay EDR signatures hiện có hay không. Red teaming thủ công tốn kém, không reproducible và không thể chạy liên tục theo từng sprint. Hậu quả là detection gap âm thầm tồn tại sau mỗi lần cập nhật hạ tầng mà không ai biết cho đến khi bị tấn công thật.

### 3.2 Hướng tiếp cận

Giải pháp đề xuất là mô hình **Continuous Detection Validation** — tức là đưa việc kiểm chứng khả năng phát hiện tấn công vào pipeline CI/CD như một giai đoạn tự động, song song với các bước test và deploy thông thường. Cụ thể:

- **Shift-left detection testing**: Thay vì chờ đến khi có sự cố, hệ thống chủ động tạo ra các tín hiệu tấn công có kiểm soát trong môi trường staging để xác nhận SIEM/EDR hoạt động đúng.
- **Infrastructure as Code cho sandbox**: Toàn bộ môi trường thử nghiệm được tạo ra và hủy bỏ tự động bằng Terraform, đảm bảo cách ly và không để lại artifact sau mỗi phiên.
- **Scenario-as-Code**: Mỗi kịch bản tấn công được định nghĩa bằng file YAML có version control, đảm bảo reproducibility và auditability.
- **Automated evaluation**: Một Python evaluator tự động truy vấn SIEM sau khi chạy xong, so khớp alert thực tế với expected mapping, và tính toán coverage metrics.

### 3.3 Phạm vi

| | Chi tiết |
|---|---|
| **Trong phạm vi** | Môi trường staging/test cách ly, 6 kịch bản TTP non-destructive, pipeline GitHub Actions, SIEM tích hợp ELK stack, báo cáo tự động |
| **Ngoài phạm vi** | Production environment, khai thác lỗ hổng thật, external network targets, phân tích malware |

---

## IV. Phương Pháp Thực Hiện

### 4.1 Kiến trúc tổng thể

Hệ thống được thiết kế theo mô hình pipeline tuyến tính gồm 6 giai đoạn tuần tự:

```
[Trigger] → [Provision Infra] → [Deploy Targets] → [Simulate Attacks]
         → [Collect Telemetry] → [Evaluate Detections] → [Report + Teardown]
```

Mỗi giai đoạn là một job độc lập trong GitHub Actions, có thể chạy lại riêng lẻ khi cần debug. Toàn bộ pipeline được kích hoạt theo hai chế độ: thủ công (workflow_dispatch với approval ticket) hoặc tự động theo lịch (nightly cron job).

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

Deploy các dịch vụ mục tiêu bằng Docker Compose: SSH server, web application, mock S3 service. Seed dữ liệu thử nghiệm (synthetic, không có thông tin thật).

**Bước 4 — Containerized simulation runners**

Build Docker image từ base Kali Linux, chỉ cài đặt các công cụ đã được phê duyệt (atomic-operator, custom benign scripts). Image được lưu trong private registry, scan bằng Trivy trước khi sử dụng. Mỗi kịch bản chỉ sinh ra observable telemetry, không exploit lỗ hổng thật.

**Bước 5 — Orchestration pipeline**

GitHub Actions job theo thứ tự: validate-approval → provision → deploy-targets → simulate → collect → evaluate → report → teardown. Job teardown luôn chạy dù các bước trước có fail hay không (`if: always()`).

**Bước 6 — Thu thập telemetry**

Filebeat được cài trên target containers để ship logs về Elasticsearch. Zeek/tshark capture network traffic. Mỗi kịch bản định nghĩa rõ log sources cần thu thập và minimum occurrences.

**Bước 7 — Evaluation & mapping**

Python evaluator đọc file `expected_mappings.yaml` (định nghĩa TTP nào phải tạo ra alert nào trong SIEM), truy vấn Elasticsearch API, tính toán: detection coverage %, TTD median, false negative rate. Kết quả lưu dạng `results.json`.

**Bước 8 — Báo cáo & thông báo**

Script Python dùng Jinja2 render HTML report từ `results.json`. Nếu phát hiện detection gap: tự động tạo JIRA issue với evidence links, severity, và remediation hints. Push summary lên Slack channel của đội DevSecOps.

**Bước 9 — Dọn dẹp**

`terraform destroy` xóa toàn bộ hạ tầng. Docker volumes bị xóa. Test credentials bị thu hồi. Artifacts được lưu trữ với access control phù hợp (sanitized, không chứa thông tin nhạy cảm).

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

### 4.4 Kế hoạch 14 tuần

| Tuần | Nội dung |
|---|---|
| 1–2 | Research frameworks, thiết kế scenario catalog, quy trình approval |
| 3–4 | Sandbox infra (Terraform), target workload fixtures, seed data |
| 5–6 | Containerized simulation runners, private registry, image scanning |
| 7–8 | CI pipeline integration, telemetry collection (Filebeat + ELK) |
| 9 | Python evaluator, expected_mappings.yaml, report generator |
| 10 | Pilot chạy canary (2 kịch bản đầu), tune và fix |
| 11 | Mở rộng lên 6 kịch bản, scheduled nightly runs |
| 12 | Kibana dashboard, Slack/JIRA auto-notification |
| 13 | Dry-run mode, replay mode, robustness testing |
| 14 | Final evaluation, documentation, demo video, handover |

---

## V. Các Kịch Bản

Tất cả 6 kịch bản đều **non-destructive** — chỉ tạo ra observable telemetry mà không gây hại thực tế. Mỗi kịch bản được định nghĩa dạng YAML có version control, bao gồm: mô tả, tham số, expected observables, và cleanup commands.

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

**Atomic Red Team** (Red Canary) là thư viện hàng nghìn test cases được map theo MITRE ATT&CK, mỗi test chỉ chạy dưới 5 phút, có cleanup commands và không destructive. Được truy cập qua `atomic-operator` — Python framework cho phép chạy các atomic tests từ command line hoặc CI pipeline mà không cần cài đặt phức tạp.

**MITRE CALDERA** là platform adversary emulation tự động của MITRE, hỗ trợ REST API và Docker, cho phép xây dựng adversary profiles phức tạp hơn và tự động hóa multi-step attack chains. Được dùng cho T2 và T5 — các kịch bản cần choreograph nhiều bước liên tiếp.

**Custom benign scripts** (Python/Bash) được viết riêng cho các kịch bản cụ thể của đề tài, sử dụng Paramiko (SSH), Boto3 (S3/IAM), và standard networking tools (`nc`, `nmap`).

### 6.3 Containerization & Infrastructure

**Docker / Docker Compose** dùng để đóng gói attack runners và deploy target workloads. Base image cho attack runner là Kali Linux, chỉ cài đặt các công cụ đã được phê duyệt.

**MinIO** (S3-compatible object storage) dùng làm mock S3 target cho kịch bản T4, chạy hoàn toàn trong sandbox network.

**Trivy** (Aqua Security) scan Docker images trước khi sử dụng để đảm bảo không có vulnerability nghiêm trọng trong runner image.

### 6.4 Telemetry & SIEM

**Filebeat** thu thập logs từ target containers và ship về Elasticsearch theo thời gian thực. Cấu hình per-scenario để chỉ thu thập log sources liên quan.

**Zeek** (trước đây là Bro) phân tích network traffic và tạo structured logs (conn.log, dns.log, http.log) — là nguồn telemetry chính cho T3 và T6.

**Elasticsearch + Kibana (ELK Stack)** là SIEM backend. Elasticsearch lưu trữ và index toàn bộ logs; Kibana cung cấp dashboard để visualize detection coverage trends qua các tuần.

**Suricata** là IDS/IPS engine, phát hiện network-based attacks như SYN scan (T6) và lateral movement (T3).

### 6.5 Detection Rules

**Sigma (SigmaHQ)** là định dạng YAML mở để viết detection rules portable qua nhiều SIEM. Với hơn 15.000 rules community-contributed, đề tài sử dụng Sigma làm ngôn ngữ chuẩn cho expected_mappings.yaml và convert sang Elasticsearch Query DSL bằng `sigma-cli`.

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

**Python + Jinja2** render HTML reports từ `results.json`. Report bao gồm: summary table (scenarios × detection status), timeline of events, evidence links, remediation hints với priority.

**Slack Incoming Webhooks** gửi alert ngay khi phát hiện detection gap, kèm link đến CI artifact và JIRA issue.

**JIRA REST API** tự động tạo issues cho mỗi detection gap, với fields: scenario ID, evidence, severity (High/Medium/Low), remediation steps, và link đến full report.

### 6.7 Secrets Management

**HashiCorp Vault** (hoặc GitHub Actions Secrets cho môi trường đơn giản hơn) lưu trữ test credentials ephemeral. Credentials được tạo mới trước mỗi phiên chạy và revoke sau khi teardown.

### 6.8 Tổng hợp tech stack

| Lớp | Công cụ |
|---|---|
| CI/CD | GitHub Actions, Terraform |
| Simulation | Atomic Red Team, MITRE CALDERA, custom scripts |
| Container | Docker, Docker Compose, Trivy, MinIO |
| Telemetry | Filebeat, Zeek, Suricata |
| SIEM | Elasticsearch, Kibana |
| Detection rules | Sigma (SigmaHQ), sigma-cli |
| Evaluation | Python (pandas, requests) |
| Reporting | Python, Jinja2, Slack Webhook, JIRA API |
| Secrets | HashiCorp Vault / GitHub Secrets |
| Ngôn ngữ | Python, Bash, YAML, HCL (Terraform) |

---

## VII. Kết Quả Dự Kiến

### 7.1 Sản phẩm kỹ thuật

Kết thúc đồ án, nhóm sẽ bàn giao một hệ thống hoạt động đầy đủ gồm:

- **Git repository** chứa toàn bộ source code: scenario definitions (YAML), simulation runner, CI pipeline configs, Terraform templates, Python evaluator và report generator — tất cả đều reproducible từ một lệnh duy nhất.
- **Docker images** cho attack runners (private registry), đã được scan và approve.
- **6 kịch bản TTP** hoạt động end-to-end trong CI pipeline, có dry-run mode và replay mode.
- **ELK stack** được cấu hình sẵn với Sigma rules và Kibana dashboards.
- **Hệ thống báo cáo tự động**: HTML artifacts, Slack notifications, JIRA issue creation.

### 7.2 Chỉ số đo lường thành công

| Metric | Mục tiêu |
|---|---|
| Detection Coverage | ≥ 80% TTPs sinh ra ít nhất 1 SIEM alert |
| Time-to-Detect (TTD) | Median ≤ 5 phút từ khi mô phỏng bắt đầu đến khi có alert |
| False Negative Rate | ≤ 20% TTPs không bị phát hiện |
| Pipeline runtime | Một full run hoàn thành trong ≤ 30 phút |
| Reproducibility | Cùng kịch bản chạy 3 lần phải cho kết quả nhất quán |
| Detection Regression | Hệ thống tự alert khi coverage giảm > 10% so với baseline |

### 7.3 Kiến thức và kỹ năng đạt được

Sau khi hoàn thành đề tài, sinh viên sẽ có khả năng:

- Vận dụng MITRE ATT&CK framework để thiết kế và phân loại kịch bản kiểm thử bảo mật.
- Xây dựng và vận hành pipeline CI/CD tích hợp kiểm thử bảo mật tự động.
- Cấu hình và vận hành ELK stack làm SIEM trong môi trường lab.
- Viết Sigma detection rules và evaluate hiệu quả của chúng.
- Thiết kế hạ tầng sandbox ephemeral bằng Terraform, đảm bảo cách ly và an toàn.
- Trình bày được mô hình DevSecOps và giải thích vị trí của detection validation trong SDLC.

### 7.4 Tài liệu bàn giao

- **Runbook** đầy đủ: quy trình approval, hướng dẫn chạy an toàn, kill-switch procedure.
- **Final report** (15–25 trang): kiến trúc, metrics thực đo, lessons learned, recommendations.
- **Demo video** (5–10 phút): một end-to-end run — từ trigger đến report — được quay và chú thích.
- **Kibana dashboard** với trend data detection coverage qua ít nhất 4 tuần chạy thực tế.

---

*Mọi kịch bản trong đề tài đều phi phá hoại và chỉ được thực thi trong môi trường sandbox đã được phê duyệt bởi instructor và lab owner.*
