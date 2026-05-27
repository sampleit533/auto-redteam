# Đối chiếu đồ án với outline đề tài — 2026-05-27

> Cập nhật của [proposal-gap-review-2026-04-08.md](proposal-gap-review-2026-04-08.md).
> Lần này đối chiếu trạng thái **hiện tại** của repo (sau khi bổ sung T7, T8 và
> chuỗi kill chain trên **AWS thật**) với **outline đề tài được ấn định**
> (`Đề tài 16: Red Team Automation trong pipeline CI/CD`).

---

## 0. Lưu ý về sự lệch đề tài (PHẢI đọc trước)

- **Proposal đã được duyệt (PDF)** là **Đề tài 5 — "Tự động phát hiện & khắc phục
  misconfigurations trên cloud bằng pipeline Ansible + công cụ quét (ScoutSuite,
  CloudSploit, Checkov)"**, môn *Kiến trúc & Bảo mật Điện toán Đám mây*.
- **Outline mục tiêu được ấn định (MD)** lại là **Đề tài 16 — "Red Team Automation
  trong CI/CD"**.
- **Repo này (`auto-redteam`) đang triển khai Đề tài 16 (Red Team)** — khớp với
  outline MD, **không khớp** với proposal misconfig đã duyệt.

➡️ **Hành động cần làm (phía nhóm, ngoài phạm vi code):** xác nhận chính thức rằng
đề tài đã chuyển sang Red Team Automation, hoặc làm rõ proposal misconfig kia
thuộc môn/đề tài khác. Bản đối chiếu dưới đây giả định hướng **Red Team (Đề tài 16)**
là đúng.

---

## 1. Bảng đối chiếu theo 17 mục của outline

Chú thích: ✅ Đã làm · 🟡 Làm một phần / thay bằng phương án tương đương · ⬜ Chưa làm (bỏ dở)

| # | Mục trong outline | Trạng thái | Ghi chú |
|---|---|---|---|
| 1 | Đặt vấn đề | ✅ | proposal §III — Continuous Detection Validation |
| 2 | Mục tiêu | ✅ | Bao phủ đủ: pipeline an toàn, isolated infra, telemetry, success criteria (coverage/TTD/MITRE), báo cáo, an toàn pháp lý |
| 3 | Kiến trúc & Tech stack | 🟡 | Xem mục 2 bên dưới — phần lớn ✅, một số thành phần thay bằng phương án nhẹ hơn |
| 4 | Threat model T1–T6 | ✅ **(vượt)** | Repo hiện thực **T1–T8** (đủ 6 TTP outline + T7/T8). Báo cáo/demo **tập trung 3 kịch bản cốt lõi T1/T2/T4** (chuỗi host→cloud); T3/T5/T6/T7/T8 giữ làm **kịch bản mở rộng** |
| 5 | Design step-by-step | ✅ | approval → sandbox → fixtures → runners → CI orchestration → telemetry+eval → report → cleanup |
| 6 | CI/CD patterns | ✅ **(vượt)** | **PR-gated** ✅ (pipeline chạy trên push/PR), **+ stage Deploy lên AWS thật** (reusable `redteam-cloud-deploy`, OIDC, approval gate). Stages provision→…→teardown đầy đủ |
| 7 | Safe simulation | 🟡 | Telemetry generator ✅, agentless/API-level ✅, **replay** (pcap → Snort/NIDS-lite offline) ✅ một phần. **Chưa**: Atomic Red Team "test mode", canary scope hình thức hoá |
| 8 | Telemetry & evidence | 🟡 | CloudTrail (management **và** data events) ✅, pcap ✅, mapping step→event ✅, artifacts ✅. **Chưa**: VPC flow logs, EDR/host events, evidence manifest chuẩn hoá |
| 9 | Metrics | 🟡 | Detection coverage ✅, regression (baseline gate + trends) ✅. **Chưa hình thức hoá**: TTD median/p95, FP-noise rate, remediation time |
| 10 | Reporting & feedback loop | 🟡 | HTML report ✅, trend dashboard (HTML) ✅. **Chưa**: auto-create JIRA/GitHub Issue, Kibana dashboard live, debrief là quy trình chứ chưa có artifact |
| 11 | Testing & reproducibility | ✅ | dry-run ✅, versioned scenario YAML ✅, CI test matrix (LocalStack gate) ✅, replay (pcap) ✅ một phần |
| 12 | Safety/ethics | ✅ | approval_form, kill_switch, runbook, non-destructive, **permissions boundary Deny-all = zero blast radius**, accountability (run_id + approval ticket) |
| 13 | Rubric | — | Tham khảo để tự chấm; xem mục 4 |
| 14 | Milestones (14 tuần) | 🟡 | Trình bày theo **8 giai đoạn triển khai** thay vì theo tuần (đã ánh xạ trong proposal §IV) |
| 15 | Deliverables | 🟡 | Repo ✅, sample artifacts ✅, runbooks ✅, trend dashboard ✅. **Chưa**: **demo video (5–10')**, **final report (15–25 trang)** |
| 16 | Appendix scenario YAML | ✅ | `scenarios/T*.yaml` đúng schema template |
| 17 | Ethical notes (approver) | ✅ | approval_form.md có chữ ký approver/lab owner; tài khoản sandbox riêng |

---

## 2. Chi tiết mục 3 (Architecture & Tech Stack)

| Thành phần outline | Trạng thái | Hiện thực trong repo |
|---|---|---|
| CI/CD platform (GitHub Actions) | ✅ | 2 workflow: `redteam-pipeline` (liên tục, push/PR), `redteam-cloud-deploy` (AWS thật, OIDC, reusable) |
| Attack framework (Atomic Red Team / CALDERA / Kali) | 🟡 | Dùng **custom Python runners** (Paramiko, Boto3, socket, JNDI probe) thay cho ART/CALDERA — chủ ý để giữ non-destructive & kiểm soát observable. Base image Kali tham khảo |
| Orchestration (Docker / K8s / Terraform ephemeral) | ✅ | Docker Compose (`targets/`) + Terraform (`infra/main.tf` Docker provider; `infra/aws-bootstrap/` cho AWS). K8s không dùng (không bắt buộc) |
| Telemetry collection (Filebeat/Fluent Bit → Kafka → SIEM) | 🟡 | `collection/filebeat.yml` có sẵn; pcap qua tcpdump ✅; **không** có Kafka/ELK/Splunk/Sentinel live — evaluator chạy **offline trên observables**. CloudTrail readback thật ✅ |
| Network pcap (Zeek/tshark) | 🟡 | Bắt pcap bằng `pcap-recorder` (tcpdump) ✅; phân tích bằng **Snort 3 offline** (T7) + **NIDS-lite** (T3/T6) thay cho Zeek/Suricata live |
| Detection stack (Sigma, EDR, WAF, cloud-native logs) | 🟡 | **Sigma rules export** ✅ (19 rule trong `sigma/`), CloudTrail (cloud-native) ✅, Snort (NIDS) ✅. **Không** có EDR, **không** có WAF |
| Reporting (JSON/HTML + JIRA/GitHub issues) | 🟡 | JSON + HTML ✅, trends ✅. **Không** auto-create issue |
| Secrets (Vault) | 🟡 → ✅* | **Không dùng Vault**; thay bằng **GitHub OIDC (zero static keys)** + GitHub Secrets. *Về mặt an toàn còn tốt hơn Vault cho CI→AWS* |
| Isolated VPC/VLAN, ephemeral ns, test accounts | ✅ | Docker internal network + **AWS permissions boundary Deny-all** + IAM path `/redteam-sandbox/` + bucket prefix `redteam-sandbox-*` |

---

## 3. Những gì đồ án LÀM VƯỢT outline (điểm mạnh để nhấn trong báo cáo)

1. **Deploy & kiểm chứng trên AWS THẬT qua GitHub OIDC** — outline chỉ giả định
   staging/sandbox; đồ án này chạy kill chain trên tài khoản AWS thật, **không dùng
   static key nào**.
2. **CloudTrail thật — cả management event lẫn data event.** T2/T8 đọc management
   event qua `LookupEvents`; T4 đọc **S3 data events** (GetObject) từ CloudWatch Logs
   thông qua một trail có advanced event selector. Đây là telemetry phát hiện **thật**,
   không phải self-report.
3. **Cloud kill chain** (T8 Recon → T2 PrivEsc → T4 Exfiltration) minh hoạ trọn chuỗi
   Discovery → Privilege Escalation → Exfiltration trên một lần deploy.
4. **3 kịch bản cốt lõi (T1/T2/T4)** trình bày chiều sâu + 5 kịch bản mở rộng trong
   repo (tổng 8; outline chỉ yêu cầu 6).
5. **Pipeline CI/CD liên tục**: push/PR → lint + gitleaks → build-test trên LocalStack
   (gate detection 100%) → deploy AWS thật (gate môi trường `aws-sandbox`), kèm
   **baseline regression gate**.
6. **Sigma export, NIDS-lite, Snort 3 offline replay, pcap, trend dashboard** — vòng
   lặp pcap → detection khép kín mà không cần Zeek/Suricata live.

---

## 4. "Bỏ dở" — danh sách rút gọn cần quyết định

Sắp theo mức độ đáng làm nốt cho điểm:

| Hạng mục | Thuộc rubric | Đề xuất |
|---|---|---|
| **Demo video (5–10') + Final report (15–25 trang)** | Docs & demo 10% | **Bắt buộc nộp** — nên làm |
| Auto-create GitHub Issue khi detection fail | Reporting 15% | Dễ thêm (GitHub API có sẵn token) — nên làm để đủ "feedback loop" |
| TTD median/p95 + FP-noise rate (metrics hình thức) | Telemetry & eval 20% | Nên thêm vài dòng tính toán vào evaluator/trends |
| ELK/Kibana live + Sigma chạy trên SIEM thật | Telemetry & eval 20% | Tốn công; có thể để "hướng mở rộng" và giải trình bằng offline-eval |
| EDR / WAF | Architecture | Để "ngoài phạm vi" — hợp lý với đồ án môn học |
| Vault | Architecture | **Đã thay bằng OIDC** — giải trình là phương án tốt hơn, không cần làm |
| Atomic Red Team / CALDERA | Safe simulation | Để "phương án thay thế" — custom runner kiểm soát tốt hơn |
| VPC flow logs, EDR/host telemetry | Telemetry | Để "hướng mở rộng" |

---

*Kết luận: đồ án đã phủ phần lõi của outline và vượt ở mảng cloud thật. Hai thứ
"bỏ dở" thực sự ảnh hưởng điểm là **demo video + final report** (deliverable bắt buộc)
và **auto-issue + một vài metric** (cho đủ rubric Reporting/Telemetry). Phần còn lại
là hướng mở rộng có thể giải trình.*
