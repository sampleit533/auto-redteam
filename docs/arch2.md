# Kiến trúc & Dataflow — auto-redteam (góc nhìn phân vùng)


> Các sơ đồ chi tiết khác (Hình 1 tổng thể, pipeline 3 stage, vòng đời 1 run, hạ tầng
> OIDC) vẫn nằm ở [`architecture.md`](architecture.md) — tài liệu này là bản bổ sung,
> không thay thế.

---

## Hình A — Kiến trúc & luồng dữ liệu (phân vùng)

Ba phân vùng chức năng (**Orchestration → Engine → Targets**) tương ứng với bố cục
*Pre-configuration → Central Engine → Post/Target* của mẫu tham khảo. Actor **User
(Tenant)** đứng dưới cùng kích hoạt pipeline; **Approver / Security reviewer** là
**consumer** của báo cáo.

```mermaid
flowchart TB
    gh(["<b>GitHub Repository</b><br/>sampleit533/auto-redteam<br/>scenarios/ · runners/ · infra/ · sigma/"])

    subgraph PRE["① Orchestration &amp; Provisioning"]
        direction TB
        ga["<b>GitHub Actions — Orchestrator</b><br/>redteam-pipeline.yml<br/>redteam-cloud-deploy.yml (reusable)"]
        tf["<b>Terraform (HashiCorp)</b><br/>Docker provider<br/>+ aws-bootstrap (OIDC, role, boundary, trail)"]
        oidc["<b>OIDC → AWS STS</b><br/>AssumeRoleWithWebIdentity<br/>role redteam-deploy<br/>boundary Deny *"]
        ga --> tf
        ga --> oidc
    end

    subgraph ENG["② Attack Simulation &amp; Detection Engine"]
        direction TB
        sim["<b>Attack Runners — simulate.py</b><br/>core: T1 SSH brute · T2 IAM privesc · T4 S3 exfil<br/>(+ T3/T5/T6/T7/T8 mở rộng)"]
        col["<b>Telemetry Collection</b><br/>CloudTrail mgmt + S3 data events<br/>pcap → Snort 3 / NIDS-lite<br/>self-report observables"]
        evalr["<b>Evaluator + Mapping</b><br/>evaluate_results.py<br/>expected_mappings.yaml<br/>coverage · composite rules"]
        gate["<b>Detection / Baseline Gate</b><br/>check_baseline.py<br/>coverage 100% trên LocalStack"]
        rep["<b>Reporting</b><br/>report.html · trends.html<br/>Sigma export"]
        sim --> col --> evalr --> gate
        evalr --> rep
    end

    subgraph TGT["③ Target Environments"]
        direction TB
        sandbox["<b>Sandbox (CI)</b><br/>Docker: ssh / web / redis<br/>LocalStack (fake cloud)"]
        aws["<b>Real AWS</b><br/>IAM / STS / S3 + CloudTrail<br/>tài nguyên redteam-sandbox-*"]
    end

    user["<b>User (Tenant)</b><br/>Developer · Operator"]
    reviewer(["<b>Consumer</b><br/>Approver / Security reviewer"])

    user -->|"Trigger — push / PR / merge main"| ga
    gh -. "checkout assets" .-> ga
    tf -->|"provision ephemeral"| sandbox
    sim -->|"run kill chain (safe)"| sandbox
    gate -. "pass + merge main → promote" .-> oidc
    oidc -->|"Deploy (zero static key)"| aws
    sandbox -->|"observables / logs"| col
    aws -->|"CloudTrail readback"| col
    rep -->|"artifacts / report"| reviewer
    ga -->|"commit status / deploy"| gh

    classDef box fill:#eef,stroke:#447,color:#000;
    classDef cloud fill:#fee,stroke:#a44,color:#000;
    classDef scm fill:#efe,stroke:#474,color:#000;
    class ga,tf,sim,col,evalr,gate,rep,sandbox box;
    class oidc,aws cloud;
    class gh scm;
```

---

## Hình B — Sequence: luồng định danh động & deploy lên AWS thật (OIDC)

Tương ứng với sequence diagram "token-exchange / JIT credential" của mẫu tham khảo,
nhưng đây là **luồng GitHub-OIDC thật** của đồ án: runner đổi **OIDC ID token (JWT)**
lấy **credential tạm thời** từ AWS STS, chạy kill chain T1→T2→T4 trên AWS thật, đọc
ngược CloudTrail để đánh giá, rồi tự dọn dẹp. Permissions boundary `Deny *` + TTL
credential đóng vai trò "zero blast radius".

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / Tenant
    participant GH as GitHub Repo
    participant PIPE as Pipeline runner<br/>(redteam-pipeline)
    participant LS as Sandbox<br/>(LocalStack + sshd)
    participant EVAL as Evaluator + Gate
    participant CD as Cloud Deploy runner<br/>(redteam-cloud-deploy)
    participant STS as AWS STS / IAM
    participant AWS as AWS S3 + CloudTrail

    Dev->>GH: push / PR vào main
    GH->>PIPE: Trigger pipeline (push / PR)
    PIPE->>PIPE: Code stage — lint + quét secret
    PIPE->>LS: Start sshd (T1) + LocalStack (T2/T4)
    PIPE->>LS: Run --scenario kill-chain (safe)
    LS-->>PIPE: Observables (auth_log · IAM · S3)
    PIPE->>EVAL: Evaluate detection coverage
    EVAL-->>PIPE: Detection gate — coverage 100% ?

    alt Gate PASS và ref == refs/heads/main
        PIPE->>CD: Promote — gọi reusable cloud-deploy
        CD->>STS: AssumeRoleWithWebIdentity<br/>(OIDC ID token JWT · role redteam-deploy)
        Note over STS: Verify issuer + sub (repo / branch)<br/>Áp permissions boundary Deny *<br/>(redteam-sandbox-boundary)
        STS-->>CD: Credential tạm thời<br/>(session redteam-run_id · TTL ~1h)
        CD->>AWS: Run kill chain trên AWS thật<br/>T1 host → T2 IAM privesc → T4 S3 bulk read
        AWS->>AWS: CloudTrail ghi management + S3 data events
        CD->>AWS: Readback CloudTrail (LookupEvents + CW Logs)
        AWS-->>CD: Cloud observables
        CD->>EVAL: Coverage + baseline gate (trên AWS thật)
        Note over CD,AWS: Sweep redteam-sandbox-* ·<br/>credential hết hạn ⇒ zero blast radius
    else Gate FAIL hoặc nhánh != main
        PIPE-->>Dev: Dừng — KHÔNG promote lên AWS
    end

    PIPE->>GH: Upload artifacts + commit status
    GH-->>Dev: Kết quả CI + report.html / trends / Sigma
```

---

## Ánh xạ với mẫu tham khảo

| Vai trò trong mẫu tham khảo | Thành phần tương đương ở auto-redteam |
|---|---|
| Pre-configuration (Control Node, Terraform, IdP/STS) | ① Orchestration: GitHub Actions + Terraform + GitHub OIDC → AWS STS |
| Central Security & Triage Engine (Scanner → SIEM → OPA) | ② Engine: simulate.py runners → Telemetry collection → Evaluator + **Detection/Baseline gate** (vai trò "policy/triage") |
| Action Dispatcher / Ticketing / ChatOps | Reporting (report.html · trends · Sigma export) + commit status trên PR |
| Post-configuration (Drift Detection, Revert) | Teardown / Sweep (`if: always()`) + baseline regression gate |
| Target Environment (OpenStack / AWS) | ③ Targets: Sandbox Docker + LocalStack (CI) và **AWS thật** (IAM/STS/S3 + CloudTrail) |
| Keycloak + Vault + STS Hub + RFC 8693 token-exchange | **GitHub OIDC native** (`AssumeRoleWithWebIdentity`) — không cần broker; boundary `Deny *` + TTL thay cơ chế JIT 15 phút |
