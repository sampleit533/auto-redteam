# Ra soat proposal va hien trang repo - 2026-04-08

## Muc dich

Tai lieu nay tong hop cac diem da doi chieu giua `proposal_v2_redteam.md` va hien trang implementation trong repo, theo huong phu hop voi do an mon hoc dai hoc.

## Cac diem da duoc chinh lai

- Thu hep muc tieu ky thuat tu `6` kich ban end-to-end thanh `2` kich ban cot loi da co implementation: `T1` va `T2`.
- Chuyen trong tam evaluation tu mo hinh SIEM/ELK day du sang `observables + expected mappings`, phu hop voi code hien tai.
- Chuyen Slack/JIRA, Vault, private registry, image scanning, Kibana, Zeek/Suricata thanh cac huong mo rong tham khao.
- Bo sung phan gioi han hoc phan de lam ro day la `prototype hoc thuat co the demo`, khong phai he thong enterprise.
- Bo sung phan doi chieu trang thai thuc te cua repo vao proposal.

## Hien trang implementation co trong repo

- GitHub Actions on-demand workflow.
- GitHub Actions scheduled workflow.
- Scenario `T1` da co YAML, runner, mapping, workflow path.
- Scenario `T2` da co YAML, runner, mapping, workflow path.
- Evaluator tu dong dua tren `results.json` va `expected_mappings.yaml`.
- HTML report generator.
- Runbook, approval form, kill switch.
- Bao cao thuc nghiem cho T2 safe-mode:
  - [t2-safe-run-2026-04-08.md](/home/beo/auto-redteam/docs/reports/t2-safe-run-2026-04-08.md)

## Cac phan chua lam va nen de o muc mo rong

- T3, T4, T5, T6.
- ELK/Kibana day du.
- Slack/JIRA notification.
- Vault.
- Trivy / private registry.
- Replay mode.
- Dashboard nhieu tuan.

## Nhan xet

Neu giu nguyen proposal cu, tai lieu se bi danh gia la vuot qua pham vi thuc te cua repo va de bi hoi ve cac thanh phan chua ton tai. Sau khi chinh, proposal va implementation da dong bo hon va phu hop voi cach trinh bay mot do an mon hoc.
