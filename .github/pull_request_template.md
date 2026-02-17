## 1. PR Purpose
Select all that apply.

- [ ] 🐛 Bug fix (corrects false positive/false negative or broken behavior)
- [ ] ✨ New control / attack-scenario coverage
- [ ] 🔧 Control logic update (existing Rego behavior change)
- [ ] 🧪 Test-only change (`*_test.rego` only, no production rule changes)
- [ ] 🗂️ Metadata / mapping update (`metadata.yaml` and/or mapping CSV)
- [ ] 📝 Documentation/content update (README, threat-model docs, images)
- [ ] ♻️ Refactor (no functional behavior changes)
- [ ] ⚙️ Build / configuration / automation change

## 2. Description

## 3. Scope
- Cloud / Service: `aws/s3` (example)
- Control ID(s): `S3.C123` (example)
- Variant(s): `universal` / `allowlist` / `denylist`

## 4. Related Issue (Leave blank if not applicable)
Closes #

## 5. Checklist
- [ ] I have performed a self-review
- [ ] I added or updated tests (`*_test.rego`) as needed
- [ ] Package header is `package wiz` for Wiz compatibility in committed Rego
- [ ] Mapping CSV updated if control metadata or mappings changed
