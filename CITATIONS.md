# Citations

All claims in this repository rest on the public record. Fill each entry with
author, title, publisher, date, URL, and access date. Keys in brackets are
referenced from the report and from `source_ref` fields in `data/phases.yaml`.

## Primary sources (the incident)

- **[HF-TIMELINE]** Hugging Face. Forensic timeline of the July 2026 intrusion
  (~17,600 attacker actions, ~9 phases). TODO: title, URL, publication date, access date.
  Pin the exact revision/commit if it is versioned.
- **[OPENAI-ACCOUNT]** OpenAI. Account of the ExploitGym evaluation and sandbox escape.
  TODO: title, URL, publication date, access date.

## Frameworks cross-walked in §2.5

- **[CSA-AICM]** Cloud Security Alliance. *AI Controls Matrix* — especially control
  **AIS-13 (sandboxing / isolation of AI workloads)**. TODO: version, URL, access date.
- **[COSAI-IR]** Coalition for Secure AI (CoSAI). Incident-response framework for AI
  systems. TODO: title, version, URL, access date.
- **[NIST-800-61r3]** NIST. *SP 800-61 Rev. 3, Incident Response Recommendations and
  Considerations for Cybersecurity Risk Management.* TODO: DOI/URL, date, access date.

## Secondary / supporting (add as needed)

- **[K8S-PSA]** Kubernetes Pod Security Admission documentation. TODO.
- **[IMDS]** Cloud provider metadata-service hardening docs (IMDSv2 / GKE metadata
  concealment). TODO.
- **[JINJA-SANDBOX]** Jinja2 `SandboxedEnvironment` documentation. TODO.
- **[TAILSCALE-ACL]** Tailscale device approval / ACL documentation. TODO.

## Citation hygiene

- Quote timestamps and action IDs from [HF-TIMELINE] where the matrix relies on them.
- Where a source is the victim's or vendor's own account, say so in the report (§5.3).
- Do not cite anything not publicly accessible at the time of submission.
