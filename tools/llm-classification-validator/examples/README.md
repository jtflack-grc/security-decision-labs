# Examples

## AICM to FAIR-CAM mapping (example only)

Demonstrates the framework by mapping CSA AI Controls Matrix (AICM v1.0.2) controls to FAIR-CAM categories. Runs all 5 dimensions against 20 real AICM controls. **The mappings in this example are illustrative — they show how to wire the framework, not how AICM controls should be mapped to FAIR-CAM.** Replace the taxonomy, expert mappings, and transitive crosswalk with your own for your use case.

This is the worked example described in [Validating LLM-Generated Control Mappings Beyond Aggregate Accuracy](https://cloudsecurityalliance.org/blog/2026/07/02/validating-llm-generated-control-mappings-beyond-aggregate-accuracy) (Cloud Security Alliance).

```bash
python examples/aicm_to_faircam.py
```

### Required: FAIR-CAM taxonomy file

The example loads `examples/faircam_taxonomy.json`, which is not included in the repository. Create this file with the following schema:

```json
{
  "DOMAIN_CODE": {
    "name": "Domain Name",
    "subdomains": {
      "Subdomain Name": {
        "functions": ["Function A", "Function B"]
      }
    }
  }
}
```

Each top-level key is a domain code. Each domain has a name, subdomains, and each subdomain has a list of functions. The example expects three domains (LEC, VMC, DSC) matching the FAIR-CAM taxonomy.
