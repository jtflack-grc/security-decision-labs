# FAIR Methodology Notice

## About FAIR and FAIR-CAM

This software implements concepts from the **Factor Analysis of Information Risk (FAIR)** methodology, specifically the estimation of **Threat Event Frequency (TEF)** — one of the foundational inputs to a quantitative FAIR risk analysis.

## Trademark and Affiliation

**FAIR**, **FAIR-CAM**, and the **FAIR Institute logo** are registered trademarks of the FAIR Institute.

### This Software Is:

- **NOT affiliated** with the FAIR Institute
- **NOT endorsed** by the FAIR Institute
- **NOT certified** by the FAIR Institute
- **An independent implementation** created for research purposes

## Official FAIR Resources

For official FAIR training, certification, and authoritative resources:

- **FAIR Institute:** https://www.fairinstitute.org/
- **FAIR Training and Certification:** https://www.fairinstitute.org/fair-training-and-certification

## Implementation Notes

This implementation follows the FAIR taxonomy as documented in:
- *"Measuring and Managing Information Risk: A FAIR Approach"* by Jack Freund and Jack Jones (2014)

Any deviations from or extensions to the standard methodology are documented in the accompanying documentation.

## Data Sources

This software incorporates empirical data from:

**IRIS 2025 (Information Risk Insights Study)**
- **Author:** Cyentia Institute (https://www.cyentia.com/)
- **Access:** Available at https://www.cyentia.com/iris2025/
- **Usage:** Statistical parameters extracted with full source attribution
- **Purpose:** To aid community efforts to manage cyber risk

**Full Citation:**
Cyentia Institute. (2025). *Information Risk Insights Study 2025: It's About Time*.
Sponsored by the Cybersecurity and Infrastructure Security Agency (CISA).
Retrieved from https://www.cyentia.com/iris2025/

**Initial Access Vector Benchmarks**

Cross-source vector proportion data (`data/reference/vectors/initial_access_vectors.json`) is compiled from:
- DBIR 2025/2026 (Verizon, 22,052/31,861 incidents)
- Palo Alto Unit 42 IR Reports 2025/2026 (500/750 engagements)
- Google/Mandiant M-Trends 2026 (500k+ IR hours)
- CrowdStrike Global Threat Report 2026 (EDR telemetry)
- Beazley Q3 2025 Threat Briefing (cyber insurance claims)
- IBM Cost of a Data Breach 2025 (600 organizations)

Each record includes extraction provenance, source verdicts, bias propagation tags, and quality tier assessments. All values were manually verified from source PDFs.

Additional data sources (Coveware, Census SUSB, Sophos, VCDB, NetDiligence, StatCan, IRIS 2022, Coalition, DShield, CISA KEV, Ransomware.live, FBI IC3) are documented with full citations in the embedded JSON data files and in `docs/technical-reference.md`.

Users must comply with the respective licenses and terms of use for all data sources.

## Questions

For questions about:
- **The FAIR/FAIR-CAM methodology itself:** Contact the FAIR Institute
- **This specific implementation:** Open an issue in this repository
