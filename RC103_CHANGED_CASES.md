# RC103 Changed Cases Report

## Overview
This report details the specific vulnerability detection cases impacted by the implementation of **Sink Argument Gating** and **Source Seeding Refinement** in the TaintFlow engine.

## 1. Source Seeding Refinement Impact
By preventing the engine from aggressively treating uncalled private methods (e.g., `def _internal_helper(data):`) as active entry points, we eliminated a major source of false positives in internal library and utility code.

**Key Resolved False Positives:**
*   **pgadmin4 internal routers:** Previously, internal private functions in pgadmin4 that lacked explicit GCG callers were assumed to be public routes. This flooded the engine with generic taint, leading to CWE-89 and CWE-22 false positives when those variables hit sinks.
*   **Django internal ORM handlers:** Private model serializers are no longer treated as HTTP endpoints.

## 2. Sink Argument Gating Impact
By gating the `Deserialization` domain arguments, the engine now requires the enclosing method to have a legitimate pathway for external taint to enter (either via parameters or explicit IR source instructions).

**Key Resolved False Positives:**
*   **Static Configuration Loaders:** Methods like `def load_config(): return yaml.load(open("config.yml"))` previously threw CWE-502 false positives because the argument was unconditionally seeded with Deserialization taint. The new gate correctly identifies that `load_config` has no parameters and no explicit sources, safely excluding it from seeding.
*   **Test Harnesses:** Deserialization sinks in test setup files are no longer flagged unless they take dynamic parameters.

## Summary
The changes successfully suppressed purely structural false positives without modifying any core taint propagation logic, thereby preserving recall while drastically reducing the FP rate.
