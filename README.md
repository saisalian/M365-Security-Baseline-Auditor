# M365 Security Baseline Auditor + Fixer

## Overview
This project aims to simulate securing a real-world Microsoft 365 tenant by building a tool that audits security configurations and identifies gaps based on a defined baseline.

## Goal
- Assess tenant security posture
- Identify misconfigurations
- Provide actionable remediation guidance
- (Future) Automate fixes

---

## Current Features

### 🔐 Secure Tenant Connection
- Connects to Microsoft Graph using tenant-specific authentication
- Supports device-based login (ideal for MSP environments)
- Prevents silent session reuse across tenants
- Displays connected account and tenant details

---

## Why this matters
In multi-tenant MSP environments, authentication sessions can persist and accidentally connect to the wrong tenant.  
This tool enforces explicit tenant selection to ensure accurate and secure auditing.

---

### 👤 Identity Audit – MFA Registration Check
- Retrieves users from the connected tenant
- Checks registered authentication methods for each user
- Identifies users without MFA methods configured
- Separately reports lookup failures for transparency

This check validates MFA registration readiness, not full MFA enforcement. Actual enforcement depends on Conditional Access, Security Defaults, or other authentication controls.

---

### 🛡️ Conditional Access Audit
- Retrieves Conditional Access policies from the tenant
- Lists configured policy names
- Detects policies that require MFA
- Detects policies likely intended to block legacy authentication

## Sample Findings

- Detected 13 Conditional Access policies in tenant
- Identified multiple MFA enforcement policies
- Detected legacy authentication blocking policies
- Observed classification limitations (e.g., BYOD policy flagged as legacy auth)

### Notes
This highlights the need for deeper policy inspection beyond basic condition matching.
---

## Status
- Phase 1 – Project setup ✅
- Phase 2 – Secure connection module ✅
- Phase 3 – MFA registration audit ✅
- Phase 4 – Conditional Access audit ✅