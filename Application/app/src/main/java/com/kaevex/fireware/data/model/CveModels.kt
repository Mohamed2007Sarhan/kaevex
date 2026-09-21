package com.kaevex.fireware.data.model

import com.google.gson.annotations.SerializedName

data class CveReportResponse(
    @SerializedName("status") val status: String = "SUCCESS",
    @SerializedName("compliance") val compliance: ComplianceStatus = ComplianceStatus(),
    @SerializedName("patched_cves") val patchedCves: List<CveItem> = emptyList(),
    @SerializedName("active_risks") val activeRisks: List<CveItem> = emptyList()
)

data class ComplianceStatus(
    @SerializedName("cis_benchmark_score") val cisBenchmarkScore: Int = 94,
    @SerializedName("status_label") val statusLabel: String = "CIS Benchmark: 94% Compliant",
    @SerializedName("nist_score") val nistScore: Int = 91,
    @SerializedName("total_audited_rules") val totalAuditedRules: Int = 120,
    @SerializedName("passed_rules") val passedRules: Int = 113,
    @SerializedName("failed_rules") val failedRules: Int = 7
)

data class CveItem(
    @SerializedName("cve_id") val cveId: String,
    @SerializedName("software_name") val softwareName: String,
    @SerializedName("installed_version") val installedVersion: String,
    @SerializedName("patched_version") val patchedVersion: String = "",
    @SerializedName("severity") val severity: String = "HIGH", // CRITICAL, HIGH, MEDIUM, LOW
    @SerializedName("cvss_score") val cvssScore: Double = 8.5,
    @SerializedName("title") val title: String = "",
    @SerializedName("mitigation_date") val mitigationDate: String = "",
    @SerializedName("patch_status") val patchStatus: String = "WINGET_PATCHED", // WINGET_PATCHED, VENDOR_HOTFIX, PENDING_UPDATE
    @SerializedName("can_auto_remediate") val canAutoRemediate: Boolean = false,
    @SerializedName("remediation_command") val remediationCommand: String = ""
)

data class RemediateRequest(
    @SerializedName("cve_id") val cveId: String,
    @SerializedName("software_name") val softwareName: String,
    @SerializedName("target_version") val targetVersion: String = ""
)

data class RemediateResponse(
    @SerializedName("status") val status: String = "success",
    @SerializedName("message") val message: String = "Patch initiated via Winget package manager",
    @SerializedName("cve_id") val cveId: String = ""
)
