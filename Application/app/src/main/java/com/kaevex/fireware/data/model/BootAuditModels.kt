package com.kaevex.fireware.data.model

import com.google.gson.annotations.SerializedName

data class BootAuditResponse(
    @SerializedName("status") val status: String = "SUCCESS",
    @SerializedName("audit_timestamp") val auditTimestamp: String = "",
    @SerializedName("overall_integrity") val overallIntegrity: String = "PASSED",
    @SerializedName("uefi") val uefi: UefiInfo = UefiInfo(),
    @SerializedName("bcd") val bcd: BcdInfo = BcdInfo(),
    @SerializedName("boot_sector") val bootSector: BootSectorInfo = BootSectorInfo(),
    @SerializedName("core_binaries") val coreBinaries: List<CoreBinaryInfo> = emptyList(),
    @SerializedName("scm") val scm: ScmInfo = ScmInfo()
)

data class UefiInfo(
    @SerializedName("secure_boot_enabled") val secureBootEnabled: Boolean = true,
    @SerializedName("nvram_state") val nvramState: String = "ACTIVE_LOCKED",
    @SerializedName("setup_mode") val setupMode: Boolean = false,
    @SerializedName("vendor") val vendor: String = "American Megatrends (AMI)",
    @SerializedName("details") val details: String = "UEFI Secure Boot active with hardware Root of Trust enforced"
)

data class BcdInfo(
    @SerializedName("test_signing_disabled") val testSigningDisabled: Boolean = true,
    @SerializedName("driver_signing_enforced") val driverSigningEnforced: Boolean = true,
    @SerializedName("no_integrity_checks") val noIntegrityChecks: Boolean = false,
    @SerializedName("hypervisor_launch_type") val hypervisorLaunchType: String = "AUTO",
    @SerializedName("status_text") val statusText: String = "Code Integrity Enforced (Unsigned Drivers Blocked)"
)

data class BootSectorInfo(
    @SerializedName("mbr_signature_valid") val mbrSignatureValid: Boolean = true,
    @SerializedName("mbr_magic") val mbrMagic: String = "0x55AA",
    @SerializedName("bootmgfw_valid") val bootmgfwValid: Boolean = true,
    @SerializedName("authenticode_verified") val authenticodeVerified: Boolean = true,
    @SerializedName("cert_subject") val certSubject: String = "Microsoft Windows Production PCA 2011",
    @SerializedName("hash_sha256") val hashSha256: String = "8A4C2E60...B489",
    @SerializedName("details") val details: String = "ESP bootmgfw.efi and MBR Sector 0 signature verified clean"
)

data class CoreBinaryInfo(
    @SerializedName("binary_name") val binaryName: String,
    @SerializedName("path") val path: String,
    @SerializedName("authenticode") val authenticode: String = "VERIFIED_VALID",
    @SerializedName("catroot_status") val catRootStatus: String = "CATROOT2_MATCH",
    @SerializedName("sha256_prefix") val sha256Prefix: String = "",
    @SerializedName("is_compromised") val isCompromised: Boolean = false
)

data class ScmInfo(
    @SerializedName("total_services_audited") val totalServicesAudited: Int = 296,
    @SerializedName("rogue_masqueraders") val rogueMasqueraders: Int = 0,
    @SerializedName("kernel_drivers_in_ram") val kernelDriversInRam: Int = 184,
    @SerializedName("unsigned_drivers_in_ram") val unsignedDriversInRam: Int = 0,
    @SerializedName("details") val details: String = "Zero rogue masqueraders detected in Windows Service Control Manager"
)
