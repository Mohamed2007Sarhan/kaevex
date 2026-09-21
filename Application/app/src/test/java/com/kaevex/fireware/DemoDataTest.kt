package com.kaevex.fireware

import com.kaevex.fireware.data.demo.DemoDataProvider
import org.junit.Assert.*
import org.junit.Test

class DemoDataTest {

    @Test
    fun testDashboardIntegrityCalculation() {
        val dashboard = DemoDataProvider.getDemoDashboard(firewallLocked = false)
        assertNotNull(dashboard.server)
        assertEquals("MOHAMED-PC", dashboard.server.hostname)
        assertTrue("Integrity score should be between 0 and 100", dashboard.integrityScore in 0..100)
        assertEquals(8, dashboard.engines.size)
        assertTrue(dashboard.recentAlerts.isNotEmpty())
    }

    @Test
    fun testBootAuditForensics() {
        val bootAudit = DemoDataProvider.getDemoBootAudit()
        assertEquals("SUCCESS", bootAudit.status)
        assertTrue(bootAudit.uefi.secureBootEnabled)
        assertTrue(bootAudit.bcd.testSigningDisabled)
        assertTrue(bootAudit.bootSector.mbrSignatureValid)
        assertEquals("0x55AA", bootAudit.bootSector.mbrMagic)
        assertEquals(8, bootAudit.coreBinaries.size)
        assertTrue(bootAudit.coreBinaries.all { it.catRootStatus == "CATROOT2_MATCH" })
    }

    @Test
    fun testCveComplianceReport() {
        val cveReport = DemoDataProvider.getDemoCveReport()
        assertEquals(94, cveReport.compliance.cisBenchmarkScore)
        assertTrue(cveReport.patchedCves.isNotEmpty())
        assertTrue(cveReport.activeRisks.isNotEmpty())
        val remediable = cveReport.activeRisks.find { it.canAutoRemediate }
        assertNotNull("At least one active risk should support 1-click remediation", remediable)
    }

    @Test
    fun testAiNaturalLanguageActionParsing() {
        // Test Arabic lockdown intent
        val arabicLockdown = DemoDataProvider.parseAiChatResponse("اعزل السيرفر 192.168.1.100 فورا", "red")
        assertNotNull(arabicLockdown.action)
        assertEquals("LOCKDOWN", arabicLockdown.action?.actionType)
        assertEquals("192.168.1.100", arabicLockdown.action?.target)

        // Test English scan intent
        val englishScan = DemoDataProvider.parseAiChatResponse("Run deep scan on host", "blue")
        assertNotNull(englishScan.action)
        assertEquals("SCAN", englishScan.action?.actionType)

        // Test Bootkit intent
        val bootIntent = DemoDataProvider.parseAiChatResponse("افحص البوت كيت", "purple")
        assertNotNull(bootIntent.action)
        assertEquals("BOOT_AUDIT", bootIntent.action?.actionType)
    }
}
