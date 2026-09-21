import 'package:flutter/material.dart';
import '../services/supabase_service.dart';

class DashboardScreen extends StatelessWidget {
  const DashboardScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return StreamBuilder<List<Map<String, dynamic>>>(
      stream: SupabaseService.telemetryStream,
      builder: (context, snapshot) {
        if (snapshot.hasError) {
          return Center(child: Text('Stream error: ${snapshot.error}', style: const TextStyle(color: Colors.red)));
        }
        if (!snapshot.hasData || snapshot.data!.isEmpty) {
          return const Center(child: CircularProgressIndicator(color: Color(0xFFFF3366)));
        }

        final latest = snapshot.data!.first;
        final cpu = latest['cpu_usage'] ?? 0;
        final ramUsed = latest['memory_usage_mb'] ?? 0;
        final ramTotal = (latest['total_memory_mb'] ?? 16384) > 0 ? (latest['total_memory_mb'] ?? 16384) : 16384;
        final ramPct = ((ramUsed / ramTotal) * 100).clamp(0, 100).toInt();
        final conns = latest['active_connections'] ?? 0;
        final wafBlocks = latest['waf_blocked_requests'] ?? 0;
        final threatScore = latest['threat_score'] ?? 0;

        return RefreshIndicator(
          onRefresh: () async {
            // Stream automatically refreshes via realtime
          },
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Top Node Overview Banner
                StreamBuilder<List<Map<String, dynamic>>>(
                  stream: SupabaseService.devicesStream,
                  builder: (context, devSnap) {
                    final dev = (devSnap.hasData && devSnap.data!.isNotEmpty)
                        ? devSnap.data!.first
                        : <String, dynamic>{};
                    final host = dev['hostname'] ?? latest['hostname'] ?? 'DESKTOP-KAEVEX';
                    final os = dev['os_version'] ?? 'Windows Host';
                    final ip = dev['primary_ip'] ?? '127.0.0.1';
                    final status = dev['status'] ?? 'ONLINE';

                    return Container(
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        gradient: const LinearGradient(
                          colors: [Color(0xFF1B2232), Color(0xFF131722)],
                          begin: Alignment.topLeft,
                          end: Alignment.bottomRight,
                        ),
                        borderRadius: BorderRadius.circular(14),
                        border: Border.all(color: const Color(0xFF2A344A)),
                      ),
                      child: Row(
                        children: [
                          Container(
                            padding: const EdgeInsets.all(12),
                            decoration: BoxDecoration(
                              color: const Color(0xFF00E5FF).withOpacity(0.12),
                              borderRadius: BorderRadius.circular(10),
                            ),
                            child: const Icon(Icons.computer, color: Color(0xFF00E5FF), size: 30),
                          ),
                          const SizedBox(width: 14),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Row(
                                  children: [
                                    Text(
                                      host,
                                      style: const TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: Colors.white),
                                    ),
                                    const SizedBox(width: 8),
                                    Container(
                                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                      decoration: BoxDecoration(
                                        color: (status == 'ONLINE') ? const Color(0xFF10B981).withOpacity(0.2) : const Color(0xFFEF4444).withOpacity(0.2),
                                        borderRadius: BorderRadius.circular(4),
                                      ),
                                      child: Text(
                                        status,
                                        style: TextStyle(
                                          fontSize: 9,
                                          fontWeight: FontWeight.bold,
                                          color: (status == 'ONLINE') ? const Color(0xFF10B981) : const Color(0xFFEF4444),
                                        ),
                                      ),
                                    ),
                                  ],
                                ),
                                const SizedBox(height: 3),
                                Text(os, style: const TextStyle(fontSize: 11, color: Color(0xFF94A3B8))),
                                Text('IP: $ip  |  Sockets: $conns active', style: const TextStyle(fontSize: 11, color: Color(0xFF64748B))),
                              ],
                            ),
                          ),
                        ],
                      ),
                    );
                  },
                ),
                const SizedBox(height: 18),

                const Text('REAL-TIME HARDWARE & NETWORK TELEMETRY',
                    style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Color(0xFF64748B), letterSpacing: 1.1)),
                const SizedBox(height: 10),

                // 2x2 Telemetry Grid
                GridView.count(
                  shrinkWrap: true,
                  physics: const NeverScrollableScrollPhysics(),
                  crossAxisCount: 2,
                  crossAxisSpacing: 12,
                  mainAxisSpacing: 12,
                  childAspectRatio: 1.35,
                  children: [
                    _buildMetricCard(
                      title: 'Kernel CPU Load',
                      value: '$cpu%',
                      subtitle: 'Hardware clock cycle diff',
                      color: cpu > 80 ? const Color(0xFFEF4444) : const Color(0xFF00E5FF),
                      icon: Icons.memory,
                      progress: cpu / 100.0,
                    ),
                    _buildMetricCard(
                      title: 'Physical RAM',
                      value: '$ramPct%',
                      subtitle: '${(ramUsed / 1024).toStringAsFixed(1)} GB / ${(ramTotal / 1024).toStringAsFixed(0)} GB',
                      color: const Color(0xFF10B981),
                      icon: Icons.storage,
                      progress: ramPct / 100.0,
                    ),
                    _buildMetricCard(
                      title: 'Active TCP Sockets',
                      value: '$conns',
                      subtitle: 'Kernel TCP table poll',
                      color: const Color(0xFFF59E0B),
                      icon: Icons.wifi_tethering,
                      progress: (conns / 50.0).clamp(0.0, 1.0),
                    ),
                    _buildMetricCard(
                      title: 'WAF Blocks',
                      value: '$wafBlocks',
                      subtitle: 'SQLi & XSS drops',
                      color: const Color(0xFFFF3366),
                      icon: Icons.security,
                      progress: (wafBlocks / 20.0).clamp(0.0, 1.0),
                    ),
                  ],
                ),
                const SizedBox(height: 18),

                // Quick Remote Defense Bar
                Container(
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    color: const Color(0xFF151922),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: const Color(0xFF262D3D)),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Row(
                        children: [
                          Icon(Icons.bolt, color: Color(0xFFFF3366), size: 18),
                          SizedBox(width: 6),
                          Text('REMOTE CLOUD ACTIONS', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13, color: Colors.white)),
                        ],
                      ),
                      const SizedBox(height: 10),
                      Row(
                        children: [
                          Expanded(
                            child: ElevatedButton.icon(
                              style: ElevatedButton.styleFrom(
                                backgroundColor: const Color(0xFFEF4444).withOpacity(0.2),
                                foregroundColor: const Color(0xFFEF4444),
                                side: const BorderBorder(color: Color(0xFFEF4444), width: 1),
                                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                              ),
                              icon: const Icon(Icons.lock, size: 16),
                              label: const Text('Lockdown', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
                              onPressed: () async {
                                await SupabaseService.dispatchRemoteAction(
                                  actionType: 'EMERGENCY_LOCKDOWN',
                                  target: 'FIREWALL',
                                  details: 'Remote Emergency Isolation triggered from Mobile App',
                                );
                                if (context.mounted) {
                                  ScaffoldMessenger.of(context).showSnackBar(
                                    const SnackBar(content: Text('Lockdown command dispatched to Windows host!')),
                                  );
                                }
                              },
                            ),
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            child: ElevatedButton.icon(
                              style: ElevatedButton.styleFrom(
                                backgroundColor: const Color(0xFF00E5FF).withOpacity(0.2),
                                foregroundColor: const Color(0xFF00E5FF),
                                side: const BorderBorder(color: Color(0xFF00E5FF), width: 1),
                                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                              ),
                              icon: const Icon(Icons.radar, size: 16),
                              label: const Text('Deep Scan', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
                              onPressed: () async {
                                await SupabaseService.dispatchRemoteAction(
                                  actionType: 'DEEP_SCAN',
                                  target: 'ALL_PROCESSES',
                                  details: 'Full Antivirus & Bootkit scan triggered remotely',
                                );
                                if (context.mounted) {
                                  ScaffoldMessenger.of(context).showSnackBar(
                                    const SnackBar(content: Text('Deep Scan dispatched to Windows host!')),
                                  );
                                }
                              },
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _buildMetricCard({
    required String title,
    required String value,
    required String subtitle,
    required Color color,
    required IconData icon,
    required double progress,
  }) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: const Color(0xFF151922),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF262D3D)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(title, style: const TextStyle(fontSize: 11, color: Color(0xFF94A3B8))),
              Icon(icon, size: 16, color: color),
            ],
          ),
          Text(
            value,
            style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold, color: color),
          ),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              ClipRRect(
                borderRadius: BorderRadius.circular(3),
                child: LinearProgressIndicator(
                  value: progress.clamp(0.0, 1.0),
                  backgroundColor: const Color(0xFF0B0E14),
                  valueColor: AlwaysStoppedAnimation<Color>(color),
                  minHeight: 4,
                ),
              ),
              const SizedBox(height: 4),
              Text(subtitle, style: const TextStyle(fontSize: 9, color: Color(0xFF64748B))),
            ],
          ),
        ],
      ),
    );
  }
}
