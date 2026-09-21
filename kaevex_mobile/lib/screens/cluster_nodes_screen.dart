import 'package:flutter/material.dart';
import 'package:supabase_flutter/supabase_flutter.dart';
import '../services/supabase_service.dart';

class ClusterNodesScreen extends StatelessWidget {
  const ClusterNodesScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final client = Supabase.instance.client;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Fleet Nodes & SOC Team'),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('REGISTERED FLEET DEVICES',
                style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Color(0xFF64748B), letterSpacing: 1.1)),
            const SizedBox(height: 10),

            StreamBuilder<List<Map<String, dynamic>>>(
              stream: SupabaseService.devicesStream,
              builder: (context, snapshot) {
                if (!snapshot.hasData) {
                  return const Center(child: CircularProgressIndicator(color: Color(0xFFFF3366)));
                }
                final devs = snapshot.data!;
                if (devs.isEmpty) {
                  return const Text('No devices registered.', style: TextStyle(color: Colors.grey));
                }

                return ListView.separated(
                  shrinkWrap: true,
                  physics: const NeverScrollableScrollPhysics(),
                  itemCount: devs.length,
                  separatorBuilder: (_, __) => const SizedBox(height: 10),
                  itemBuilder: (context, index) {
                    final d = devs[index];
                    final host = d['hostname'] ?? 'DESKTOP-KAEVEX';
                    final os = d['os_version'] ?? 'Windows Host';
                    final ip = d['primary_ip'] ?? '127.0.0.1';
                    final conns = d['active_connections'] ?? 0;
                    final prof = d['security_profile'] ?? 'Enterprise SOC';
                    final status = d['status'] ?? 'ONLINE';
                    final isOnline = status == 'ONLINE';

                    return Container(
                      padding: const EdgeInsets.all(14),
                      decoration: BoxDecoration(
                        color: const Color(0xFF151922),
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(color: const Color(0xFF262D3D)),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Icon(Icons.desktop_windows, size: 18, color: isOnline ? const Color(0xFF10B981) : Colors.red),
                              const SizedBox(width: 8),
                              Text(host, style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 14, color: Colors.white)),
                              const Spacer(),
                              Container(
                                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                decoration: BoxDecoration(
                                  color: isOnline ? const Color(0xFF10B981).withOpacity(0.2) : Colors.red.withOpacity(0.2),
                                  borderRadius: BorderRadius.circular(4),
                                ),
                                child: Text(status, style: TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: isOnline ? const Color(0xFF10B981) : Colors.red)),
                              ),
                            ],
                          ),
                          const SizedBox(height: 8),
                          Text('OS: $os', style: const TextStyle(fontSize: 11, color: Color(0xFF94A3B8))),
                          Text('Primary IP: $ip  |  Active TCP Sockets: $conns', style: const TextStyle(fontSize: 11, color: Color(0xFF94A3B8))),
                          Text('Profile: $prof', style: const TextStyle(fontSize: 11, color: Color(0xFF00E5FF))),
                        ],
                      ),
                    );
                  },
                );
              },
            ),

            const SizedBox(height: 24),
            const Text('SOC TEAM MEMBERS & DIRECTION',
                style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Color(0xFF64748B), letterSpacing: 1.1)),
            const SizedBox(height: 10),

            StreamBuilder<List<Map<String, dynamic>>>(
              stream: client.from('team_members').stream(primaryKey: ['id']),
              builder: (context, snapshot) {
                if (!snapshot.hasData) {
                  return const Center(child: CircularProgressIndicator(color: Color(0xFFFF3366)));
                }
                final team = snapshot.data!;
                if (team.isEmpty) {
                  return const Text('No team members found.', style: TextStyle(color: Colors.grey));
                }

                return ListView.separated(
                  shrinkWrap: true,
                  physics: const NeverScrollableScrollPhysics(),
                  itemCount: team.length,
                  separatorBuilder: (_, __) => const SizedBox(height: 8),
                  itemBuilder: (context, index) {
                    final m = team[index];
                    final name = m['name'] ?? 'Analyst';
                    final role = m['role'] ?? 'SOC_OPERATOR';
                    final email = m['email'] ?? '';
                    final dir = m['direction'] ?? 'Security Operations';
                    final clr = m['clearance'] ?? 'TIER_3';

                    return Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: const Color(0xFF151922),
                        borderRadius: BorderRadius.circular(10),
                        border: Border.all(color: const Color(0xFF262D3D)),
                      ),
                      child: Row(
                        children: [
                          CircleAvatar(
                            radius: 18,
                            backgroundColor: const Color(0xFFFF3366).withOpacity(0.2),
                            child: Text(name.isNotEmpty ? name[0].toUpperCase() : 'U',
                                style: const TextStyle(fontWeight: FontWeight.bold, color: Color(0xFFFF3366))),
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(name, style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13, color: Colors.white)),
                                Text('$email  ($clr)', style: const TextStyle(fontSize: 10, color: Color(0xFF94A3B8))),
                                Text('Focus: $dir', style: const TextStyle(fontSize: 10, color: Color(0xFF00E5FF))),
                              ],
                            ),
                          ),
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                            decoration: BoxDecoration(
                              color: const Color(0xFF262D3D),
                              borderRadius: BorderRadius.circular(4),
                            ),
                            child: Text(role, style: const TextStyle(fontSize: 9, color: Colors.white70)),
                          ),
                        ],
                      ),
                    );
                  },
                );
              },
            ),
          ],
        ),
      ),
    );
  }
}
