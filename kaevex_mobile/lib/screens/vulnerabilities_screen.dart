import 'package:flutter/material.dart';
import '../services/supabase_service.dart';

class VulnerabilitiesScreen extends StatefulWidget {
  const VulnerabilitiesScreen({super.key});

  @override
  State<VulnerabilitiesScreen> createState() => _VulnerabilitiesScreenState();
}

class _VulnerabilitiesScreenState extends State<VulnerabilitiesScreen> {
  String _filter = 'ALL';

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        // Filter tabs
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
          child: Row(
            children: ['ALL', 'DISCOVERED', 'PATCHED'].map((f) {
              final isSel = _filter == f;
              return Padding(
                padding: const EdgeInsets.only(right: 8),
                child: ChoiceChip(
                  label: Text(f, style: TextStyle(fontSize: 11, fontWeight: isSel ? FontWeight.bold : FontWeight.normal)),
                  selected: isSel,
                  selectedColor: const Color(0xFFFF3366),
                  backgroundColor: const Color(0xFF151922),
                  onSelected: (val) {
                    if (val) setState(() => _filter = f);
                  },
                ),
              );
            }).toList(),
          ),
        ),

        Expanded(
          child: StreamBuilder<List<Map<String, dynamic>>>(
            stream: SupabaseService.vulnerabilitiesStream,
            builder: (context, snapshot) {
              if (snapshot.hasError) {
                return Center(child: Text('Error: ${snapshot.error}', style: const TextStyle(color: Colors.red)));
              }
              if (!snapshot.hasData) {
                return const Center(child: CircularProgressIndicator(color: Color(0xFFFF3366)));
              }

              var list = snapshot.data!;
              if (_filter != 'ALL') {
                list = list.where((v) => (v['status'] ?? '').toString().toUpperCase() == _filter).toList();
              }

              if (list.isEmpty) {
                return const Center(
                  child: Text('No matching CVE vulnerabilities found.', style: TextStyle(color: Colors.grey)),
                );
              }

              return ListView.separated(
                padding: const EdgeInsets.all(14),
                itemCount: list.length,
                separatorBuilder: (_, __) => const SizedBox(height: 10),
                itemBuilder: (context, index) {
                  final v = list[index];
                  final cve = v['cve_id'] ?? 'CVE-XXXX';
                  final sw = v['software_name'] ?? 'Software';
                  final ver = v['installed_version'] ?? 'N/A';
                  final sev = v['severity'] ?? 'HIGH';
                  final status = v['status'] ?? 'DISCOVERED';
                  final cvss = v['cvss_score'] ?? 7.5;
                  final action = v['action_taken'] ?? 'Pending analysis';
                  final host = v['hostname'] ?? 'DESKTOP-KAEVEX';
                  final isPatched = status == 'PATCHED';

                  return Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: const Color(0xFF151922),
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: isPatched ? const Color(0xFF10B981).withOpacity(0.3) : const Color(0xFFEF4444).withOpacity(0.3)),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                              decoration: BoxDecoration(
                                color: const Color(0xFFFF3366).withOpacity(0.2),
                                borderRadius: BorderRadius.circular(4),
                              ),
                              child: Text(cve, style: const TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Color(0xFFFF3366))),
                            ),
                            const SizedBox(width: 8),
                            Text('CVSS $cvss', style: const TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Color(0xFFF59E0B))),
                            const Spacer(),
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                              decoration: BoxDecoration(
                                color: isPatched ? const Color(0xFF10B981).withOpacity(0.2) : const Color(0xFFEF4444).withOpacity(0.2),
                                borderRadius: BorderRadius.circular(4),
                              ),
                              child: Text(
                                status,
                                style: TextStyle(
                                  fontSize: 10,
                                  fontWeight: FontWeight.bold,
                                  color: isPatched ? const Color(0xFF10B981) : const Color(0xFFEF4444),
                                ),
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 8),
                        Text('$sw (v$ver)', style: const TextStyle(fontSize: 13, fontWeight: FontWeight.bold, color: Colors.white)),
                        const SizedBox(height: 4),
                        Text('Remediation: $action', style: const TextStyle(fontSize: 11, color: Color(0xFF94A3B8))),
                        if (!isPatched) ...[
                          const SizedBox(height: 10),
                          Align(
                            alignment: Alignment.centerRight,
                            child: ElevatedButton.icon(
                              style: ElevatedButton.styleFrom(
                                backgroundColor: const Color(0xFF00E5FF).withOpacity(0.15),
                                foregroundColor: const Color(0xFF00E5FF),
                                side: const BorderSide(color: Color(0xFF00E5FF)),
                                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
                              ),
                              icon: const Icon(Icons.build, size: 14),
                              label: const Text('Remote 1-Tap Fix', style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold)),
                              onPressed: () async {
                                await SupabaseService.requestCvePatch(
                                  cveId: cve,
                                  softwareName: sw,
                                  hostname: host,
                                );
                                if (context.mounted) {
                                  ScaffoldMessenger.of(context).showSnackBar(
                                    SnackBar(content: Text('Remediation dispatched for $cve ($sw)')),
                                  );
                                }
                              },
                            ),
                          ),
                        ],
                      ],
                    ),
                  );
                },
              );
            },
          ),
        ),
      ],
    );
  }
}
