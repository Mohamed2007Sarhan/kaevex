import 'package:flutter/material.dart';
import '../services/supabase_service.dart';

class AlertsScreen extends StatefulWidget {
  const AlertsScreen({super.key});

  @override
  State<AlertsScreen> createState() => _AlertsScreenState();
}

class _AlertsScreenState extends State<AlertsScreen> {
  String _selectedSeverity = 'ALL';

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        // Filter Bar
        SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
          child: Row(
            children: ['ALL', 'CRITICAL', 'HIGH', 'WARNING', 'INFO'].map((sev) {
              final isSel = _selectedSeverity == sev;
              return Padding(
                padding: const EdgeInsets.only(right: 8),
                child: ChoiceChip(
                  label: Text(sev, style: TextStyle(fontSize: 11, fontWeight: isSel ? FontWeight.bold : FontWeight.normal)),
                  selected: isSel,
                  selectedColor: const Color(0xFFFF3366),
                  backgroundColor: const Color(0xFF151922),
                  onSelected: (selected) {
                    if (selected) setState(() => _selectedSeverity = sev);
                  },
                ),
              );
            }).toList(),
          ),
        ),

        Expanded(
          child: StreamBuilder<List<Map<String, dynamic>>>(
            stream: SupabaseService.alertsStream,
            builder: (context, snapshot) {
              if (snapshot.hasError) {
                return Center(child: Text('Error: ${snapshot.error}', style: const TextStyle(color: Colors.red)));
              }
              if (!snapshot.hasData) {
                return const Center(child: CircularProgressIndicator(color: Color(0xFFFF3366)));
              }

              var alerts = snapshot.data!;
              if (_selectedSeverity != 'ALL') {
                alerts = alerts.where((a) => (a['severity'] ?? '').toString().toUpperCase() == _selectedSeverity).toList();
              }

              if (alerts.isEmpty) {
                return const Center(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(Icons.shield_outlined, size: 48, color: Color(0xFF10B981)),
                      SizedBox(height: 12),
                      Text('No security incidents detected.', style: TextStyle(color: Colors.grey)),
                    ],
                  ),
                );
              }

              return ListView.separated(
                padding: const EdgeInsets.all(14),
                itemCount: alerts.length,
                separatorBuilder: (_, __) => const SizedBox(height: 10),
                itemBuilder: (context, index) {
                  final a = alerts[index];
                  final sev = (a['severity'] ?? 'INFO').toString().toUpperCase();
                  final title = a['title'] ?? 'Security Event';
                  final engine = a['engine'] ?? 'Defense Core';
                  final srcIp = a['src_ip'] ?? 'Local';
                  final attck = a['attck_tag'] ?? 'N/A';
                  final blocked = a['is_blocked'] ?? false;
                  final time = a['created_at'] != null ? a['created_at'].toString().split('T').last.split('.').first : '';

                  Color sevColor;
                  switch (sev) {
                    case 'CRITICAL':
                      sevColor = const Color(0xFFEF4444);
                      break;
                    case 'HIGH':
                      sevColor = const Color(0xFFF97316);
                      break;
                    case 'WARNING':
                      sevColor = const Color(0xFFF59E0B);
                      break;
                    default:
                      sevColor = const Color(0xFF00E5FF);
                  }

                  return Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: const Color(0xFF151922),
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: sevColor.withOpacity(0.35)),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                              decoration: BoxDecoration(
                                color: sevColor.withOpacity(0.18),
                                borderRadius: BorderRadius.circular(4),
                                border: Border.all(color: sevColor, width: 0.8),
                              ),
                              child: Text(sev, style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: sevColor)),
                            ),
                            const SizedBox(width: 8),
                            Text(engine, style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 12, color: Colors.white)),
                            const Spacer(),
                            if (blocked)
                              Container(
                                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                decoration: BoxDecoration(
                                  color: const Color(0xFF10B981).withOpacity(0.2),
                                  borderRadius: BorderRadius.circular(4),
                                ),
                                child: const Text('BLOCKED', style: TextStyle(fontSize: 9, color: Color(0xFF10B981), fontWeight: FontWeight.bold)),
                              ),
                            const SizedBox(width: 6),
                            Text(time, style: const TextStyle(fontSize: 10, color: Color(0xFF64748B))),
                          ],
                        ),
                        const SizedBox(height: 8),
                        Text(title, style: const TextStyle(fontSize: 13, color: Color(0xFFE2E8F0))),
                        const SizedBox(height: 6),
                        Row(
                          children: [
                            const Icon(Icons.pin_drop, size: 12, color: Color(0xFF94A3B8)),
                            const SizedBox(width: 4),
                            Text('Src: $srcIp', style: const TextStyle(fontSize: 11, color: Color(0xFF94A3B8))),
                            const SizedBox(width: 14),
                            const Icon(Icons.tag, size: 12, color: Color(0xFF94A3B8)),
                            const SizedBox(width: 4),
                            Text(attck, style: const TextStyle(fontSize: 11, color: Color(0xFF94A3B8))),
                          ],
                        ),
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
