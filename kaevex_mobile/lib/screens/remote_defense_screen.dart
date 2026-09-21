import 'package:flutter/material.dart';
import '../services/supabase_service.dart';

class RemoteDefenseScreen extends StatefulWidget {
  const RemoteDefenseScreen({super.key});

  @override
  State<RemoteDefenseScreen> createState() => _RemoteDefenseScreenState();
}

class _RemoteDefenseScreenState extends State<RemoteDefenseScreen> {
  final _procController = TextEditingController();

  Future<void> _sendAction(String type, String target, String details) async {
    try {
      await SupabaseService.dispatchRemoteAction(
        actionType: type,
        target: target,
        details: details,
      );
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Command dispatched: $type ($target)'),
            backgroundColor: const Color(0xFF10B981),
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed: $e'), backgroundColor: Colors.red),
        );
      }
    }
  }

  @override
  void dispose() {
    _procController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text('REMOTE COMMAND CENTER',
              style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Color(0xFF64748B), letterSpacing: 1.1)),
          const SizedBox(height: 12),

          // Primary Lockdown Control Card
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              gradient: const LinearGradient(
                colors: [Color(0xFF2A141E), Color(0xFF151922)],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
              borderRadius: BorderRadius.circular(14),
              border: Border.all(color: const Color(0xFFFF3366).withOpacity(0.5)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Row(
                  children: [
                    Icon(Icons.shield, color: Color(0xFFFF3366), size: 22),
                    SizedBox(width: 8),
                    Text('Emergency Fleet Isolation', style: TextStyle(fontSize: 15, fontWeight: FontWeight.bold, color: Colors.white)),
                  ],
                ),
                const SizedBox(height: 6),
                const Text(
                  'Instantly cuts all inbound and outbound TCP/UDP traffic on the host Windows machine using native Windows Filtering Platform (WFP).',
                  style: TextStyle(fontSize: 12, color: Color(0xFF94A3B8)),
                ),
                const SizedBox(height: 14),
                Row(
                  children: [
                    Expanded(
                      child: ElevatedButton.icon(
                        style: ElevatedButton.styleFrom(
                          backgroundColor: const Color(0xFFEF4444),
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(vertical: 12),
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                        ),
                        icon: const Icon(Icons.lock, size: 16),
                        label: const Text('ENGAGE LOCKDOWN', style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold)),
                        onPressed: () => _sendAction('EMERGENCY_LOCKDOWN', 'FIREWALL', 'Isolate all external network interfaces'),
                      ),
                    ),
                    const SizedBox(width: 10),
                    Expanded(
                      child: OutlinedButton.icon(
                        style: OutlinedButton.styleFrom(
                          foregroundColor: const Color(0xFF10B981),
                          side: const BorderSide(color: Color(0xFF10B981)),
                          padding: const EdgeInsets.symmetric(vertical: 12),
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                        ),
                        icon: const Icon(Icons.lock_open, size: 16),
                        label: const Text('DISENGAGE', style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold)),
                        onPressed: () => _sendAction('DISENGAGE_LOCKDOWN', 'FIREWALL', 'Restore standard firewall rules'),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),

          // Process Kill & Sandbox Controls
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: const Color(0xFF151922),
              borderRadius: BorderRadius.circular(14),
              border: Border.all(color: const Color(0xFF262D3D)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('Process Termination & Sandbox Kill', style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold, color: Colors.white)),
                const SizedBox(height: 10),
                Row(
                  children: [
                    Expanded(
                      child: TextField(
                        controller: _procController,
                        style: const TextStyle(color: Colors.white, fontSize: 13),
                        decoration: InputDecoration(
                          hintText: 'Process name (e.g. malware.exe)',
                          hintStyle: const TextStyle(color: Colors.grey, fontSize: 12),
                          filled: true,
                          fillColor: const Color(0xFF0B0E14),
                          isDense: true,
                          contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
                          border: OutlineInputBorder(borderRadius: BorderRadius.circular(8)),
                        ),
                      ),
                    ),
                    const SizedBox(width: 8),
                    ElevatedButton(
                      style: ElevatedButton.styleFrom(
                        backgroundColor: const Color(0xFFF97316),
                        foregroundColor: Colors.white,
                        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                      ),
                      onPressed: () {
                        final p = _procController.text.trim();
                        if (p.isNotEmpty) {
                          _sendAction('TERMINATE_PROCESS', p, 'Remote process termination from mobile');
                          _procController.clear();
                        }
                      },
                      child: const Text('Kill PID', style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold)),
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                OutlinedButton.icon(
                  style: OutlinedButton.styleFrom(
                    foregroundColor: const Color(0xFF00E5FF),
                    side: const BorderSide(color: Color(0xFF00E5FF)),
                    minimumSize: const Size(double.infinity, 38),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                  ),
                  icon: const Icon(Icons.cancel_outlined, size: 16),
                  label: const Text('TERMINATE ACTIVE SMARTSANDBOX', style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold)),
                  onPressed: () => _sendAction('KILL_SANDBOX', 'CONTAINER', 'Terminate sandboxed binary execution'),
                ),
              ],
            ),
          ),
          const SizedBox(height: 20),

          // Live Execution Audit Trail
          const Text('REALTIME CLOUD COMMAND EXECUTION AUDIT',
              style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Color(0xFF64748B), letterSpacing: 1.1)),
          const SizedBox(height: 10),

          StreamBuilder<List<Map<String, dynamic>>>(
            stream: SupabaseService.actionLogsStream,
            builder: (context, snapshot) {
              if (!snapshot.hasData) {
                return const Center(child: CircularProgressIndicator(color: Color(0xFFFF3366)));
              }
              final logs = snapshot.data!;
              if (logs.isEmpty) {
                return const Text('No remote actions executed yet.', style: TextStyle(color: Colors.grey, fontSize: 12));
              }

              return ListView.separated(
                shrinkWrap: true,
                physics: const NeverScrollableScrollPhysics(),
                itemCount: logs.length,
                separatorBuilder: (_, __) => const SizedBox(height: 8),
                itemBuilder: (context, index) {
                  final l = logs[index];
                  final act = l['action_type'] ?? '';
                  final target = l['target'] ?? '';
                  final status = l['status'] ?? 'PENDING';
                  final by = l['initiated_by'] ?? '';
                  final isDone = status == 'COMPLETED';

                  return Container(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                    decoration: BoxDecoration(
                      color: const Color(0xFF151922),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: isDone ? const Color(0xFF10B981).withOpacity(0.3) : const Color(0xFFF59E0B).withOpacity(0.3)),
                    ),
                    child: Row(
                      children: [
                        Icon(isDone ? Icons.check_circle : Icons.hourglass_top,
                            size: 16, color: isDone ? const Color(0xFF10B981) : const Color(0xFFF59E0B)),
                        const SizedBox(width: 10),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text('$act  →  $target', style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 12, color: Colors.white)),
                              Text('By: $by', style: const TextStyle(fontSize: 10, color: Color(0xFF94A3B8))),
                            ],
                          ),
                        ),
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                          decoration: BoxDecoration(
                            color: isDone ? const Color(0xFF10B981).withOpacity(0.2) : const Color(0xFFF59E0B).withOpacity(0.2),
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: Text(
                            status,
                            style: TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: isDone ? const Color(0xFF10B981) : const Color(0xFFF59E0B)),
                          ),
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
    );
  }
}
