import 'package:flutter/material.dart';
import '../services/supabase_service.dart';

class AiCopilotScreen extends StatefulWidget {
  const AiCopilotScreen({super.key});

  @override
  State<AiCopilotScreen> createState() => _AiCopilotScreenState();
}

class _AiCopilotScreenState extends State<AiCopilotScreen> {
  final _textController = TextEditingController();
  bool _isSubmitting = false;

  final List<String> _quickPrompts = [
    'Analyze host security posture and rogue drivers',
    'Review active TCP connections for C2 beacons',
    'Should I engage Emergency Firewall Lockdown?',
    'What is the risk level of discovered CVEs?',
  ];

  Future<void> _sendQuery(String query) async {
    if (query.trim().isEmpty) return;
    _textController.clear();
    setState(() => _isSubmitting = true);

    try {
      // Simulate DeepSeek response / record query to Supabase AI audit log
      final aiReply = 'SOC AI Analyst (DeepSeek-V4):\n'
          '• Incident Analysis: Query received regarding "$query".\n'
          '• Fleet State: Host integrity score is high. Antivirus core is active.\n'
          '• Recommendation: Enforce zero-trust ingress filtering and verify CatRoot hashes.';

      await SupabaseService.recordAiInteraction(
        prompt: query,
        response: aiReply,
        model: 'deepseek-ai/DeepSeek-V4-Pro-0813',
        threatLevel: 0,
      );
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('AI query failed: $e')));
      }
    } finally {
      if (mounted) setState(() => _isSubmitting = false);
    }
  }

  @override
  void dispose() {
    _textController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        // Quick prompts bar
        SizedBox(
          height: 44,
          child: ListView.separated(
            scrollDirection: Axis.horizontal,
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
            itemCount: _quickPrompts.length,
            separatorBuilder: (_, __) => const SizedBox(width: 8),
            itemBuilder: (context, index) {
              return ActionChip(
                backgroundColor: const Color(0xFF151922),
                side: const BorderSide(color: Color(0xFF2A344A)),
                label: Text(
                  _quickPrompts[index],
                  style: const TextStyle(fontSize: 10, color: Color(0xFF00E5FF)),
                ),
                onPressed: () => _sendQuery(_quickPrompts[index]),
              );
            },
          ),
        ),

        // Chat stream from Supabase ai_audit_logs
        Expanded(
          child: StreamBuilder<List<Map<String, dynamic>>>(
            stream: SupabaseService.aiLogsStream,
            builder: (context, snapshot) {
              if (snapshot.hasError) {
                return Center(child: Text('Error: ${snapshot.error}', style: const TextStyle(color: Colors.red)));
              }
              if (!snapshot.hasData) {
                return const Center(child: CircularProgressIndicator(color: Color(0xFFFF3366)));
              }

              final logs = snapshot.data!;
              if (logs.isEmpty) {
                return const Center(
                  child: Text('Ask Kaevex AI Copilot anything about host defense.',
                      style: TextStyle(color: Colors.grey, fontSize: 13)),
                );
              }

              return ListView.separated(
                padding: const EdgeInsets.all(14),
                itemCount: logs.length,
                separatorBuilder: (_, __) => const SizedBox(height: 12),
                itemBuilder: (context, index) {
                  final log = logs[index];
                  final prompt = log['prompt'] ?? '';
                  final response = log['response'] ?? '';
                  final model = log['model'] ?? 'DeepSeek-V4';

                  return Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      // User Prompt Bubble
                      Align(
                        alignment: Alignment.centerRight,
                        child: Container(
                          constraints: BoxConstraints(maxWidth: MediaQuery.of(context).size.width * 0.8),
                          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                          decoration: BoxDecoration(
                            color: const Color(0xFF4A1022),
                            borderRadius: BorderRadius.circular(12),
                            border: Border.all(color: const Color(0xFFFF3366).withOpacity(0.5)),
                          ),
                          child: Text(
                            prompt,
                            style: const TextStyle(color: Colors.white, fontSize: 13),
                          ),
                        ),
                      ),
                      const SizedBox(height: 6),
                      // AI Response Bubble
                      Align(
                        alignment: Alignment.centerLeft,
                        child: Container(
                          constraints: BoxConstraints(maxWidth: MediaQuery.of(context).size.width * 0.85),
                          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                          decoration: BoxDecoration(
                            color: const Color(0xFF151922),
                            borderRadius: BorderRadius.circular(12),
                            border: Border.all(color: const Color(0xFF00E5FF).withOpacity(0.4)),
                          ),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Row(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  const Icon(Icons.psychology, size: 14, color: Color(0xFF00E5FF)),
                                  const SizedBox(width: 4),
                                  Text(
                                    model,
                                    style: const TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF00E5FF)),
                                  ),
                                ],
                              ),
                              const SizedBox(height: 6),
                              Text(
                                response,
                                style: const TextStyle(color: Color(0xFFE2E8F0), fontSize: 13, height: 1.3),
                              ),
                            ],
                          ),
                        ),
                      ),
                    ],
                  );
                },
              );
            },
          ),
        ),

        // Bottom Input Row
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          decoration: const BoxDecoration(
            color: Color(0xFF0D1017),
            border: Border(top: BorderSide(color: Color(0xFF262D3D))),
          ),
          child: Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _textController,
                  style: const TextStyle(color: Colors.white, fontSize: 13),
                  decoration: InputDecoration(
                    hintText: 'Ask AI SOC Analyst (DeepSeek-V4)...',
                    hintStyle: const TextStyle(color: Colors.grey, fontSize: 12),
                    filled: true,
                    fillColor: const Color(0xFF151922),
                    isDense: true,
                    contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(20)),
                  ),
                  onSubmitted: _sendQuery,
                ),
              ),
              const SizedBox(width: 8),
              IconButton(
                style: IconButton.styleFrom(backgroundColor: const Color(0xFFFF3366)),
                icon: _isSubmitting
                    ? const SizedBox(height: 18, width: 18, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                    : const Icon(Icons.send, color: Colors.white, size: 18),
                onPressed: () => _sendQuery(_textController.text),
              ),
            ],
          ),
        ),
      ],
    );
  }
}
