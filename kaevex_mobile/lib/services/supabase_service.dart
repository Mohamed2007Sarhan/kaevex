import 'package:supabase_flutter/supabase_flutter.dart';

class SupabaseService {
  static final SupabaseClient client = Supabase.instance.client;

  // 1. Realtime Telemetry Stream
  static Stream<List<Map<String, dynamic>>> get telemetryStream {
    return client
        .from('telemetry_snapshots')
        .stream(primaryKey: ['id'])
        .order('recorded_at', ascending: false)
        .limit(20);
  }

  // 2. Realtime Devices Stream
  static Stream<List<Map<String, dynamic>>> get devicesStream {
    return client
        .from('devices')
        .stream(primaryKey: ['id'])
        .order('last_seen', ascending: false);
  }

  // 3. Realtime Security Alerts Stream
  static Stream<List<Map<String, dynamic>>> get alertsStream {
    return client
        .from('security_alerts')
        .stream(primaryKey: ['id'])
        .order('created_at', ascending: false)
        .limit(50);
  }

  // 4. Realtime Vulnerabilities Stream
  static Stream<List<Map<String, dynamic>>> get vulnerabilitiesStream {
    return client
        .from('vulnerabilities')
        .stream(primaryKey: ['id'])
        .order('remediated_at', ascending: false);
  }

  // 5. Realtime Action Logs Stream (Remote commands execution status)
  static Stream<List<Map<String, dynamic>>> get actionLogsStream {
    return client
        .from('action_logs')
        .stream(primaryKey: ['id'])
        .order('executed_at', ascending: false)
        .limit(30);
  }

  // 6. Realtime AI Audit Logs Stream
  static Stream<List<Map<String, dynamic>>> get aiLogsStream {
    return client
        .from('ai_audit_logs')
        .stream(primaryKey: ['id'])
        .order('created_at', ascending: false)
        .limit(40);
  }

  // 7. Dispatch Remote Command to Desktop PC via Supabase Cloud Loop
  static Future<void> dispatchRemoteAction({
    required String actionType,
    required String target,
    required String details,
    String hostname = 'DESKTOP-KAEVEX',
  }) async {
    final user = client.auth.currentUser;
    final sender = user?.email ?? 'Mobile SOC Analyst';

    await client.from('action_logs').insert({
      'hostname': hostname,
      'action_type': actionType,
      'target': target,
      'initiated_by': sender,
      'status': 'PENDING',
      'details': details,
      'executed_at': DateTime.now().toIso8601String(),
    });
  }

  // 8. Remotely Request Remediation on a specific CVE
  static Future<void> requestCvePatch({
    required String cveId,
    required String softwareName,
    required String hostname,
  }) async {
    await dispatchRemoteAction(
      actionType: 'PATCH_CVE',
      target: '$softwareName ($cveId)',
      details: 'Remote automated winget/registry patch requested for $cveId',
      hostname: hostname,
    );
  }

  // 9. Send Prompt to AI SOC Analyst and record in Cloud Audit
  static Future<void> recordAiInteraction({
    required String prompt,
    required String response,
    String model = 'deepseek-ai/DeepSeek-V4-Pro-0813',
    int threatLevel = 0,
    String hostname = 'DESKTOP-KAEVEX',
  }) async {
    await client.from('ai_audit_logs').insert({
      'hostname': hostname,
      'prompt': prompt,
      'response': response,
      'model': model,
      'threat_level': threatLevel,
      'created_at': DateTime.now().toIso8601String(),
    });
  }
}
