import 'package:flutter/material.dart';
import 'package:supabase_flutter/supabase_flutter.dart';
import 'screens/auth_screen.dart';
import 'screens/dashboard_screen.dart';
import 'screens/alerts_screen.dart';
import 'screens/remote_defense_screen.dart';
import 'screens/vulnerabilities_screen.dart';
import 'screens/ai_copilot_screen.dart';
import 'screens/cluster_nodes_screen.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await Supabase.initialize(
    url: 'https://lqvijkatveozunxzlaid.supabase.co',
    anonKey: 'sb_publishable_87D-MbAPOprfjvY8CkLNnQ_KvIOBjhj',
  );
  runApp(const KaevexApp());
}

class KaevexApp extends StatelessWidget {
  const KaevexApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Kaevex SOC Enterprise',
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark().copyWith(
        scaffoldBackgroundColor: const Color(0xFF0B0E14),
        primaryColor: const Color(0xFFFF3366),
        cardColor: const Color(0xFF151922),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFFFF3366),
          secondary: Color(0xFF00E5FF),
          surface: Color(0xFF151922),
          error: Color(0xFFEF4444),
        ),
        appBarTheme: const AppBarTheme(
          backgroundColor: Color(0xFF0D1017),
          elevation: 0,
          centerTitle: false,
          titleTextStyle: TextStyle(
            color: Colors.white,
            fontSize: 18,
            fontWeight: FontWeight.bold,
            letterSpacing: 0.5,
          ),
        ),
        bottomNavigationBarTheme: const BottomNavigationBarThemeData(
          backgroundColor: Color(0xFF0D1017),
          selectedItemColor: Color(0xFFFF3366),
          unselectedItemColor: Color(0xFF6B7280),
          selectedLabelStyle: TextStyle(fontWeight: FontWeight.bold, fontSize: 11),
          unselectedLabelStyle: TextStyle(fontSize: 10),
          type: BottomNavigationBarType.fixed,
        ),
      ),
      home: const AuthGate(),
    );
  }
}

class AuthGate extends StatelessWidget {
  const AuthGate({super.key});

  @override
  Widget build(BuildContext context) {
    return StreamBuilder<AuthState>(
      stream: Supabase.instance.client.auth.onAuthStateChange,
      builder: (context, snapshot) {
        final session = Supabase.instance.client.auth.currentSession;
        if (session != null) {
          return const MainShell();
        }
        return const AuthScreen();
      },
    );
  }
}

class MainShell extends StatefulWidget {
  const MainShell({super.key});

  @override
  State<MainShell> createState() => _MainShellState();
}

class _MainShellState extends State<MainShell> {
  int _currentIndex = 0;

  final List<Widget> _screens = const [
    DashboardScreen(),
    AlertsScreen(),
    RemoteDefenseScreen(),
    VulnerabilitiesScreen(),
    AiCopilotScreen(),
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 4),
              decoration: BoxDecoration(
                color: const Color(0xFFFF3366),
                borderRadius: BorderRadius.circular(6),
              ),
              child: const Text(
                'K',
                style: TextStyle(fontWeight: FontWeight.w900, color: Colors.white, fontSize: 16),
              ),
            ),
            const SizedBox(width: 10),
            const Text('KAEVEX SOC'),
            const SizedBox(width: 8),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              decoration: BoxDecoration(
                color: const Color(0xFF10B981).withOpacity(0.2),
                borderRadius: BorderRadius.circular(4),
                border: Border.all(color: const Color(0xFF10B981), width: 0.8),
              ),
              child: const Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  CircleAvatar(radius: 3, backgroundColor: Color(0xFF10B981)),
                  SizedBox(width: 4),
                  Text('CLOUD SYNC', style: TextStyle(fontSize: 9, color: Color(0xFF10B981), fontWeight: FontWeight.bold)),
                ],
              ),
            ),
          ],
        ),
        actions: [
          IconButton(
            tooltip: 'Connected Devices & Topology',
            icon: const Icon(Icons.hub_outlined, color: Color(0xFF00E5FF)),
            onPressed: () {
              Navigator.push(
                context,
                MaterialPageRoute(builder: (_) => const ClusterNodesScreen()),
              );
            },
          ),
          Builder(
            builder: (ctx) {
              final user = Supabase.instance.client.auth.currentUser;
              final email = user?.email ?? 'Account';
              final initial = email.isNotEmpty ? email[0].toUpperCase() : 'A';

              return Padding(
                padding: const EdgeInsets.only(right: 10),
                child: GestureDetector(
                  onTap: () {
                    showDialog(
                      context: ctx,
                      builder: (dialogCtx) {
                        return AlertDialog(
                          backgroundColor: const Color(0xFF151922),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(16),
                            side: const BorderSide(color: Color(0xFF262D3D)),
                          ),
                          title: Row(
                            children: [
                              CircleAvatar(
                                radius: 16,
                                backgroundColor: const Color(0xFFFF3366),
                                child: Text(initial, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                              ),
                              const SizedBox(width: 10),
                              const Text('SOC Cloud Profile', style: TextStyle(fontSize: 16, color: Colors.white)),
                            ],
                          ),
                          content: Column(
                            mainAxisSize: MainAxisSize.min,
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text('Email: $email', style: const TextStyle(fontSize: 13, color: Colors.white70)),
                              const SizedBox(height: 6),
                              Text('User ID: ${user?.id ?? "N/A"}', style: const TextStyle(fontSize: 11, color: Color(0xFF64748B))),
                              const SizedBox(height: 6),
                              const Row(
                                children: [
                                  CircleAvatar(radius: 3, backgroundColor: Color(0xFF10B981)),
                                  SizedBox(width: 6),
                                  Text('Supabase Realtime: Active', style: TextStyle(fontSize: 12, color: Color(0xFF10B981), fontWeight: FontWeight.bold)),
                                ],
                              ),
                              const SizedBox(height: 12),
                              const Text('Endpoint: lqvijkatveozunxzlaid.supabase.co', style: TextStyle(fontSize: 10, color: Colors.grey)),
                            ],
                          ),
                          actions: [
                            TextButton(
                              onPressed: () => Navigator.pop(dialogCtx),
                              child: const Text('Close', style: TextStyle(color: Colors.grey)),
                            ),
                            ElevatedButton.icon(
                              style: ElevatedButton.styleFrom(
                                backgroundColor: const Color(0xFFEF4444),
                                foregroundColor: Colors.white,
                              ),
                              icon: const Icon(Icons.logout, size: 14),
                              label: const Text('Sign Out'),
                              onPressed: () async {
                                Navigator.pop(dialogCtx);
                                await Supabase.instance.client.auth.signOut();
                              },
                            ),
                          ],
                        );
                      },
                    );
                  },
                  child: Chip(
                    avatar: CircleAvatar(
                      radius: 12,
                      backgroundColor: const Color(0xFFFF3366),
                      child: Text(initial, style: const TextStyle(color: Colors.white, fontSize: 11, fontWeight: FontWeight.bold)),
                    ),
                    label: Text(
                      email.length > 12 ? '${email.substring(0, 10)}...' : email,
                      style: const TextStyle(fontSize: 11, color: Colors.white),
                    ),
                    backgroundColor: const Color(0xFF151922),
                    side: const BorderSide(color: Color(0xFF262D3D)),
                  ),
                ),
              );
            },
          ),
        ],
      ),
      body: _screens[_currentIndex],
      bottomNavigationBar: BottomNavigationBar(
        currentIndex: _currentIndex,
        onTap: (index) => setState(() => _currentIndex = index),
        items: const [
          BottomNavigationBarItem(
            icon: Icon(Icons.speed),
            label: 'Telemetry',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.warning_amber_rounded),
            label: 'Alerts',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.g_mobiledata_outlined),
            label: 'Defense',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.security_update_good),
            label: 'CVE Fixes',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.psychology_outlined),
            label: 'AI Analyst',
          ),
        ],
      ),
    );
  }
}
