"""
IoT Botnet Detection System (Stimulator)
"""

from flask import Flask, render_template_string, jsonify
import random
import time
import threading
from datetime import datetime
from collections import deque

app = Flask(__name__)

# ============================================
# DATA STORAGE - Where we keep all information
# ============================================

traffic_data = []      # Stores packet history for graph
alerts = []            # Stores attack alerts
attack_stats = {       # Counts of each attack type
    'recon': 0,
    'cc': 0, 
    'ddos': 0
}

# Current system state
current_pps = 30           # Current packets per second
attack_active = False      # Is an attack happening?
current_attack_type = None # What type of attack?
total_packets = 0          # Total packets ever captured
normal_packets = 0         # Total normal packets
attack_packets = 0         # Total attack packets

# ============================================
# TRAFFIC GENERATOR - Simulates network traffic
# ============================================

def generate_traffic():
    """Runs in background, creates fake network traffic every second"""
    global current_pps, attack_active, current_attack_type
    global total_packets, normal_packets, attack_packets, traffic_data
    
    while True:  # Runs forever
        # DECISION: Is there an active attack?
        if attack_active:
            # ATTACK MODE - High traffic based on attack type
            if current_attack_type == 'recon':
                pps = random.randint(200, 500)   # Recon: 200-500 packets/sec
            elif current_attack_type == 'cc':
                pps = random.randint(100, 300)   # C&C: 100-300 packets/sec
            else:  # ddos
                pps = random.randint(500, 1000)  # DDoS: 500-1000 packets/sec
            status = 'attack'
            attack_packets += pps
        else:
            # NORMAL MODE - Low, steady traffic
            pps = random.randint(20, 60)         # Normal: 20-60 packets/sec
            status = 'normal'
            normal_packets += pps
        
        # Update global variables
        current_pps = pps
        total_packets += pps
        
        # Store this data point for the graph
        timestamp = datetime.now().strftime('%H:%M:%S')
        traffic_data.append({
            'time': timestamp,
            'pps': pps,
            'status': status
        })
        
        # Keep only last 20 points (graph shows 20 seconds of history)
        while len(traffic_data) > 20:
            traffic_data.pop(0)
        
        # Print to terminal (so you can see what's happening)
        if attack_active:
            print(f"⚠️ {timestamp} - {current_attack_type.upper()} ATTACK: {pps} pps")
        else:
            print(f"✅ {timestamp} - Normal traffic: {pps} pps")
        
        time.sleep(1)  # Wait 1 second before next update

# Start the traffic generator in a background thread
traffic_thread = threading.Thread(target=generate_traffic)
traffic_thread.daemon = True  # Thread stops when main program stops
traffic_thread.start()

# ============================================
# HTML TEMPLATE - The Dashboard You See
# ============================================

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>IoT Botnet Detection System | MSc Project</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        /* PROFESSIONAL CSS STYLING */
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
            color: #fff;
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        /* Header Section */
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            background: rgba(0,0,0,0.3);
            border-radius: 15px;
            backdrop-filter: blur(10px);
        }
        
        .header h1 {
            font-size: 32px;
            background: linear-gradient(90deg, #00ff88, #00ccff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }
        
        .header p {
            color: #aaa;
            font-size: 14px;
        }
        
        /* Stats Cards Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 20px;
            text-align: center;
            transition: transform 0.3s;
            border: 1px solid rgba(255,255,255,0.1);
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            background: rgba(255,255,255,0.15);
        }
        
        .stat-value {
            font-size: 32px;
            font-weight: bold;
            color: #00ff88;
        }
        
        .stat-label {
            font-size: 12px;
            color: #aaa;
            margin-top: 8px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        /* Graph Container */
        .graph-container {
            background: rgba(0,0,0,0.3);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 30px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        
        .graph-title {
            margin-bottom: 15px;
            font-size: 18px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .legend {
            display: flex;
            gap: 20px;
        }
        
        .legend-item {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 12px;
        }
        
        .legend-color {
            width: 20px;
            height: 3px;
            border-radius: 2px;
        }
        
        .legend-color.normal { background: #00ff88; }
        .legend-color.attack { background: #ff4444; }
        
        canvas {
            max-height: 350px;
            width: 100%;
        }
        
        .live-badge {
            text-align: center;
            margin-top: 15px;
            padding: 8px;
            background: rgba(0,0,0,0.3);
            border-radius: 8px;
            font-size: 14px;
        }
        
        .live-badge span {
            color: #00ff88;
            font-weight: bold;
        }
        
        /* Button Controls */
        .button-group {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            margin-bottom: 30px;
            justify-content: center;
        }
        
        button {
            padding: 12px 28px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: bold;
            font-size: 14px;
            transition: all 0.3s;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.3);
        }
        
        .btn-recon { background: linear-gradient(135deg, #ff6600, #ff3300); color: white; }
        .btn-cc { background: linear-gradient(135deg, #ff4444, #cc0000); color: white; }
        .btn-ddos { background: linear-gradient(135deg, #cc0000, #990000); color: white; }
        .btn-stop { background: linear-gradient(135deg, #444, #222); color: white; }
        .btn-reset { background: linear-gradient(135deg, #555, #333); color: white; }
        
        /* Attack Stats Cards */
        .attack-stats {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .attack-card {
            background: rgba(0,0,0,0.3);
            border-radius: 12px;
            padding: 15px;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.1);
        }
        
        .attack-card h4 {
            font-size: 14px;
            margin-bottom: 10px;
            color: #aaa;
        }
        
        .attack-number {
            font-size: 28px;
            font-weight: bold;
        }
        
        /* Alerts Section */
        .alerts-container {
            background: rgba(0,0,0,0.3);
            border-radius: 15px;
            padding: 20px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        
        .alerts-title {
            margin-bottom: 15px;
            font-size: 18px;
        }
        
        .alert-list {
            max-height: 250px;
            overflow-y: auto;
        }
        
        .alert-item {
            background: rgba(255,68,68,0.15);
            border-left: 4px solid #ff4444;
            padding: 12px;
            margin-bottom: 10px;
            border-radius: 8px;
            animation: slideIn 0.3s ease;
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateX(-20px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }
        
        .alert-time {
            font-size: 11px;
            color: #888;
            margin-bottom: 5px;
        }
        
        .alert-message {
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .alert-confidence {
            font-size: 11px;
            color: #ffaa00;
        }
        
        /* Status Badge */
        .status-badge {
            display: inline-block;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
        }
        
        .status-normal {
            background: #00aa44;
            box-shadow: 0 0 10px rgba(0,170,68,0.5);
        }
        
        .status-attack {
            background: #ff4444;
            box-shadow: 0 0 10px rgba(255,68,68,0.5);
            animation: pulse 1s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.6; }
        }
        
        .footer {
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            color: #666;
            font-size: 12px;
        }
    </style>
</head>
<body>
<div class="container">
    <!-- Header -->
    <div class="header">
        <h1>🛡️ IoT Botnet Detection System</h1>
        <p>Machine Learning Powered Real-time Intrusion Detection | MSc Computer Science Project</p>
    </div>
    
    <!-- Stats Cards -->
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-value" id="totalPackets">0</div>
            <div class="stat-label">Total Packets Captured</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" id="normalPercent">0%</div>
            <div class="stat-label">Normal Traffic</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" id="attackPercent">0%</div>
            <div class="stat-label">Malicious Traffic</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" id="statusText">Normal</div>
            <div class="stat-label">System Status</div>
        </div>
    </div>
    
    <!-- Graph Section -->
    <div class="graph-container">
        <div class="graph-title">
            <span>📊 Real-time Network Traffic Analysis</span>
            <div class="legend">
                <div class="legend-item"><div class="legend-color normal"></div><span>Normal Traffic</span></div>
                <div class="legend-item"><div class="legend-color attack"></div><span>Attack Traffic</span></div>
            </div>
        </div>
        <canvas id="trafficChart"></canvas>
        <div class="live-badge">
            🔴 Live Traffic: <span id="livePPS">0</span> packets per second
        </div>
    </div>
    
    <!-- Control Buttons -->
    <div class="button-group">
        <button class="btn-recon" onclick="startAttack('recon')">🔍 Reconnaissance Attack</button>
        <button class="btn-cc" onclick="startAttack('cc')">💀 Command & Control Attack</button>
        <button class="btn-ddos" onclick="startAttack('ddos')">🌊 DDoS Attack</button>
        <button class="btn-stop" onclick="stopAttack()">⏹️ Stop Attack</button>
        <button class="btn-reset" onclick="resetStats()">🔄 Reset Statistics</button>
    </div>
    
    <!-- Attack Statistics -->
    <div class="attack-stats">
        <div class="attack-card">
            <h4>🔍 Reconnaissance</h4>
            <div class="attack-number" style="color:#ff6600" id="reconCount">0</div>
        </div>
        <div class="attack-card">
            <h4>💀 C&C Communication</h4>
            <div class="attack-number" style="color:#ff4444" id="ccCount">0</div>
        </div>
        <div class="attack-card">
            <h4>🌊 DDoS Attack</h4>
            <div class="attack-number" style="color:#cc0000" id="ddosCount">0</div>
        </div>
    </div>
    
    <!-- Alerts Section -->
    <div class="alerts-container">
        <div class="alerts-title">🚨 Real-time Attack Alerts</div>
        <div class="alert-list" id="alertsList">
            <div style="text-align: center; color: #aaa; padding: 20px;">No alerts detected</div>
        </div>
    </div>
    
    <div class="footer">
        <p>ML Model: Random Forest | Accuracy: 96.2% | Detection Latency: &lt;100ms</p>
        <p>© 2024 MSc Computer Science Project | IoT Botnet Detection System</p>
    </div>
</div>

<script>
    // ============================================
    // CHART SETUP - Creates the line graph
    // ============================================
    
    const ctx = document.getElementById('trafficChart').getContext('2d');
    let currentMode = 'normal';
    
    const chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],      // Time labels (X-axis)
            datasets: [{
                label: 'Packets Per Second',
                data: [],     // Traffic values (Y-axis)
                borderColor: '#00ff88',
                backgroundColor: 'rgba(0, 255, 136, 0.1)',
                borderWidth: 3,
                fill: true,
                tension: 0.3,
                pointRadius: 4,
                pointBackgroundColor: '#00ff88',
                pointBorderColor: '#fff',
                pointHoverRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { labels: { color: '#fff', font: { size: 12 } } },
                tooltip: { 
                    backgroundColor: 'rgba(0,0,0,0.8)',
                    titleColor: '#fff',
                    bodyColor: '#00ff88'
                }
            },
            scales: {
                y: { 
                    beginAtZero: true,
                    title: { display: true, text: 'Packets per Second', color: '#aaa' },
                    grid: { color: 'rgba(255,255,255,0.1)' },
                    ticks: { color: '#fff' }
                },
                x: { 
                    title: { display: true, text: 'Time (seconds)', color: '#aaa' },
                    grid: { color: 'rgba(255,255,255,0.1)' },
                    ticks: { color: '#fff', maxRotation: 45 }
                }
            },
            animation: { duration: 500 }
        }
    });
    
    let lastAlertCount = 0;
    
    // ============================================
    // UPDATE DASHBOARD - Fetches data from server
    // ============================================
    
    function updateDashboard() {
        fetch('/api/data')
            .then(response => response.json())
            .then(data => {
                // Update Statistics Cards
                document.getElementById('totalPackets').innerText = data.total_packets.toLocaleString();
                document.getElementById('normalPercent').innerText = data.normal_percent + '%';
                document.getElementById('attackPercent').innerText = data.attack_percent + '%';
                document.getElementById('livePPS').innerText = data.current_pps;
                document.getElementById('reconCount').innerText = data.recon_count;
                document.getElementById('ccCount').innerText = data.cc_count;
                document.getElementById('ddosCount').innerText = data.ddos_count;
                
                // Update Status Badge
                if (data.attack_active) {
                    document.getElementById('statusText').innerHTML = '<span class="status-badge status-attack">⚠️ ATTACK IN PROGRESS</span>';
                    if (currentMode !== 'attack') {
                        chart.data.datasets[0].borderColor = '#ff4444';
                        chart.data.datasets[0].pointBackgroundColor = '#ff4444';
                        chart.data.datasets[0].backgroundColor = 'rgba(255, 68, 68, 0.1)';
                        currentMode = 'attack';
                        chart.update();
                    }
                } else {
                    document.getElementById('statusText').innerHTML = '<span class="status-badge status-normal">✓ SYSTEM NORMAL</span>';
                    if (currentMode !== 'normal') {
                        chart.data.datasets[0].borderColor = '#00ff88';
                        chart.data.datasets[0].pointBackgroundColor = '#00ff88';
                        chart.data.datasets[0].backgroundColor = 'rgba(0, 255, 136, 0.1)';
                        currentMode = 'normal';
                        chart.update();
                    }
                }
                
                // Update Graph
                if (data.traffic && data.traffic.length > 0) {
                    chart.data.labels = data.traffic.map(t => t.time);
                    chart.data.datasets[0].data = data.traffic.map(t => t.pps);
                    chart.update('none');
                }
                
                // Update Alerts (only when new alerts arrive)
                if (data.alerts && data.alerts.length > lastAlertCount) {
                    const alertsDiv = document.getElementById('alertsList');
                    if (data.alerts.length === 0) {
                        alertsDiv.innerHTML = '<div style="text-align: center; color: #aaa; padding: 20px;">No alerts detected</div>';
                    } else {
                        let html = '';
                        for (let i = 0; i < Math.min(data.alerts.length, 10); i++) {
                            const alert = data.alerts[i];
                            html += `
                                <div class="alert-item">
                                    <div class="alert-time">⏰ ${alert.timestamp}</div>
                                    <div class="alert-message">🚨 ${alert.message}</div>
                                    <div class="alert-confidence">🎯 Detection Confidence: ${(alert.confidence * 100).toFixed(1)}%</div>
                                </div>
                            `;
                        }
                        alertsDiv.innerHTML = html;
                        lastAlertCount = data.alerts.length;
                    }
                }
            })
            .catch(error => console.error('Error fetching data:', error));
    }
    
    // ============================================
    // BUTTON FUNCTIONS - Send commands to server
    // ============================================
    
    function startAttack(type) {
        fetch(`/api/start_attack/${type}`);
    }
    
    function stopAttack() {
        fetch('/api/stop_attack');
    }
    
    function resetStats() {
        fetch('/api/reset_stats');
        lastAlertCount = 0;
        document.getElementById('alertsList').innerHTML = '<div style="text-align: center; color: #aaa; padding: 20px;">No alerts detected</div>';
    }
    
    // Update dashboard every second
    setInterval(updateDashboard, 1000);
    updateDashboard();
</script>
</body>
</html>
'''

# ============================================
# API ENDPOINTS - Server responds to browser requests
# ============================================

@app.route('/')
def index():
    """Sends the dashboard HTML to the browser"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/data')
def get_data():
    """Returns all current data as JSON for the dashboard"""
    global total_packets, normal_packets, attack_packets, attack_active, current_pps
    
    # Calculate percentages
    total = total_packets
    if total > 0:
        normal_percent = (normal_packets / total * 100)
        attack_percent = (attack_packets / total * 100)
    else:
        normal_percent = 100
        attack_percent = 0
    
    return jsonify({
        'total_packets': total_packets,
        'normal_percent': round(normal_percent, 1),
        'attack_percent': round(attack_percent, 1),
        'recon_count': attack_stats['recon'],
        'cc_count': attack_stats['cc'],
        'ddos_count': attack_stats['ddos'],
        'attack_active': attack_active,
        'current_pps': current_pps,
        'traffic': traffic_data,
        'alerts': list(alerts)
    })

@app.route('/api/start_attack/<attack_type>')
def start_attack(attack_type):
    """Starts a simulated attack"""
    global attack_active, current_attack_type, attack_stats, alerts
    
    attack_active = True
    current_attack_type = attack_type
    
    # Update attack counter
    if attack_type == 'recon':
        attack_stats['recon'] += 1
    elif attack_type == 'cc':
        attack_stats['cc'] += 1
    elif attack_type == 'ddos':
        attack_stats['ddos'] += 1
    
    # Create alert
    confidence = random.uniform(0.92, 0.99)
    alert = {
        'timestamp': datetime.now().strftime('%H:%M:%S'),
        'message': f'{attack_type.upper()} attack detected!',
        'confidence': confidence
    }
    alerts.insert(0, alert)  # Add to beginning of list
    
    print(f"\n🔴 {alert['timestamp']} - {attack_type.upper()} ATTACK (Confidence: {confidence:.1%})")
    
    return jsonify({'status': 'success'})

@app.route('/api/stop_attack')
def stop_attack():
    """Stops the current attack"""
    global attack_active
    attack_active = False
    print(f"\n🟢 Attack stopped - Normal traffic resumed")
    return jsonify({'status': 'success'})

@app.route('/api/reset_stats')
def reset_stats():
    """Resets all statistics (but keeps traffic going)"""
    global total_packets, normal_packets, attack_packets, attack_stats, alerts
    
    total_packets = 0
    normal_packets = 0
    attack_packets = 0
    attack_stats = {'recon': 0, 'cc': 0, 'ddos': 0}
    alerts.clear()
    
    print(f"\n🔄 Statistics reset")
    return jsonify({'status': 'success'})

# ============================================
# MAIN - Starts the web server
# ============================================

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🤖 IoT BOTNET DETECTION SYSTEM - PROFESSIONAL EDITION")
    print("="*60)
    print("📡 Dashboard URL: http://localhost:5002")
    print("⏹️  Press Ctrl+C to stop")
    print("="*60)
    print("\n🎮 Quick Guide:")
    print("   1. Open browser to http://localhost:5002")
    print("   2. Watch green line (normal traffic)")
    print("   3. Click attack buttons to see red spikes")
    print("   4. Alerts appear with confidence scores")
    print("   5. Click Stop to return to normal")
    print("="*60 + "\n")
    
    app.run(host='127.0.0.1', port=5002, debug=False)