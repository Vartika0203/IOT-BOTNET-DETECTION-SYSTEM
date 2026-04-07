from flask import Flask, render_template_string, jsonify
from flask_cors import CORS
from datetime import datetime
import threading
import time
import random
import base64
from io import BytesIO

app = Flask(__name__)
CORS(app)

# Import detector
from real_detector import EnhancedBotnetDetector

# Initialize detector
detector = EnhancedBotnetDetector()

# Store traffic history for graph
traffic_history = []  # (timestamp, pps, attack_percent)

# Simulation control
simulation_running = True
simulation_thread = None

# HTML Template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IoT Botnet Detection System</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
            color: #fff;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { text-align: center; margin-bottom: 10px; font-size: 2.5em; background: linear-gradient(135deg, #00ff88, #00aaff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .subtitle { text-align: center; color: #8899bb; margin-bottom: 30px; }
        
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: rgba(255,255,255,0.1); backdrop-filter: blur(10px); border-radius: 15px; padding: 20px; text-align: center; }
        .stat-value { font-size: 2.5em; font-weight: bold; margin: 10px 0; }
        .stat-label { color: #8899bb; font-size: 0.9em; }
        
        .graph-container { background: rgba(0,0,0,0.5); border-radius: 15px; padding: 20px; margin-bottom: 30px; }
        .graph-title { text-align: center; margin-bottom: 15px; font-size: 1.2em; color: #00aaff; }
        .graph-image { width: 100%; border-radius: 10px; }
        
        .status-card { background: rgba(0,0,0,0.5); border-radius: 15px; padding: 20px; margin-bottom: 30px; text-align: center; }
        .status-text { font-size: 2em; font-weight: bold; margin: 10px 0; }
        .green { color: #00ff88; }
        .yellow { color: #ffaa00; }
        .red { color: #ff4444; }
        
        .two-columns { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; }
        .card { background: rgba(255,255,255,0.1); backdrop-filter: blur(10px); border-radius: 15px; padding: 20px; }
        .card h3 { margin-bottom: 15px; color: #00aaff; }
        
        .attack-bar { background: linear-gradient(90deg, #ff4444, #ff8844); height: 30px; border-radius: 5px; margin: 5px 0; display: flex; align-items: center; padding-left: 10px; }
        .ip-bar { background: linear-gradient(90deg, #ffaa00, #ffcc44); height: 20px; border-radius: 3px; margin: 5px 0; }
        
        .metrics { display: flex; justify-content: space-around; margin-top: 15px; }
        .metric { text-align: center; }
        .metric-value { font-size: 1.5em; font-weight: bold; }
        .metric-label { font-size: 0.8em; color: #8899bb; }
        
        .feature-item { background: rgba(0,0,0,0.3); padding: 10px; margin: 5px 0; border-radius: 5px; font-family: monospace; }
        .alert-box { background: rgba(255,68,68,0.2); border-left: 4px solid #ff4444; padding: 15px; margin-top: 20px; border-radius: 5px; }
        
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        .alert-active { animation: pulse 1s infinite; }
        
        @media (max-width: 768px) { .two-columns { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 IoT BOTNET DETECTION SYSTEM</h1>
        <div class="subtitle">Real-Time Network Intrusion Detection | Enhanced Visual Edition | ML: Random Forest</div>
        
        <div class="stats-grid">
            <div class="stat-card"><div class="stat-label">TOTAL PACKETS</div><div class="stat-value" id="totalPackets">0</div></div>
            <div class="stat-card"><div class="stat-label">TOTAL DATA (MB)</div><div class="stat-value" id="totalData">0</div></div>
            <div class="stat-card"><div class="stat-label">NORMAL TRAFFIC</div><div class="stat-value" id="normalPercent">0%</div></div>
            <div class="stat-card"><div class="stat-label">ATTACK TRAFFIC</div><div class="stat-value" id="attackPercent">0%</div></div>
        </div>
        
        <div class="graph-container">
            <div class="graph-title">📈 Live Network Traffic - Packets Per Second (Green = Normal, Red = Attack)</div>
            <img id="trafficGraph" class="graph-image" src="" alt="Traffic Graph">
            <div style="text-align: center; margin-top: 10px; font-size: 0.8em;">
                <span style="color: #00ff88;">●</span> Normal | 
                <span style="color: #ffaa00;">●</span> Suspicious | 
                <span style="color: #ff4444;">●</span> Attack | 
                <span style="color: #00aaff;">- - -</span> Baseline
            </div>
        </div>
        
        <div class="status-card">
            <div class="stat-label">CURRENT SYSTEM STATUS (Last 60 seconds)</div>
            <div class="status-text" id="systemStatus">✅ SYSTEM NORMAL</div>
            <div class="stat-label" id="recentStats">Last 60s: 0 packets, 0% attack | 0 pps</div>
        </div>
        
        <div class="two-columns">
            <div class="card"><h3>📊 Attack Type Distribution</h3><div id="attackDistribution">Loading...</div></div>
            <div class="card"><h3>🎯 Model Performance</h3><div id="modelPerformance">Loading...</div></div>
        </div>
        
        <div class="two-columns">
            <div class="card"><h3>🌐 Top Attacking IPs</h3><div id="topAttackers">Loading...</div></div>
            <div class="card"><h3>📡 Live Traffic Statistics</h3><div id="liveTraffic">Loading...</div></div>
        </div>
        
        <div class="card"><h3>💡 Feature Importance (Last Attack)</h3><div id="featureImportance">Waiting for attack...</div></div>
        <div id="alerts"></div>
    </div>
    
    <script>
        function updateDashboard() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('totalPackets').innerText = data.total_packets.toLocaleString();
                    document.getElementById('totalData').innerText = ((data.total_packets * 150) / (1024 * 1024)).toFixed(1);
                    document.getElementById('normalPercent').innerText = (100 - data.attack_percent_total).toFixed(1) + '%';
                    document.getElementById('attackPercent').innerText = data.attack_percent_total.toFixed(1) + '%';
                    
                    document.getElementById('systemStatus').innerHTML = data.status;
                    document.getElementById('systemStatus').className = 'status-text ' + data.status_color;
                    document.getElementById('recentStats').innerHTML = `Last 60s: ${data.window_total} packets, ${data.window_attack_percent}% attack | ${data.current_pps} pps`;
                    
                    if (data.graph_image) {
                        document.getElementById('trafficGraph').src = 'data:image/png;base64,' + data.graph_image;
                    }
                    
                    let attackHtml = '';
                    for (const [type, count] of Object.entries(data.attack_counts)) {
                        const percent = data.total_attacks > 0 ? (count / data.total_attacks * 100).toFixed(1) : 0;
                        attackHtml += `<div style="margin: 5px 0;">${type}: ${count} (${percent}%)</div><div class="attack-bar" style="width: ${percent}%;">${percent}%</div>`;
                    }
                    document.getElementById('attackDistribution').innerHTML = attackHtml || 'No attacks yet';
                    
                    document.getElementById('modelPerformance').innerHTML = `
                        <div class="metrics">
                            <div class="metric"><div class="metric-value" style="color:#00ff88;">${data.precision}%</div><div class="metric-label">Precision</div></div>
                            <div class="metric"><div class="metric-value" style="color:#00aaff;">${data.recall}%</div><div class="metric-label">Recall</div></div>
                            <div class="metric"><div class="metric-value" style="color:#ffaa00;">${data.f1}</div><div class="metric-label">F1-Score</div></div>
                        </div>
                        <div style="text-align:center; margin-top:10px;">✅ Model Active (Random Forest)</div>
                    `;
                    
                    let ipHtml = '';
                    for (const ip of data.top_attackers) {
                        ipHtml += `<div>${ip.ip}: ${ip.count} packets</div><div class="ip-bar" style="width: ${Math.min(100, ip.count/5*100)}%;"></div>`;
                    }
                    document.getElementById('topAttackers').innerHTML = ipHtml || 'No attackers yet';
                    
                    const ratio = (data.current_pps / data.baseline_pps).toFixed(2);
                    document.getElementById('liveTraffic').innerHTML = `
                        <div class="metrics">
                            <div class="metric"><div class="metric-value">${data.current_pps}</div><div class="metric-label">Current PPS</div></div>
                            <div class="metric"><div class="metric-value">${data.baseline_pps}</div><div class="metric-label">Baseline PPS</div></div>
                            <div class="metric"><div class="metric-value">${ratio}x</div><div class="metric-label">Ratio</div></div>
                        </div>
                        <div style="text-align:center; margin-top:10px;">🔍 Last Confidence: ${data.last_confidence}%</div>
                    `;
                    
                    if (data.feature_importance && data.feature_importance.length > 0) {
                        let featHtml = '';
                        for (const f of data.feature_importance) {
                            featHtml += `<div class="feature-item"><strong>${f.feature}:</strong> ${f.value.toFixed(2)} (importance: ${f.importance_score.toFixed(3)})</div>`;
                        }
                        document.getElementById('featureImportance').innerHTML = featHtml;
                    }
                    
                    if (data.rate_alert) {
                        document.getElementById('alerts').innerHTML = `<div class="alert-box alert-active"><strong>🚨 ALERT:</strong> ${data.rate_alert}</div>`;
                    } else {
                        document.getElementById('alerts').innerHTML = '';
                    }
                })
                .catch(error => console.error('Error:', error));
        }
        
        setInterval(updateDashboard, 2000);
        updateDashboard();
    </script>
</body>
</html>
"""

def generate_graph():
    """Generate traffic graph"""
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    
    if not traffic_history:
        fig, ax = plt.subplots(figsize=(12, 4))
        ax.set_facecolor('#0a0e27')
        fig.patch.set_facecolor('#0a0e27')
        ax.text(0.5, 0.5, 'Waiting for traffic data...', ha='center', va='center', color='#8899bb', transform=ax.transAxes)
        ax.set_title('Live Network Traffic', color='white')
        ax.set_xlabel('Time (seconds ago)', color='#8899bb')
        ax.set_ylabel('Packets Per Second', color='#8899bb')
        
        buf = BytesIO()
        plt.savefig(buf, format='png', dpi=100, bbox_inches='tight')
        buf.seek(0)
        plt.close()
        return base64.b64encode(buf.getvalue()).decode()
    
    timestamps = [t[0] for t in traffic_history]
    pps_values = [t[1] for t in traffic_history]
    attack_percentages = [t[2] for t in traffic_history]
    
    fig, ax = plt.subplots(figsize=(12, 4))
    ax.set_facecolor('#0a0e27')
    fig.patch.set_facecolor('#0a0e27')
    
    for i in range(len(pps_values) - 1):
        if attack_percentages[i] < 10:
            color = '#00ff88'
        elif attack_percentages[i] > 30:
            color = '#ff4444'
        else:
            color = '#ffaa00'
        ax.plot(timestamps[i:i+2], pps_values[i:i+2], color=color, linewidth=2)
    
    baseline = detector.get_baseline_pps()
    ax.axhline(y=baseline, color='#00aaff', linestyle='--', linewidth=1, alpha=0.7, label=f'Baseline ({baseline} pps)')
    
    ax.set_title('📊 Live Network Traffic - Packets Per Second', color='white', fontsize=14)
    ax.set_xlabel('Time (seconds ago)', color='#8899bb')
    ax.set_ylabel('Packets Per Second', color='#8899bb')
    ax.tick_params(colors='#8899bb')
    ax.grid(True, alpha=0.2)
    
    if timestamps:
        max_time = max(timestamps)
        ax.set_xlim(max_time - 60, max_time)
    
    plt.tight_layout()
    buf = BytesIO()
    plt.savefig(buf, format='png', dpi=100, bbox_inches='tight', facecolor='#0a0e27')
    buf.seek(0)
    plt.close()
    return base64.b64encode(buf.getvalue()).decode()

def simulate_traffic():
    """Generate simulated traffic"""
    global traffic_history
    print("🚀 Starting traffic simulation...")
    
    last_graph_update = time.time()
    packet_counter = 0
    last_pps_time = time.time()
    
    while simulation_running:
        try:
            # Generate packet
            is_attack = random.random() < 0.25
            
            if is_attack:
                attack_type = random.choice(['DDoS', 'Reconnaissance', 'C&C Communication', 'Port Scan'])
                if attack_type == 'DDoS':
                    packet = {'packet_size': random.randint(1000,1500), 'dst_port': random.choice([80,443,8080]), 'protocol': 'TCP', 'ttl': random.randint(128,255), 'flow_duration': random.randint(100,500), 'packets_per_flow': random.randint(50,200), 'bytes_per_second': random.random()*1000, 'src_ip': f"192.168.1.{random.randint(100,200)}"}
                elif attack_type == 'Reconnaissance':
                    packet = {'packet_size': random.randint(40,100), 'dst_port': random.choice([22,23,3389,5900]), 'protocol': 'TCP', 'ttl': random.randint(60,128), 'flow_duration': random.randint(1,30), 'packets_per_flow': random.randint(1,20), 'bytes_per_second': random.random()*50, 'src_ip': f"10.0.0.{random.randint(1,50)}"}
                elif attack_type == 'C&C Communication':
                    packet = {'packet_size': random.randint(50,200), 'dst_port': random.choice([6667,6668,31337,4444]), 'protocol': 'TCP', 'ttl': random.randint(128,255), 'flow_duration': random.randint(20,200), 'packets_per_flow': random.randint(5,50), 'bytes_per_second': random.random()*200, 'src_ip': f"172.16.{random.randint(1,10)}.{random.randint(1,255)}"}
                else:
                    packet = {'packet_size': random.randint(40,100), 'dst_port': random.randint(1,65535), 'protocol': 'TCP', 'ttl': random.randint(60,128), 'flow_duration': random.randint(1,10), 'packets_per_flow': random.randint(10,100), 'bytes_per_second': random.random()*30, 'src_ip': f"192.168.1.{random.randint(50,99)}"}
            else:
                packet = {'packet_size': random.randint(40,1500), 'dst_port': random.choice([53,80,443,123,161]), 'protocol': random.choice(['TCP','UDP']), 'ttl': random.randint(60,65), 'flow_duration': random.randint(1,50), 'packets_per_flow': random.randint(1,10), 'bytes_per_second': random.random()*100, 'src_ip': f"192.168.1.{random.randint(10,50)}"}
            
            prediction, confidence = detector.predict_with_confidence(packet)
            attack_type = detector.predict_attack_type(packet) if prediction == 1 else None
            
            detector.add_packet(packet, prediction, confidence, attack_type)
            detector.update_metrics(1 if is_attack else 0, prediction)
            
            packet_counter += 1
            
            # Update PPS every second
            now = time.time()
            if now - last_pps_time >= 1:
                current_pps = packet_counter
                packet_counter = 0
                last_pps_time = now
                
                window_stats = detector.get_window_stats()
                traffic_history.append((now, current_pps, window_stats['attack_percent']))
                cutoff = now - 60
                traffic_history = [(t, pps, ap) for t, pps, ap in traffic_history if t > cutoff]
                
                detector.update_adaptive_baseline(current_pps)
            
            time.sleep(1/15)  # 15 packets per second
            
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(0.1)

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/stats')
def get_stats():
    window_stats = detector.get_window_stats()
    lifetime_stats = detector.get_lifetime_stats()
    status, color = detector.get_system_status(window_stats)
    
    total_attacks = sum(detector.attack_counts.values())
    graph_image = generate_graph()
    
    last_confidence = 0
    feature_importance = []
    for packet in reversed(detector.packet_history[-50:]):
        if packet['is_attack']:
            last_confidence = packet['confidence']
            feature_importance = detector.get_feature_importance(packet['packet'])
            break
    
    return jsonify({
        'total_packets': lifetime_stats['total_packets'],
        'attack_percent_total': lifetime_stats['attack_percent'],
        'attack_counts': detector.attack_counts,
        'total_attacks': total_attacks,
        'window_total': window_stats['total'],
        'window_attack_percent': round(window_stats['attack_percent'], 1),
        'current_pps': window_stats['packets_per_sec'],
        'baseline_pps': detector.get_baseline_pps(),
        'status': status,
        'status_color': color,
        'rate_alert': detector.check_rate_alert(window_stats['packets_per_sec']),
        'top_attackers': detector.get_top_attack_ips(5),
        'precision': round(detector.precision * 100, 2),
        'recall': round(detector.recall * 100, 2),
        'f1': round(detector.f1, 3),
        'last_confidence': round(last_confidence, 1),
        'feature_importance': feature_importance,
        'graph_image': graph_image
    })

if __name__ == '__main__':
    simulation_thread = threading.Thread(target=simulate_traffic, daemon=True)
    simulation_thread.start()
    
    print("=" * 60)
    print("🚀 IoT BOTNET DETECTION SYSTEM - RUNNING")
    print("=" * 60)
    print("📍 Open: http://localhost:5000")
    print("=" * 60)
    
    app.run(debug=False, host='0.0.0.0', port=5000)