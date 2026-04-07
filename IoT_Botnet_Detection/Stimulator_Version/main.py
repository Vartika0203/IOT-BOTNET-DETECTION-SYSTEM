"""
Main Entry Point - Run the Complete System
"""

import subprocess
import sys
import os
import time
import threading
import webbrowser

def print_banner():
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║     I o T   B o t n e t   D e t e c t i o n   S y s t e m    ║
    ║                      (Stimulator)                            ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def run_training():
    """Train the ML model"""
    print("\n[1/3] Training Machine Learning Model...")
    print("-" * 50)
    
    from model_trainer import generate_training_data, BotnetDetector
    
    features, labels = generate_training_data()
    detector = BotnetDetector()
    detector.feature_names = [f"F{i}" for i in range(features.shape[1])]
    detector.train(features, labels)
    detector.save_model()
    
    print("\n✓ Model training complete!")
    return detector

def run_traffic_generator():
    """Run traffic generator in background"""
    print("\n[2/3] Starting Traffic Generator...")
    print("-" * 50)
    
    from traffic_generator import IoTTrafficGenerator
    
    generator = IoTTrafficGenerator()
    print("✓ Traffic generator ready")
    return generator

def run_dashboard():
    """Start the web dashboard"""
    print("\n[3/3] Starting Dashboard Server...")
    print("-" * 50)
    
    from dashboard import app, socketio
    
    def open_browser():
        time.sleep(2)
        webbrowser.open('http://localhost:5000')
    
    threading.Thread(target=open_browser, daemon=True).start()
    
    print("\n" + "=" * 50)
    print("🚀 SYSTEM IS RUNNING!")
    print("=" * 50)
    print("Dashboard URL: http://localhost:5000")
    print("Press Ctrl+C to stop the system")
    print("=" * 50)
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)

def generate_report():
    """Generate sample results for paper"""
    print("\n[Report Generation] Creating results for paper...")
    print("-" * 50)
    
    from model_trainer import generate_training_data, BotnetDetector
    from sklearn.metrics import classification_report, confusion_matrix
    import matplotlib.pyplot as plt
    import seaborn as sns
    import pandas as pd
    import numpy as np
    
    # Generate data
    features, labels = generate_training_data(2000)
    detector = BotnetDetector()
    detector.feature_names = [f"F{i}" for i in range(features.shape[1])]
    detector.train(features, labels)
    
    # Make predictions
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(features, 
                                                         [0 if l=='normal' else 1 for l in labels], 
                                                         test_size=0.3, random_state=42)
    
    X_scaled = detector.scaler.fit_transform(X_train)
    detector.model.fit(X_scaled, y_train)
    
    X_test_scaled = detector.scaler.transform(X_test)
    y_pred = detector.model.predict(X_test_scaled)
    
    # Generate confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='RdYlGn', 
                xticklabels=['Normal', 'Attack'],
                yticklabels=['Normal', 'Attack'])
    plt.title('Confusion Matrix - IoT Botnet Detection')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.savefig('confusion_matrix.png', dpi=150, bbox_inches='tight')
    print("✓ Saved: confusion_matrix.png")
    
    # Generate classification report
    report = classification_report(y_test, y_pred, target_names=['Normal', 'Attack'])
    print("\nClassification Report:")
    print(report)
    
    # Save report to file
    with open('classification_report.txt', 'w') as f:
        f.write("=" * 60 + "\n")
        f.write("IoT BOTNET DETECTION - CLASSIFICATION REPORT\n")
        f.write("=" * 60 + "\n\n")
        f.write(report)
        f.write("\n\nConfusion Matrix:\n")
        f.write(str(cm))
    
    print("\n✓ Saved: classification_report.txt")
    
    # Generate feature importance plot
    if hasattr(detector.model, 'feature_importances_'):
        importance_df = pd.DataFrame({
            'feature': detector.feature_names,
            'importance': detector.model.feature_importances_
        }).sort_values('importance', ascending=False).head(10)
        
        plt.figure(figsize=(10, 6))
        plt.barh(importance_df['feature'], importance_df['importance'], color='green')
        plt.xlabel('Importance')
        plt.title('Top 10 Feature Importances')
        plt.gca().invert_yaxis()
        plt.tight_layout()
        plt.savefig('feature_importance.png', dpi=150, bbox_inches='tight')
        print("✓ Saved: feature_importance.png")
    
    return report

if __name__ == "__main__":
    print_banner()
    
    print("\nWhat would you like to do?")
    print("1. Run Complete System (Train + Dashboard)")
    print("2. Train Model Only")
    print("3. Generate Report Only (for paper)")
    print("4. Run Dashboard Only")
    
    choice = input("\nEnter choice (1-4): ").strip()
    
    if choice == '1':
        run_training()
        print("\nStarting dashboard in 3 seconds...")
        time.sleep(3)
        run_dashboard()
        
    elif choice == '2':
        run_training()
        
    elif choice == '3':
        generate_report()
        
    elif choice == '4':
        run_dashboard()
        
    else:
        print("Invalid choice. Running full system...")
        run_training()
        time.sleep(3)
        run_dashboard()