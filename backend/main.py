from flask import Flask, jsonify
from flask_cors import CORS
from traffic_analyzer import TrafficAnalyzer
from anomaly_detector import AnomalyDetector

app = Flask(__name__)
CORS(app)

@app.route('/api/traffic', methods=['GET'])
def get_traffic():
    analyzer = TrafficAnalyzer(interface="eth0")  # Change to your interface
    analyzer.capture_traffic(duration=5)
    return jsonify(analyzer.analyze_traffic())

@app.route('/api/anomalies', methods=['GET'])
def get_anomalies():
    analyzer = TrafficAnalyzer(interface="eth0")
    analyzer.capture_traffic(duration=5)
    traffic_data = analyzer.analyze_traffic()
    detector = AnomalyDetector()
    detector.train(traffic_data)
    return jsonify(detector.predict(traffic_data))

if __name__ == "__main__":
    app.run(debug=True)
