from flask import Flask, render_template, request, jsonify
import threading
import sqlite3
from traffic_sniffer import TrafficSniffer
from database import init_db
import pickle
import pandas as pd

app = Flask(__name__)

init_db()

sniffer = TrafficSniffer(interface="en0")  # можно заменить en0 на другой интерфейс
sniffing_thread = None

try:
    model = pickle.load(open('model/attack_model.pkl', 'rb'))
    label_encoders = pickle.load(open('model/label_encoders.pkl', 'rb'))
except Exception as e:
    print(f"Error loading model: {e}")
    model = None
    label_encoders = None


@app.route('/')
def index():
    """Главная страница"""
    return render_template("home.html")


@app.route('/sniffing')
def sniffing_page():
    """Страница управления сниффингом"""
    conn = sqlite3.connect("traffic.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM traffic ORDER BY id DESC LIMIT 10")
    packets = cursor.fetchall()
    conn.close()

    return render_template("index.html", packets=packets)


@app.route('/cyberattack')
def cyberattack_page():
    """Страница для определения кибератаки"""
    return render_template("cyberattack.html")


@app.route('/data')
def get_data():
    conn = sqlite3.connect("traffic.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM traffic ORDER BY id DESC LIMIT 10")
    packets = cursor.fetchall()
    conn.close()

    packets_list = [
        {
            "timestamp": p[1],
            "src_ip": p[2],
            "dst_ip": p[3],
            "protocol": p[4],
            "bytes": p[5],
            "service": p[6],
            "flag": p[7],
            "count": p[8],
            "srv_count": p[9],
            "dst_host_count": p[10],
            "dst_host_srv_count": p[11]
        }
        for p in packets
    ]
    return jsonify(packets_list)


@app.route('/predict', methods=['POST'])
def predict():
    """Endpoint для предсказания атак"""
    if not model or not label_encoders:
        return jsonify({"error": "Model not loaded"}), 500

    try:
        data = request.json
        input_data = {
            'protocol_type': data.get('protocol', 'tcp').lower(),
            'service': data.get('service', 'http').lower(),
            'flag': data.get('flag', 'SF'),
            'src_bytes': int(data.get('bytes', 0)),
            'dst_bytes': int(data.get('bytes', 0)),
            'count': int(data.get('count', 0)),
            'srv_count': int(data.get('srv_count', 0)),
            'dst_host_count': int(data.get('dst_host_count', 0)),
            'dst_host_srv_count': int(data.get('dst_host_srv_count', 0))
        }
        df = pd.DataFrame([input_data])
        for col in ['protocol_type', 'service', 'flag']:
            le = label_encoders[col]
            df[col] = df[col].apply(lambda x: x if x in le.classes_ else 'unknown')
            df[col] = le.transform(df[col])
        prediction = model.predict(df)[0]
        probability = model.predict_proba(df)[0][1]

        return jsonify({
            "is_attack": bool(prediction),
            "probability": float(probability),
            "type": "Attack" if prediction else "Normal",
            "features": input_data
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/start', methods=['POST'])
def start_sniffing():
    """Запуск сниффинга"""
    global sniffing_thread
    if not sniffer.sniffing:
        sniffing_thread = threading.Thread(target=sniffer.start_sniffing)
        sniffing_thread.start()
    return '', 204


@app.route('/stop', methods=['POST'])
def stop_sniffing():
    """Остановка сниффинга"""
    sniffer.stop_sniffing()
    return '', 204


@app.route('/analytics')
def analytics_page():
    """Страница аналитики трафика"""
    return render_template("analytics.html")


@app.route('/instruction')
def instruction():
    return render_template('instruction.html')


@app.route('/traffic/analytics')
def traffic_analytics():
    """Возвращает данные для аналитики трафика в формате JSON"""
    conn = sqlite3.connect("traffic.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT protocol, COUNT(*) FROM traffic
        GROUP BY protocol
    """)
    protocol_data = cursor.fetchall()

    cursor.execute("""
        SELECT service, COUNT(*) FROM traffic
        GROUP BY service
    """)
    service_data = cursor.fetchall()

    conn.close()

    protocols = [{"protocol": row[0], "count": row[1]} for row in protocol_data]
    services = [{"service": row[0], "count": row[1]} for row in service_data]

    return jsonify({"protocols": protocols, "services": services})


if __name__ == '__main__':
    app.run(debug=True)