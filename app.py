from flask import Flask, render_template, jsonify, request, Response  
from rdflib import Graph, Literal, RDF, URIRef, Namespace  
import os  
  
app = Flask(__name__)  
  
TTL_FILE = "graph.ttl"  
  
# Namespaces  
CVE = Namespace("http://example.org/cve#")  
SOFT = Namespace("http://example.org/software#")  
  
  
def load_cves_from_rdf():  
    """Wczytuje dane CVE z pliku RDF"""  
    g = Graph()  
    if os.path.exists(TTL_FILE):  
        g.parse(TTL_FILE, format="turtle")  
    cves = []  
    for cve_uri in g.subjects(RDF.type, CVE.CVE):  
        cve_data = {  
            "cve_id": str(cve_uri).split("/")[-1],  
            "severity": str(g.value(cve_uri, CVE.severity)),  
            "description": str(g.value(cve_uri, CVE.description)),  
            "software": str(g.value(cve_uri, CVE.software)),  
            "date_identified": str(g.value(cve_uri, CVE.dateIdentified)),  
            "date_resolved": str(g.value(cve_uri, CVE.dateResolved)),  
            "assigned_to": str(g.value(cve_uri, CVE.assignedTo)),  
            "email": str(g.value(cve_uri, CVE.email)),  
            "status": str(g.value(cve_uri, CVE.status)),  
        }  
        cves.append(cve_data)  
    return cves  
  
  
def save_cves_to_rdf(cves):  
    """Zapisuje listę CVE do pliku RDF"""  
    g = Graph()  
    g.bind("cve", CVE)  
    for c in cves:  
        cve_uri = URIRef(f"http://example.org/cve/{c['cve_id']}")  
        g.add((cve_uri, RDF.type, CVE.CVE))  
        g.add((cve_uri, CVE.severity, Literal(c["severity"])))  
        g.add((cve_uri, CVE.description, Literal(c["description"])))  
        g.add((cve_uri, CVE.software, Literal(c["software"])))  
        g.add((cve_uri, CVE.dateIdentified, Literal(c["date_identified"])))  
        if c.get("date_resolved"):  
            g.add((cve_uri, CVE.dateResolved, Literal(c["date_resolved"])))  
        g.add((cve_uri, CVE.assignedTo, Literal(c["assigned_to"])))  
        g.add((cve_uri, CVE.email, Literal(c["email"])))  
        g.add((cve_uri, CVE.status, Literal(c["status"])))  
    g.serialize(TTL_FILE, format="turtle")  
  
  
@app.route('/')  
def index():  
    return render_template('index.html')  
  
  
@app.route('/charts')  
def charts():  
    return render_template('charts.html')  
  
  
# ---- CRUD API ----  
@app.route('/api/cves', methods=['GET'])  
def get_cves():  
    cves = load_cves_from_rdf()  
    return jsonify(cves)  
  
  
@app.route('/api/cves', methods=['POST'])  
def add_cve():  
    data = request.json  
    cves = load_cves_from_rdf()  
    cves.append(data)  
    save_cves_to_rdf(cves)  
    return jsonify({"message": "CVE added"}), 201  
  
  
@app.route('/api/cves/<cve_id>', methods=['PUT'])  
def update_cve(cve_id):  
    data = request.json  
    cves = load_cves_from_rdf()  
    for c in cves:  
        if c["cve_id"] == cve_id:  
            c.update(data)  
            save_cves_to_rdf(cves)  
            return jsonify({"message": "CVE updated"})  
    return jsonify({"error": "Not found"}), 404  
  
  
@app.route('/api/cves/<cve_id>', methods=['DELETE'])  
def delete_cve(cve_id):  
    cves = load_cves_from_rdf()  
    new_cves = [c for c in cves if c["cve_id"] != cve_id]  
    save_cves_to_rdf(new_cves)  
    return jsonify({"message": "CVE deleted"})  
  
  
# ---- Email Alert API (Mock) ----  
@app.route('/api/alert/<cve_id>', methods=['POST'])  
def send_alert(cve_id):  
    cves = load_cves_from_rdf()  
    cve = next((c for c in cves if c["cve_id"] == cve_id), None)  
    if not cve:  
        return jsonify({"error": "Not found"}), 404  
    print(f"Sending email alert to {cve['email']} for {cve['cve_id']}")  
    return jsonify({"message": f"Alert sent to {cve['email']}"})  
  
  
# ---- RDF Export ----  
@app.route('/rdf')  
def export_rdf():  
    if os.path.exists(TTL_FILE):  
        with open(TTL_FILE, "r", encoding="utf-8") as f:  
            turtle_data = f.read()  
    else:  
        turtle_data = ""  
    return Response(turtle_data, mimetype="text/turtle")  
  
  
if __name__ == '__main__':  
    app.run(debug=True)  
