from flask import Flask, render_template, jsonify, request, Response  
from data import mock_cves  
from rdflib import Graph, Literal, RDF, URIRef, Namespace  
  
app = Flask(__name__)  
  
@app.route('/')  
def index():  
    return render_template('index.html')  
  
@app.route('/charts')  
def charts():  
    return render_template('charts.html')  
  
# ---- CRUD API ----  
@app.route('/api/cves', methods=['GET'])  
def get_cves():  
    return jsonify(mock_cves)  
  
@app.route('/api/cves', methods=['POST'])  
def add_cve():  
    data = request.json  
    mock_cves.append(data)  
    return jsonify({"message": "CVE added"}), 201  
  
@app.route('/api/cves/<cve_id>', methods=['PUT'])  
def update_cve(cve_id):  
    data = request.json  
    for cve in mock_cves:  
        if cve["cve_id"] == cve_id:  
            cve.update(data)  
            return jsonify({"message": "CVE updated"})  
    return jsonify({"error": "Not found"}), 404  
  
@app.route('/api/cves/<cve_id>', methods=['DELETE'])  
def delete_cve(cve_id):  
    global mock_cves  
    mock_cves = [c for c in mock_cves if c["cve_id"] != cve_id]  
    return jsonify({"message": "CVE deleted"})  
  
# ---- Email Alert API (Mock) ----  
@app.route('/api/alert/<cve_id>', methods=['POST'])  
def send_alert(cve_id):  
    cve = next((c for c in mock_cves if c["cve_id"] == cve_id), None)  
    if not cve:  
        return jsonify({"error": "Not found"}), 404  
    print(f"Sending email alert to {cve['email']} for {cve['cve_id']}")  
    return jsonify({"message": f"Alert sent to {cve['email']}"})  
  
# ---- RDF Export ----  
@app.route('/rdf')  
def export_rdf():  
    EX = Namespace("http://example.org/cve#")  
    g = Graph()  
    g.bind("ex", EX)  
    for c in mock_cves:  
        cve_uri = URIRef(f"http://example.org/cve/{c['cve_id']}")  
        g.add((cve_uri, RDF.type, EX.CVE))  
        g.add((cve_uri, EX.severity, Literal(c["severity"])))  
        g.add((cve_uri, EX.description, Literal(c["description"])))  
        g.add((cve_uri, EX.software, Literal(c["software"])))  
        g.add((cve_uri, EX.dateIdentified, Literal(c["date_identified"])))  
        if c["date_resolved"]:  
            g.add((cve_uri, EX.dateResolved, Literal(c["date_resolved"])))  
        g.add((cve_uri, EX.assignedTo, Literal(c["assigned_to"])))  
        g.add((cve_uri, EX.email, Literal(c["email"])))  
        g.add((cve_uri, EX.status, Literal(c["status"])))  
    turtle_data = g.serialize(format="turtle")  
    return Response(turtle_data, mimetype="text/turtle")  
  
if __name__ == '__main__':  
    app.run(debug=True)  