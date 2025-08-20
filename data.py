from datetime import date  
  
mock_cves = [  
    {  
        "cve_id": "CVE-2024-12345",  
        "severity": "High",  
        "description": "Buffer overflow in XYZ software",  
        "software": "XYZ App 2.1",  
        "date_identified": date(2024, 6, 1).isoformat(),  
        "date_resolved": None,  
        "assigned_to": "Alice",  
        "email": "alice@example.com",  
        "status": "Open"  
    },  
    {  
        "cve_id": "CVE-2024-67890",  
        "severity": "Medium",  
        "description": "SQL injection in ABC web app",  
        "software": "ABC Web 4.0",  
        "date_identified": date(2024, 5, 15).isoformat(),  
        "date_resolved": date(2024, 6, 5).isoformat(),  
        "assigned_to": "Bob",  
        "email": "bob@example.com",  
        "status": "Resolved"  
    },  
    {  
        "cve_id": "CVE-2024-11111",  
        "severity": "Critical",  
        "description": "Remote code execution in DEF service",  
        "software": "DEF Service 1.5",  
        "date_identified": date(2024, 4, 20).isoformat(),  
        "date_resolved": None,  
        "assigned_to": "Charlie",  
        "email": "charlie@example.com",  
        "status": "Open"  
    }  
]  