import requests


def search_security(keyword, severity):

    url = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?keywordSearch={keyword}&resultsPerPage=5"
    )

    response = requests.get(url)
    data = response.json()

    results = []

    if "vulnerabilities" in data:

        for item in data["vulnerabilities"]:

            cve = item["cve"]

            description = "Açıklama bulunamadı"
            severity_level = "Unknown"
            score = "N/A"

            if "descriptions" in cve:
                for desc in cve["descriptions"]:
                    if desc["lang"] == "en":
                        description = desc["value"]
                        break

            if "metrics" in cve:

                metrics = cve["metrics"]

                if "cvssMetricV31" in metrics:
                    metric = metrics["cvssMetricV31"][0]
                    severity_level = metric["cvssData"]["baseSeverity"]
                    score = metric["cvssData"]["baseScore"]

                elif "cvssMetricV30" in metrics:
                    metric = metrics["cvssMetricV30"][0]
                    severity_level = metric["cvssData"]["baseSeverity"]
                    score = metric["cvssData"]["baseScore"]

                elif "cvssMetricV2" in metrics:
                    metric = metrics["cvssMetricV2"][0]
                    severity_level = metric.get("baseSeverity", "Unknown")
                    score = metric["cvssData"]["baseScore"]

            if severity != "ALL" and severity != severity_level:
                continue
           
        results.append({
    "title": cve["id"],
    "description": description,
    "source": "NVD",
    "severity": severity_level,
    "score": score,
    "published": cve.get("published", "Bilinmiyor"),
    "modified": cve.get("lastModified", "Bilinmiyor"),
    "link": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"
})

    return results