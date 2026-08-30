import requests


# ============================================================
# HTTP HEADERS
# ============================================================

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/142.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json,text/plain,*/*",
}


# ============================================================
# SABİT DEĞERLER
# ============================================================

NVD_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

CISA_KEV_URL = (
    "https://raw.githubusercontent.com/"
    "cisagov/kev-data/"
    "develop/"
    "known_exploited_vulnerabilities.json"
)

ALLOWED_SEVERITIES = [
    "ALL",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL"
]


# ============================================================
# NVD SEARCH
# ============================================================

def search_nvd(
    keyword,
    severity
):

    results = []

    severity = severity.upper()

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 200
    }

    if severity in [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]:

        params["cvssV3Severity"] = severity

    response = requests.get(
        NVD_URL,
        params=params,
        headers=DEFAULT_HEADERS,
        timeout=20
    )

    response.raise_for_status()

    data = response.json()

    for item in data.get(
        "vulnerabilities",
        []
    ):

        cve = item.get(
            "cve",
            {}
        )

        cve_id = cve.get(
            "id",
            "Bilinmiyor"
        )

        # ----------------------------------------------------
        # AÇIKLAMA
        # ----------------------------------------------------

        description = (
            "Açıklama bulunamadı"
        )

        for desc in cve.get(
            "descriptions",
            []
        ):

            if desc.get("lang") == "en":

                description = desc.get(
                    "value",
                    description
                )

                break

        # ----------------------------------------------------
        # CVSS
        # ----------------------------------------------------

        severity_level = "Unknown"
        score = "N/A"

        metrics = cve.get(
            "metrics",
            {}
        )

        # CVSS 4.0
        if metrics.get(
            "cvssMetricV40"
        ):

            metric = metrics[
                "cvssMetricV40"
            ][0]

            cvss_data = metric.get(
                "cvssData",
                {}
            )

            severity_level = cvss_data.get(
                "baseSeverity",
                "Unknown"
            )

            score = cvss_data.get(
                "baseScore",
                "N/A"
            )

        # CVSS 3.1
        elif metrics.get(
            "cvssMetricV31"
        ):

            metric = metrics[
                "cvssMetricV31"
            ][0]

            cvss_data = metric.get(
                "cvssData",
                {}
            )

            severity_level = cvss_data.get(
                "baseSeverity",
                "Unknown"
            )

            score = cvss_data.get(
                "baseScore",
                "N/A"
            )

        # CVSS 3.0
        elif metrics.get(
            "cvssMetricV30"
        ):

            metric = metrics[
                "cvssMetricV30"
            ][0]

            cvss_data = metric.get(
                "cvssData",
                {}
            )

            severity_level = cvss_data.get(
                "baseSeverity",
                "Unknown"
            )

            score = cvss_data.get(
                "baseScore",
                "N/A"
            )

        # CVSS 2.0
        elif metrics.get(
            "cvssMetricV2"
        ):

            metric = metrics[
                "cvssMetricV2"
            ][0]

            cvss_data = metric.get(
                "cvssData",
                {}
            )

            severity_level = metric.get(
                "baseSeverity",
                "Unknown"
            )

            score = cvss_data.get(
                "baseScore",
                "N/A"
            )

        # ----------------------------------------------------
        # SEVERITY FİLTRESİ
        # ----------------------------------------------------

        if severity != "ALL":

            if (
                severity_level.upper()
                != severity
            ):

                continue

        # ----------------------------------------------------
        # SONUCU EKLE
        # ----------------------------------------------------

        results.append({

            "title":
                cve_id,

            "description":
                description,

            "source":
                "NVD",

            "severity":
                severity_level,

            "score":
                score,

            "published":
                cve.get(
                    "published",
                    "Bilinmiyor"
                ),

            "modified":
                cve.get(
                    "lastModified",
                    "Bilinmiyor"
                ),

            "link":
                (
                    "https://nvd.nist.gov/vuln/detail/"
                    f"{cve_id}"
                ),

            "cve":
                cve_id
        })

    return results


# ============================================================
# CISA KEV SEARCH
# ============================================================

def search_cisa_kev(
    keyword
):

    results = []

    response = requests.get(
        CISA_KEV_URL,
        headers=DEFAULT_HEADERS,
        timeout=30
    )

    response.raise_for_status()

    data = response.json()

    keyword_lower = (
        keyword.strip().lower()
    )

    vulnerabilities = data.get(
        "vulnerabilities",
        []
    )

    for item in vulnerabilities:

        cve_id = str(
            item.get(
                "cveID",
                ""
            )
        )

        vendor = str(
            item.get(
                "vendorProject",
                ""
            )
        )

        product = str(
            item.get(
                "product",
                ""
            )
        )

        vulnerability_name = str(
            item.get(
                "vulnerabilityName",
                ""
            )
        )

        description = str(
            item.get(
                "shortDescription",
                ""
            )
        )

        # ----------------------------------------------------
        # ARAMA METNİ
        # ----------------------------------------------------

        searchable_text = " ".join([
            cve_id,
            vendor,
            product,
            vulnerability_name,
            description
        ]).lower()

        if keyword_lower not in searchable_text:

            continue

        # ----------------------------------------------------
        # SONUÇ
        # ----------------------------------------------------

        results.append({

            "title":
                cve_id
                if cve_id
                else vulnerability_name,

            "description":
                description
                if description
                else "Açıklama bulunamadı",

            "source":
                "CISA KEV",

            "severity":
                "UNKNOWN",

            "score":
                "N/A",

            "published":
                item.get(
                    "dateAdded",
                    "Bilinmiyor"
                ),

            "modified":
                item.get(
                    "dueDate",
                    "Bilinmiyor"
                ),

            "link":
                (
                    "https://nvd.nist.gov/vuln/detail/"
                    f"{cve_id}"
                    if cve_id
                    else ""
                ),

            "cve":
                cve_id,

            "vendor":
                vendor,

            "product":
                product,

            "vulnerability_name":
                vulnerability_name,

            "required_action":
                item.get(
                    "requiredAction",
                    ""
                ),

            "due_date":
                item.get(
                    "dueDate",
                    ""
                )
        })

    return results


# ============================================================
# ANA SEARCH FONKSİYONU
# ============================================================

def search_security(
    keyword,
    severity,
    source="NVD"
):

    if not keyword or not keyword.strip():

        raise ValueError(
            "Keyword boş olamaz"
        )

    source = (
        source.strip().upper()
    )

    severity = (
        severity.strip().upper()
    )

    if severity not in ALLOWED_SEVERITIES:

        raise ValueError(
            f"Geçersiz severity: {severity}"
        )

    # --------------------------------------------------------
    # NVD
    # --------------------------------------------------------

    if source == "NVD":

        return search_nvd(
            keyword,
            severity
        )

    # --------------------------------------------------------
    # CISA / CISA KEV
    # --------------------------------------------------------

    if source in [
        "CISA",
        "CISA KEV",
        "CISA KNOWN EXPLOITED VULNERABILITIES"
    ]:

        return search_cisa_kev(
            keyword
        )

    # --------------------------------------------------------
    # DESTEKLENMEYEN KAYNAK
    # --------------------------------------------------------

    raise ValueError(
        f"Desteklenmeyen kaynak: {source}"
    )