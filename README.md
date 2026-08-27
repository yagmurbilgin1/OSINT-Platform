# 🛡️ OSINT Platform

OSINT Platform, herkese açık siber güvenlik verilerini ve CVE (Common Vulnerabilities and Exposures) kayıtlarını toplayarak kullanıcıya sunan Python tabanlı bir web uygulamasıdır.

Uygulama, kullanıcı tarafından girilen anahtar kelimelere göre NVD (National Vulnerability Database) üzerinde güvenlik açığı araması gerçekleştirir. Elde edilen CVE kayıtları açıklama, severity seviyesi, CVSS skoru, yayınlanma tarihi ve son güncelleme tarihi gibi bilgilerle birlikte kullanıcıya sunulur.

---

## 📌 Proje Hakkında

Bu projenin amacı, güvenlik açıkları hakkında herkese açık kaynaklarda bulunan bilgilerin daha kolay aranabilmesini ve incelenebilmesini sağlamaktır.

Kullanıcı uygulamanın ana sayfasından bir anahtar kelime girerek güvenlik açığı araması yapabilir. Ayrıca sonuçları severity seviyesine göre filtreleyebilir.

Sistem, NVD'nin herkese açık CVE API servisini kullanarak ilgili güvenlik açığı kayıtlarını getirir.

Arama işlemleri aynı zamanda SQLite veritabanında saklanarak kullanıcının daha sonra arama geçmişini görüntüleyebilmesine olanak sağlar.

---

## 🎯 Projenin Amacı

Projenin temel amaçları:

- Açık kaynaklardan siber güvenlik verilerine erişmek
- CVE kayıtlarının aranmasını kolaylaştırmak
- Güvenlik açıklarını severity seviyelerine göre filtrelemek
- CVSS skorlarını kullanıcıya göstermek
- Arama geçmişini veritabanında saklamak
- Arama geçmişini istatistiksel olarak görüntülemek
- Verileri CSV ve PDF formatlarında dışa aktarabilmek
- Kullanıcıların güvenlik açıkları hakkında hızlı bilgi edinebilmesini sağlamak

---

## 🔎 Temel Özellikler

Uygulamanın mevcut sürümünde aşağıdaki özellikler bulunmaktadır:

- 🔎 Anahtar kelime ile CVE arama
- ⚠️ Severity seviyesine göre filtreleme
- 📊 CVSS skoru gösterme
- 📝 CVE açıklaması gösterme
- 📅 Yayınlanma tarihi gösterme
- 🔄 Son güncelleme tarihini gösterme
- 🔗 NVD üzerindeki orijinal CVE kaydına bağlantı
- 🗄️ SQLite veritabanı kullanımı
- 🕘 Arama geçmişinin tutulması
- 📊 Dashboard
- 📥 Arama geçmişini CSV olarak dışa aktarma
- 📄 Arama geçmişini PDF olarak dışa aktarma

---

## 🛠️ Kullanılan Teknolojiler

### Backend

- Python
- Flask
- Requests

### Frontend

- HTML
- CSS
- Jinja2

### Database

- SQLite

### PDF

- ReportLab

### Veri Kaynağı

- NVD CVE API

### Geliştirme Araçları

- Visual Studio Code
- Git
- GitHub
- Python Virtual Environment (venv)

---

## 🏗️ Proje Yapısı

Projenin mevcut klasör yapısı aşağıdaki gibidir:

```text
OSINT-Platform/
│
├── backend/
│   └── app/
│       ├── main.py
│       ├── crawler.py
│       ├── database.py
│       ├── osint.db
│       │
│       ├── templates/
│       │   ├── index.html
│       │   ├── results.html
│       │   ├── history.html
│       │   └── dashboard.html
│       │
│       └── static/
│           └── css/
│               └── style.css
│
├── data/
├── docs/
├── frontend/
├── logs/
├── venv/
├── requirements.txt
└── README.md