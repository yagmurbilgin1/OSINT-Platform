# 🛡️ OSINT Platform

Güvenlik duyurularını ve CVE bilgilerini internet üzerindeki açık kaynaklardan
toplayarak kullanıcıya sunan Python tabanlı bir OSINT uygulamasıdır.

## 📌 Proje Hakkında

Bu projenin amacı, güvenlik açıkları hakkında herkese açık kaynaklardan
bilgi toplayarak kullanıcıların bu bilgilere daha kolay ulaşmasını sağlamaktır.

Uygulamada kullanıcı bir anahtar kelime girerek güvenlik açığı araması
yapabilir. Sistem NVD (National Vulnerability Database) üzerinden ilgili
CVE kayıtlarını getirir ve sonuçları kullanıcıya sunar.

## 🎯 Temel Özellikler

- 🔎 Anahtar kelime ile güvenlik açığı arama
- ⚠️ Severity seviyesine göre filtreleme
- 📊 CVSS skoru gösterme
- 📅 Yayınlanma tarihi gösterme
- 🔄 Son güncelleme tarihini gösterme
- 🔗 CVE kaydına ait NVD bağlantısı
- 🗄️ SQLite veritabanı kullanımı
- 🕘 Arama geçmişinin tutulması
- 📊 Dashboard
- 📥 Arama geçmişini CSV olarak indirme
- 📄 Arama geçmişini PDF olarak indirme

## 🛠️ Kullanılan Teknolojiler

- Python
- Flask
- SQLite
- HTML
- CSS
- Jinja2
- Requests
- ReportLab
- NVD CVE API

## 🏗️ Proje Yapısı

```text
OSINT-Platform/
│
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── crawler.py
│   │   ├── database.py
│   │   ├── osint.db
│   │   │
│   │   ├── templates/
│   │   │   ├── index.html
│   │   │   ├── results.html
│   │   │   ├── history.html
│   │   │   └── dashboard.html
│   │   │
│   │   └── static/
│   │       └── css/
│   │           └── style.css
│   │
│   └── venv/
│
├── data/
├── docs/
├── frontend/
├── logs/
└── README.md
```

## 🔎 Veri Kaynağı

Uygulamanın güvenlik açığı verilerini almak için NVD'nin CVE API servisi
kullanılmaktadır.

NVD üzerinden alınan bilgiler arasında:

- CVE ID
- Açıklama
- Severity
- CVSS skoru
- Yayın tarihi
- Son güncelleme tarihi

bulunmaktadır.

## ⚙️ Çalışma Mantığı

Sistem temel olarak aşağıdaki şekilde çalışmaktadır:

```text
Kullanıcı
   │
   ▼
Ana Sayfa
   │
   ▼
Anahtar Kelime + Severity
   │
   ▼
Crawler
   │
   ▼
NVD CVE API
   │
   ▼
CVE Sonuçları
   │
   ├── CVE ID
   ├── Açıklama
   ├── Severity
   ├── CVSS
   ├── Yayın Tarihi
   └── Güncelleme Tarihi
   │
   ▼
Kullanıcıya Gösterim
```

Aynı zamanda yapılan aramalar SQLite veritabanında tutulmaktadır.

## 🗄️ Veritabanı

Projede arama geçmişinin tutulması için SQLite kullanılmaktadır.

Arama kayıtlarında temel olarak:

- Aranan kelime
- Arama tarihi

bilgileri tutulmaktadır.

Bu bilgiler;

- Arama Geçmişi
- Dashboard
- CSV çıktısı
- PDF çıktısı

özelliklerinde kullanılmaktadır.

## 📊 Dashboard

Dashboard bölümünde arama geçmişinden elde edilen istatistikler
gösterilmektedir.

Dashboard üzerinde:

- Toplam arama sayısı
- En çok aranan kelime
- Son aranan kelime
- Bugünkü arama sayısı

bilgileri görüntülenmektedir.

## 📥 CSV Dışa Aktarma

Arama geçmişi CSV formatında dışa aktarılabilmektedir.

CSV dosyasında arama kelimesi ve arama tarihi bilgileri bulunmaktadır.

## 📄 PDF Dışa Aktarma

Arama geçmişi PDF formatında da dışa aktarılabilmektedir.

PDF içerisinde arama kelimeleri ve arama tarihleri listelenmektedir.

## 🚀 Kurulum

Projeyi çalıştırmak için Python'un bilgisayarda kurulu olması gerekir.

### 1. Projeyi klonlama

```bash
git clone https://github.com/yagmurbilgin1/OSINT-Platform.git
```

### 2. Proje klasörüne girme

```bash
cd OSINT-Platform
```

### 3. Backend klasörüne girme

```bash
cd backend
```

### 4. Virtual environment oluşturma

```bash
python -m venv venv
```

### 5. Virtual environment'ı aktifleştirme

Windows PowerShell:

```powershell
.\venv\Scripts\activate
```

### 6. Gerekli paketleri yükleme

```bash
pip install -r requirements.txt
```

## ▶️ Uygulamayı Çalıştırma

Backend içerisindeki `app` klasörüne girilir:

```bash
cd app
```

Daha sonra:

```bash
python main.py
```

komutu çalıştırılır.

Flask uygulaması çalıştıktan sonra tarayıcıdan:

```text
http://127.0.0.1:5000
```

adresine gidilebilir.

## 🖥️ Kullanım

1. Ana sayfayı açın.
2. Arama kutusuna bir anahtar kelime girin.
3. İstenilen severity seviyesini seçin.
4. Arama işlemini başlatın.
5. Sistem NVD üzerinden ilgili CVE kayıtlarını getirir.
6. Sonuçlarda CVE bilgileri görüntülenir.
7. Arama geçmişi bölümünden geçmiş aramalar incelenebilir.
8. Geçmiş kayıtları CSV veya PDF olarak dışa aktarılabilir.
9. Dashboard üzerinden arama istatistikleri görüntülenebilir.

## ⚠️ Mevcut Sınırlılıklar

Mevcut sürüm, temel OSINT güvenlik duyurusu toplama ve görüntüleme
işlevlerine odaklanmaktadır.

Mevcut sürümde veri toplama temel olarak NVD kaynağı üzerinden
gerçekleştirilmektedir.

Çoklu kaynak desteği, gelişmiş background job sistemi, kapsamlı API
mimarisi, Docker altyapısı ve otomatik test kapsamı sonraki geliştirme
aşamalarında ele alınabilecek özelliklerdir.

## 🔮 Gelecekteki Geliştirmeler

- FastAPI tabanlı REST API
- Birden fazla güvenilir güvenlik kaynağının eklenmesi
- Background crawl işlemleri
- Crawl ilerleme durumunun gösterilmesi
- Kaynak yönetimi
- Gelişmiş log sistemi
- Otomatik testlerin genişletilmesi
- Docker ve Docker Compose desteği
- Gelişmiş güvenlik kontrolleri
- Daha gelişmiş dashboard ve grafikler

## 👩‍💻 Proje

**OSINT Platform**

Python ve Flask kullanılarak geliştirilmiştir.