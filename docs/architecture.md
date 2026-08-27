# OSINT Platform - Sistem Mimarisi

## 1. Genel Mimari

OSINT Platform, kullanıcıdan alınan arama kriterleri doğrultusunda
NVD üzerinden güvenlik açığı bilgilerini toplayan ve sonuçları
kullanıcıya sunan Python tabanlı bir web uygulamasıdır.

Temel çalışma akışı:

Kullanıcı
↓
Flask Web Arayüzü
↓
Arama İşlemi
↓
Crawler
↓
NVD CVE API
↓
CVE Sonuçları
↓
SQLite Veritabanı
↓
Kullanıcıya Gösterim

## 2. Uygulama Katmanları

### Kullanıcı Arayüzü

HTML ve CSS kullanılarak oluşturulmuştur.

Kullanıcı:

- Anahtar kelime girebilir.
- Severity seviyesi seçebilir.
- CVE sonuçlarını görüntüleyebilir.
- Arama geçmişini görüntüleyebilir.
- Dashboard istatistiklerini inceleyebilir.
- CSV ve PDF çıktısı alabilir.

### Flask Uygulaması

`main.py` dosyası Flask uygulamasının temel yönlendirme
işlemlerini gerçekleştirir.

Başlıca işlemler:

- Ana sayfanın gösterilmesi
- Arama isteğinin alınması
- Sonuçların gösterilmesi
- Arama geçmişinin gösterilmesi
- Dashboard'un gösterilmesi
- CSV oluşturulması
- PDF oluşturulması

### Crawler

`crawler.py` dosyası NVD API üzerinden güvenlik açığı
verilerini almaktadır.

Toplanan temel bilgiler:

- CVE ID
- Açıklama
- Severity
- CVSS skoru
- Yayın tarihi
- Son güncelleme tarihi
- NVD bağlantısı

### Veritabanı

`database.py` SQLite veritabanı işlemlerini yönetmektedir.

Arama geçmişi veritabanında saklanmaktadır.

### Dış Veri Kaynağı

NVD CVE API, güvenlik açığı bilgilerinin alınmasında
kullanılan temel dış veri kaynağıdır.

## 3. Veri Akışı

1. Kullanıcı anahtar kelime girer.
2. Kullanıcı severity filtresi seçebilir.
3. Flask arama isteğini alır.
4. Crawler NVD API'ye istek gönderir.
5. NVD'den CVE kayıtları alınır.
6. CVE bilgileri işlenir.
7. Severity filtresi uygulanır.
8. Sonuçlar kullanıcıya gösterilir.
9. Arama bilgisi SQLite veritabanına kaydedilir.
10. Kullanıcı geçmiş aramalarını Dashboard ve History
    bölümlerinden görüntüleyebilir.

## 4. Dışa Aktarma

Arama geçmişi iki farklı formatta dışa aktarılabilir:

- CSV
- PDF

CSV işlemi Flask Response kullanılarak gerçekleştirilir.

PDF işlemi ReportLab kullanılarak gerçekleştirilir.

## 5. Kullanılan Teknolojiler

- Python
- Flask
- Requests
- SQLite
- HTML
- CSS
- Jinja2
- ReportLab
- NVD CVE API