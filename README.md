<div align="center">

# ⚡ Discord DNS v3.5 — Smart ISP & DPI Bypass Suite

**Türkiye İSS Engellerini (Superonline, Türk Telekom, Vodafone, TürkNet) ve Discord Erişim Kısıtlamalarını Aşmak İçin Geliştirilmiş Akıllı Arayüz & Tünelleme Yazılımı**

![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows_10%2F11-0078D6?logo=windows)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![UI](https://img.shields.io/badge/UI-CustomTkinter-5865F2?logo=discord)
![DPI Bypass](https://img.shields.io/badge/DPI_Engine-GoodbyeDPI_%2B_DoH-orange)

</div>

---

## 📌 Hakkında

**Discord DNS v3.5**, Türkiye'deki internet servis sağlayıcılarının (İSS) Discord ve benzeri platformlara uyguladığı **DNS Hijacking**, **SNI Blocking** ve **DPI (Derin Paket İnceleme)** engellerini tek tıkla aşmak için tasarlanmış gelişmiş bir açık kaynaklı Windows uygulamasıdır.

Uygulama; **TürkNet** kullanıcılarından **Superonline Fiber** ve **Türk Telekom** altyapısındaki ağır engellemelere kadar tüm senaryolarda bağlantınızı otomatik tespit eder ve en uygun bypass kanalını sunar.

---

## ✨ Öne Çıkan Özellikler

### 🌐 1. Akıllı İSS Tespiti (Smart ISP Detector)
- Uygulama başlatıldığında internet sağlayıcınızı (`TürkNet`, `Superonline`, `Türk Telekom`, `Vodafone`, `KabloNet` vb.) arka planda otomatik tespit eder.
- İSS'nizin engelleme türüne göre (DNS Yönlendirmesi / SNI Bloklama) en uygun kanalı otomatik tavsiye eder ve seçer.

### 🔀 2. Üç Farklı Bağlantı Kanalı (Multi-Channel Switching)
- 🟢 **Kanal 1: Standart DNS (TürkNet & Engelsiz İSS'ler)**: Cloudflare (1.1.1.1), Google (8.8.8.8), Quad9, AdGuard, OpenDNS ve ControlD profilleri.
- 🔒 **Kanal 2: DoH (DNS-over-HTTPS) Şifreli DNS**: DNS sorgularını 443/TLS portu üzerinden tam şifreleyerek İSS'nin DNS müdahalelerini engeller (Windows 10/11 uyumlu).
- ⚡ **Kanal 3: Superonline & Türk Telekom DPI Bypass**: GoodbyeDPI & WinDivert sürücü motoru ile TLS Client Hello paketlerini bölerek (packet fragmentation) Superonline ve Türk Telekom'un SNI engellerini tam olarak aşar.

### ⏱ 3. Dijital Kronometre & Manuel Kontrol
- Uygulama ilk açıldığında ağ kartınızı varsayılan (DHCP) konumda tutar; siz **`⚡ ETKİNLEŞTİR`** butonuna basmadan hiçbir işlem yapmaz.
- Kronometre sayacı sadece koruma butonla açıldığında saymaya başlar; kapatıldığında `00:00:00 PASİF — DNS KAPALI` moduna döner.

### 🛡 4. Otomatik Kapanış Restorasyonu (Safe Clean Shutdown)
- Uygulamadan çıkıldığında (veya sistem tepsisinden kapatıldığında) Windows DNS ayarlarınız otomatik olarak orijinal varsayılanına (DHCP) sıfırlanır.
- Arka planda çalışan GoodbyeDPI tüneli ve WinDivert sürücüsü güvenle durdurulup sistemden temizlenir.

### 💓 5. Heartbeat Guard (Kesintisiz Sesli Sohbet Failover)
- Discord sunucuları ile bağlantınızı 25 saniyede bir kontrol eder.
- Bağlantı kalitesi düştüğünde veya İSS kesintisi yaşandığında aktif Discord sesli görüşmenizi koparmadan otomatik olarak bir sonraki en hızlı DNS'e geçiş yapar (Smart Failover).

### ⚡ 6. Multi-DNS Hız Testi (DNS Jumper)
- Tüm popüler DNS sağlayıcılarının gecikme sürelerini (ping/ms) milisaniye hassasiyetinde ölçer ve bölgenizdeki en hızlı DNS'i otomatik olarak seçer.

---

## 🚀 Hızlı Başlangıç (Executable / Derlenmiş Sürüm)

Derlenmiş ve kuruluma ihtiyaç duymayan taşınabilir sürümü kullanmak için:

1. [Releases](../../releases) bölümünden veya `dist/Discord_DNS_v3.exe` dosyasını indirin.
2. Dosyaya sağ tıklayıp **"Yönetici olarak çalıştır"** (Run as Administrator) deyin *(Ağ ayarlarını değiştirmek için Yönetici yetkisi gereklidir)*.
3. Otomatik tespit edilen kanal ile **`⚡ DNS & KANAL ETKİNLEŞTİR`** butonuna basın.

---

## 🛠 Kaynak Koddan Çalıştırma & Geliştirme

### Gereksinimler
- **Python 3.10** veya üstü
- **Windows 10 / 11**

### Kurulum

```bash
# 1. Depoyu klonlayın
git clone https://github.com/berkelmali/Discord-DNS.git
cd Discord-DNS

# 2. Bağımlılıkları yükleyin
pip install -r requirements.txt

# 3. Uygulamayı başlatın (Yönetici yetkisiyle)
python main.py
```

### Kendi `.exe` Dosyanızı Derleyin

Uygulamayı tek bir taşınabilir `.exe` dosyası haline getirmek için:

```bash
python build_exe.py
```
Derlenmiş executable `dist/Discord_DNS_v3.exe` konumunda oluşturulacaktır.

---

## 📂 Proje Mimarisi

```text
Discord-DNS/
├── main.py              # Uygulama giriş noktası (Auto UAC Admin Elevation)
├── gui.py               # CustomTkinter Dark Mode Discord Arayüzü & Kanal Yönetimi
├── dns_manager.py       # PowerShell & netsh DNS okuma, yazma ve DoH yönetimi
├── dpi_bypass.py        # İSS tespiti & GoodbyeDPI / WinDivert tünel motoru
├── discord_checker.py   # Discord HTTP & Ses Bölgesi Ping ölçüm modülü
├── heartbeat_guard.py   # Kesintisiz bağlantı bekçi daemoni (Smart Failover)
├── dns_benchmark.py     # Multi-DNS ping & gecikme kıyaslama motoru
├── admin_utils.py       # Windows UAC Yönetici izni doğrulama & yükseltme
├── build_exe.py         # PyInstaller tek-dosya derleme betiği
├── requirements.txt     # Python bağımlılıkları
└── assets/              # Discord Wumpus logosu ve uygulama ikonları
```

---

## 🔒 Güvenlik & Antivirüs Uyarısı (False Positives)

Uygulama, Windows ağ kartı DNS adreslerini düzenlemek ve WinDivert ağ sürücüsünü yüklemek için **Yönetici Yetkisi (Administrator Privileges)** gerektirir. 

Derlenmiş `.exe` dosyaları imzasız (unsigned executable) olduğu için Windows Defender veya bazı antivirüs yazılımları ağ sürücüsü müdahalesinden dolayı "yalancı pozitif" (false-positive) uyarısı verebilir. Kodların tamamı açık kaynaklıdır ve incelemenize açıktır.

---

## 📜 Lisans

Bu proje [MIT Lisansı](LICENSE) altında lisanslanmıştır. Özgürce kullanabilir, değiştirebilir ve dağıtabilirsiniz.
