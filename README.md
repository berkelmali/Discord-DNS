<div align="center">

# ⚡ Discord DNS v3.6 — Smart ISP & DPI Bypass Suite

**Türkiye İSS Engellerini (Superonline, Türk Telekom, Vodafone, TürkNet) ve Discord Erişim Kısıtlamalarını Aşmak İçin Geliştirilmiş Akıllı Arayüz & Tünelleme Yazılımı**

![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows_10%2F11-0078D6?logo=windows)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![UI](https://img.shields.io/badge/UI-CustomTkinter-5865F2?logo=discord)
![DPI Bypass](https://img.shields.io/badge/DPI_Engine-Native_WinDivert_%2B_Local_DoH-orange)

</div>

---

## 📌 Hakkında

**Discord DNS v3.6**, Türkiye'deki internet servis sağlayıcılarının (İSS) Discord ve benzeri platformlara uyguladığı **DNS Hijacking**, **SNI Blocking** ve **DPI (Derin Paket İnceleme)** engellerini tek tıkla aşmak için tasarlanmış gelişmiş bir açık kaynaklı Windows uygulamasıdır.

Uygulama; **TürkNet** kullanıcılarından **Superonline Fiber** ve **Türk Telekom** altyapısındaki ağır engellemelere kadar tüm senaryolarda bağlantınızı otomatik tespit eder ve en uygun bypass kanalını sunar.

---

## ✨ Öne Çıkan Özellikler

### 🌐 1. Akıllı İSS Tespiti & Otomatik Hazırlık
- Uygulama başlatıldığında internet sağlayıcınızı (`TürkNet`, `Superonline`, `Türk Telekom / Avea`, `Vodafone`, `KabloNet` vb.) arka planda otomatik tespit eder.
- Aynı anda altı DNS sağlayıcısını ölçer ve **en hızlısını kendiliğinden seçer** — siz açtığınızda bağlantı ekranı çoktan hazırdır (elle bir profil seçtiyseniz ona dokunmaz).
- İSS'nizin engelleme türüne göre (DNS Yönlendirmesi / SNI Bloklama) en uygun kanalı otomatik tavsiye eder ve seçer.

### 🔀 2. Üç Farklı Bağlantı Kanalı (Multi-Channel Switching)
- 🟢 **Kanal 1: Standart DNS (TürkNet & Engelsiz İSS'ler)**: Cloudflare (1.1.1.1), Google (8.8.8.8), Quad9, AdGuard, OpenDNS ve ControlD profilleri.
- 🔒 **Kanal 2: DoH (DNS-over-HTTPS) Şifreli DNS**: Uygulamanın **kendi yerel DNS çözümleyicisi** (`127.0.0.1:53`) devreye girer; tüm sorgular Cloudflare/Google/Quad9'a 443/TLS üzerinden şifreli gider. Windows 10 ve 11'de aynı şekilde çalışır, IPv6 sızıntısına karşı `::1` de dinlenir.
- ⚡ **Kanal 3: Superonline & Türk Telekom DPI Bypass**: **Uygulamanın kendi paket motoru** (WinDivert 2.2 sürücüsü üzerinde, harici `goodbyedpi.exe` süreci olmadan) TLS ClientHello paketini SNI alan adının ortasından böler, sahte paket enjekte eder ve segmentleri ters sırayla göndererek SNI engellerini aşar.

### ⏱ 3. Dijital Kronometre & Manuel Kontrol
- Uygulama ilk açıldığında ağ kartınıza hiç dokunmaz; siz **`⚡ BAĞLAN`** butonuna basmadan hiçbir işlem yapmaz.
- Kronometre sayacı sadece koruma butonla açıldığında saymaya başlar; kapatıldığında `00:00:00 PASİF — DNS KAPALI` moduna döner.

### 🛡 4. Otomatik Kapanış Restorasyonu (Safe Clean Shutdown)
- Koruma kapatıldığında veya uygulamadan çıkıldığında DNS ayarlarınız **kendi orijinal sunucularınıza** geri döner (DHCP'ye değil) — koruma açılırken alınan yedek, hangi ağ kartında hangi adreslerin olduğunu bilir.
- Pencerenin **X** düğmesi uygulamayı kapatmaz, sistem tepsisine küçültür; tamamen çıkmak için tepsi menüsünden **Çıkış**'ı seçin. Koruma açıkken küçülttüğünüzde uygulama bunu bildirimle hatırlatır.
- Yerel DPI motoru ve DoH çözümleyici durdurulur; WinDivert sürücüsü son tanıtıcı kapandığında kendini sistemden kaldırır.

### 💓 5. Heartbeat Guard (Kesintisiz Sesli Sohbet Failover)
- Discord sunucuları ile bağlantınızı 25 saniyede bir kontrol eder.
- Bağlantı kalitesi düştüğünde veya İSS kesintisi yaşandığında aktif Discord sesli görüşmenizi koparmadan otomatik olarak bir sonraki en hızlı DNS'e geçiş yapar (Smart Failover).

### ⚡ 6. Multi-DNS Hız Testi (DNS Jumper)
- Tüm popüler DNS sağlayıcılarının gecikme sürelerini (ping/ms) milisaniye hassasiyetinde ölçer ve bölgenizdeki en hızlı DNS'i otomatik olarak seçer.

### 🎯 7. Otomatik Strateji Bulucu
- "Bende çalışmıyor" sorununu tahminle değil **ölçümle** çözer: engel aşma profillerini en hafiften en agresife doğru tek tek dener.
- Her profil için hedef sitelere **gerçek TLS bağlantısı** kurar (sertifika doğrulaması açık), kaçının açıldığını sayar ve hepsini açan **en hafif** profili seçer.
- Engel DNS katmanındaysa bunu ayırt eder ve DPI profili yerine Kanal 2'yi önerir; hiç engel yoksa "gerek yok" der.

### 🔬 8. Test & Kanıtla Paneli
- Tek tuşla tanılama raporu: sürücü durumu, motor sayaçları, DNS kaçırma kontrolü, gerçek bağlantı testleri ve paket kanıtı.
- Rapor **paylaşıma hazırdır**: genel IP maskelenir (`95.70.x.x`), kişisel veri toplanmaz. Panoya kopyalayıp GitHub issue'suna yapıştırabilirsiniz.

### 🛡 9. Otomatik TTL & RST Koruması
- Gelen SYN-ACK paketinin TTL'inden sunucunun kaç sekme uzakta olduğu öğrenilir; sahte paket **İSS'nin DPI kutusunu geçip sunucuya varmadan** ölecek şekilde ayarlanır.
- DPI'ın bağlantıyı öldürmek için ürettiği sahte RST paketleri düşürülür — yalnızca motorun dokunduğu akışlar için ve yalnızca birkaç saniyelik pencerede, böylece sunucunun gerçek RST'si engellenmez.

---

## 🧠 Yerel DPI Motoru Nasıl Çalışıyor?

v3.6 ile birlikte engel aşma işini **harici bir program değil, uygulamanın kendi motoru** yapar. `goodbyedpi.exe` yalnızca yerel motor sürücüyü açamazsa devreye giren yedek plandır.

Motor, WinDivert filtresi sayesinde çekirdekten yalnızca **ilgili paketleri** alır (TLS ClientHello ve düz HTTP istekleri); geri kalan tüm trafik hiç kullanıcı alanına çıkmadan hızlı yolda devam eder. Yakalanan her pakette sırasıyla:

1. **Sahte paket (decoy)** — gerçek paketle aynı uzunlukta, SNI alanı zararsız bir alan adıyla (`www.microsoft.com` vb.) değiştirilmiş ve **TCP sağlaması kasten bozulmuş** bir kopya gönderilir. DPI kutusu bu paketi kaydeder, hedef sunucu ise sağlama hatalı olduğu için atar.
2. **SNI içinden bölme** — gerçek ClientHello, biri TLS kayıt başlığında biri de **alan adının tam ortasında** olmak üzere iki noktadan kesilir. Hiçbir TCP segmentinde aranabilir bir alan adı kalmaz.
3. **Ters sıralı gönderim** — segmentler son parçadan başlayarak gönderilir; yalnızca ilk segmente bakan DPI motorları akışı hiç eşleştiremez.
4. **QUIC kapatma (opsiyonel)** — UDP/443 düşürülerek tarayıcılar TCP+TLS'e döner, böylece yukarıdaki adımlar bu trafiğe de uygulanır.

İSS profillerine göre hazır stratejiler `dpi_engine.PRESETS` içinde tanımlıdır ve strateji bulucu bunları en hafiften en agresife doğru dener:

`vodafone` → `general` → `ttnet` → `superonline` → `hardened` → `maximum` → `stateful` → `stateful_fake_only` → `native_frag`

**Sahada doğrulandı (Türk Telekom / Avea mobil hattı):**

```
Motor kapalıyken:  discord.com FAIL — SNI engeli, İSS bağlantıyı RST ile kesti
                   gateway.discord.gg FAIL — aynı

→ Durum Takipli DPI profili:  2/2 hedef açıldı, ortanca 188 ms
                              (2 paket yeniden yazıldı, 0 RST engellendi)
```

`0 RST engellendi` satırı burada en önemli veri: DPI kutusu reset **göndermedi bile**. Yani bağlantı "reset'e rağmen ayakta kalmadı" — engel hiç tetiklenmedi. Aynı hatta yalnızca parçalamaya dayanan yedi profilin tamamı başarısız oldu, çünkü o kutu TCP akışını yeniden birleştiriyor.

**Durum takipli DPI için özel profiller:** Türk Telekom mobil (Avea) hattında yapılan ölçüm, oradaki DPI kutusunun TCP akışını **yeniden birleştirdiğini** gösterdi — parçalama tek başına yetmiyor. Bu kutulara karşı sahte paketin *doğru sıra numarasında* olması ve sunucuya varmadan **TTL ile ölmesi** gerekir (pencere dışı `badseq` sahte paketini durum takibi yapan DPI zaten yok sayar). `stateful` ve `stateful_fake_only` profilleri tam olarak bunu yapar; sunucu mesafesi henüz öğrenilmemişse sahte paket **hiç gönderilmez**, çünkü yanlış TTL gerçek el sıkışmasını bozardı.

Ayrıca yalnızca Discord alan adlarına dokunan `discord_only` profili vardır.

### GoodbyeDPI ile karşılaştırma

Motor, GoodbyeDPI'nin HTTPS/SNI tekniklerinin tamamını kendi kodumuzla uygular; kapsamı dürüstçe belirtmek gerekirse:

| GoodbyeDPI özelliği | Bu uygulamada |
|---|---|
| `-e` / `-f` ClientHello parçalama | ✅ SNI **içinden** bölme (sabit ofsetten güçlü) |
| `--reverse-frag` ters sıra | ✅ |
| `--wrong-seq` pencere dışı sahte paket | ✅ varsayılan |
| `--wrong-chksum` bozuk sağlamalı sahte paket | ✅ (badseq ile birlikte) |
| `--auto-ttl` otomatik TTL | ✅ gelen SYN-ACK'ten mesafe öğrenilir |
| `--native-frag` IP katmanında parçalama | ✅ `native_frag` profili |
| `-p` pasif DPI engelleme (sahte RST) | ✅ tüm profillerde varsayılan; art arda gelen RST'lerin **hepsini** düşürür (TTL ayrımı opsiyonel — ölçümde DPI'ın TTL taklit ettiği görüldü) |
| `-r` `Host:` → `hOsT:` | ✅ |
| `-m` Host değerinde harf karıştırma | ✅ |
| `-s` + `-a` boşluk taşıma | ✅ **çift olarak** (uzunluk korunur, TCP akışı bozulmaz) |
| `--blacklist` alan adı listesi | ✅ `%APPDATA%\DiscordDNS\blacklist.txt` |
| `--dns-addr` DNS yönlendirme | ✅ yerine şifreli yerel DoH çözümleyici |
| `-k` HTTP isteğini N parçaya bölme | ➖ TLS bölme mevcut, HTTP için ayrı parçalama yok |
| Windows servisi olarak kurulum | ➖ uygulama açıkken çalışır |

### Performans

Motor, çekirdek filtresi sayesinde yalnızca ClientHello ve HTTP isteklerini kullanıcı alanına alır; video, indirme ve oyun trafiği hiç uğramaz.

| Ölçüm | Sonuç |
|---|---|
| ClientHello başına işlem maliyeti | **~150-200 mikrosaniye** (sahte paket üretimi ve sağlama hesabı dahil, gerçek kod yolunda ölçüldü) |
| Toplu veri trafiğine etkisi | **yok** — çekirdek hızlı yolunda kalır |
| DNS: modem (şifresiz) | ~17 ms |
| DNS: yerel DoH (şifreli) | ~15 ms |
| DNS: yerel DoH (önbellekten) | ~0.2 ms |

Şifreli DNS, kalıcı HTTPS bağlantısı ve önbellek sayesinde pratikte İSS DNS'inden **daha yavaş değildir**.

### Test Etme

```bash
# Birim testleri: paket cerrahisi, SNI, bölme, sağlama, otomatik TTL, RST filtresi
python -m tests.test_dpi_engine

# Paket kanıtı: gerçek bir ClientHello'nun telde nasıl parçalandığını gösterir
python -m tests.test_dpi_wire

# Gerçek trafikle canlı tanılama — YÖNETİCİ olarak açılmış bir terminalde
python -m tests.test_dpi_live
```

`test_dpi_live`, motoru açıp gerçek TLS bağlantıları kurar, kaç paketin yeniden yazıldığını raporlar, sonra motoru kapatıp arkada bir şey kalmadığını doğrular.

---

## 🔌 VPN Gibi Çalışır: Bağlan / Bağlantıyı Kes

Arayüz de buna göre kurulmuştur: **bağlantı paneli ilk ekranda** — kanal seçimi, DPI profili, bağlantı durumu ve **BAĞLAN** butonu, hiç kaydırmadan görünür. Pencere sabit bir piksel boyutuyla değil, ekranınıza ve içeriğin gerçek genişliğine göre açılır; yüksek DPI ekranlarda içerik kesilmez.

Tek buton, beş durum — ve her ikisi de **doğrulanır**:

| Durum | Buton | Ne oluyor |
|---|---|---|
| `disconnected` | ⚡ **BAĞLAN** | Sisteme hiç dokunulmamış |
| `connecting` | ⏳ BAĞLANILIYOR… | DNS uygulanıyor, motor açılıyor, **gerçek TLS bağlantısıyla sınanıyor** |
| `connected` | ⏹ **BAĞLANTIYI KES** | Hedeflere erişim ölçülerek doğrulandı |
| `disconnecting` | ⏳ KAPATILIYOR… | Motorlar durduruluyor, DNS geri yükleniyor |
| `error` | ⏹ BAĞLANTIYI KES (sorun var) | Bağlandı ama engel aşılamadı — sebep loglandı |

**BAĞLAN** yalnızca ayar uygulamaz; uyguladıktan sonra hedeflere **gerçek TLS bağlantısı** açar. Hâlâ engelliyse, çalışan bir profil bulunana kadar merdiveni kendisi tırmanır ve ancak ölçülen bir başarıdan sonra "bağlandı" der. Bulamazsa nedeni katman katman loglar.

**BAĞLANTIYI KES** motorları durdurur, **kendi orijinal DNS sunucularınızı** geri yükler (DHCP'ye değil) ve sonra **doğrular**: motor gerçekten durdu mu, çözümleyici kapandı mı, ağ kartı hâlâ `127.0.0.1`'e mi bakıyor. Eksik kalan bir şey varsa açıkça söyler.

**Otomatik toparlama:** Bağlıyken İSS davranışını değiştirirse uygulama kendi kendine çalışan yeni bir strateji arar ve ona geçer — siz hiçbir şey yapmadan.

**Kopma tespiti ~12 saniye.** Koruma açıkken kontrol aralığı 10 saniyeye iner ve başarısız bir kontrol tam tur beklemeden 2 saniye içinde doğrulanır (önceden iki adet 25 saniyelik tur, yani ~50 saniye).

Kontrolün kendisi de değişti: eskiden yalnızca TCP bağlantısı kuruluyordu, bu da Türkiye hatlarında **iki yönde birden yanlış** sonuç veriyordu — DNS kaçırılan hatta bağlantı engel sunucusuna oturup "çalışıyor" diyordu, engel sunucusuna erişilemeyen hatta ise uygulamanın kendi şifreli yolu sorunsuz çalışırken "koptu" diyordu. Artık şifreli DNS ile çözülmüş gerçek adrese tam TLS el sıkışması yapılır ve başarısızlığın nedeni (SNI reseti / DNS kaçırma / zaman aşımı) günlüğe yazılır.

**DPI profili seçici:** VPN'lerdeki sunucu listesi gibi; `Otomatik (İSS'ye göre)` bırakabilir ya da profillerden birini elle seçebilirsiniz — yalnızca Discord alan adlarına dokunan `Sadece Discord` profili dahil.

**Ayarlarınız hatırlanır.** Seçtiğiniz kanal, DNS sağlayıcısı, DPI profili ve ağ kartı bir sonraki açılışta hazır gelir. Elle yaptığınız seçimler, otomatik tespit ve hız testi tarafından **ezilmez** — uygulama ölçümü bildirir, kararı size bırakır.

**Windows ile başlat — yönetici olarak, UAC sormadan.** Tek kutucukla uygulama açılışta başlatılır. Bu iş için kayıt defteri `Run` anahtarı yerine **yönetici yetkili zamanlanmış görev** kullanılır; çünkü `Run` anahtarı uygulamayı yetkisiz başlatır ve her açılışta UAC onayı sorulmasına yol açar. Yönetici yetkisi yoksa uygulama `Run` anahtarına düşer ve bunu size açıkça söyler.

**Açılışta otomatik bağlan.** İkinci bir kutucukla uygulama açılır açılmaz (İSS tespiti ve hız testi bittikten sonra) kendiliğinden bağlanır. İkisi birlikte, Windows servisi kurmadan "açılıştan itibaren koruma" davranışını verir.

**Alan adı listesi artık uygulama içinden düzenlenir.** Günlük çubuğundaki `📝 Liste` düğmesi listeyi açar; `Discord alan adlarını doldur` ile tek tıkta hazırlanır. Liste boş bırakılırsa motor tüm trafiğe uygulanır.

**Yedekleme zinciri ölçüme göre sıralanır.** Heartbeat bir sağlayıcıda sorun görürse altı sağlayıcının hepsine geçebilir ve sıra, hız testinin ölçtüğü gecikmeye göre belirlenir — daha yavaş bir sağlayıcıya düşmez. (Önceden zincir üç sağlayıcıyla sınırlıydı ve uygulamanın kendi ölçtüğü en hızlı sağlayıcı bile dışarıda kalabiliyordu.)

---

## 🩺 Bağlanamadığında Nedenini Söyler

Uygulama "bağlanamadı" demekle yetinmez; engeli **katman katman** ölçüp mekanizmayı adıyla söyler:

| Teşhis | Anlamı | Çözümü |
|---|---|---|
| `dns_hijack` | İSS DNS yanıtını engel sunucusuna çeviriyor | Kanal 2 (şifreli DNS) |
| `sni_rst` | TCP kuruluyor, alan adı görülünce sahte RST geliyor | Kanal 3 (DPI motoru) |
| `sni_timeout` | Alan adı görülünce paketler sessizce yutuluyor | Kanal 3 |
| `tcp_blocked` | Sunucuya TCP hiç kurulamıyor (IP/port engeli) | DPI motoru çözemez |
| `mitm` | Sahte sertifika sunuluyor | Kanal 2 |

Örnek log çıktısı:

```
🔎 Erişim sorunu teşhisi: SNI ENGELİ: TCP bağlantısı kuruluyor, ancak İSS alan
   adını (discord.com) görür görmez bağlantıyı sahte bir RST paketiyle kesiyor.
    · Sistem DNS'i (172.20.10.1) → 195.175.254.2, gerçek adres → 162.159.128.233
    · TCP 162.159.128.233:443 → açık
    · ClientHello gönderildikten hemen sonra RST geldi
↪ Öneri: Kanal 3 (DPI Bypass) veya 🎯 Strateji Bul.
```

Farklı IP + geçerli sertifika durumunu **CDN farkı** olarak ayırt eder, boş yere "kaçırma" demez.

### Kendi alan adı listeniz

`%APPDATA%\DiscordDNS\blacklist.txt` dosyası oluşturursanız motor **yalnızca** oradaki alan adlarına dokunur, geri kalan tüm trafiğinize hiç karışmaz:

```text
# satır başına bir alan adı, # ile yorum
discord.com
discord.gg
discordapp.net
```

---

## 🔔 Sistem Tepsisi Davranışı

Uygulama açıkken Windows 11, **yeni tepsi simgelerini varsayılan olarak gizli alana** (görev çubuğundaki `^` oku) koyar. Bu Windows'un davranışıdır, uygulamanın değil — hiçbir program kendini bu alandan zorla çıkaramaz.

Simgeyi kalıcı olarak görünür yapmak için iki yol var:

1. Görev çubuğundaki `^` okuna tıklayıp **Discord DNS simgesini sürükleyip** görev çubuğuna bırakın, veya
2. **Ayarlar → Kişiselleştirme → Görev çubuğu → Diğer sistem tepsisi simgeleri** yolundan Discord DNS'i açık konuma alın.

Simgenin üzerine geldiğinizde durum canlı olarak yazar (`🔒 Şifreli DNS · ⚡ DPI motoru` gibi), böylece pencereyi açmadan korumanın aktif olduğunu görebilirsiniz.

---

## 🆘 İnternet Gitti mi? (Acil Kurtarma)

Kanal 2 açıkken uygulama **görev yöneticisinden zorla kapatılırsa** (normal kapatma ve Ctrl+C güvenlidir), ağ kartı `127.0.0.1`'e bakmaya devam edebilir. Bu duruma karşı üç katman var:

1. **Güvenlik ağı** — ikincil DNS olarak Cloudflare yazılır; yerel çözümleyici susarsa Windows otomatik ona düşer, internet kesilmez.
2. **Nöbetçi (watchdog)** — uygulama açıkken her 30 saniyede kontrol eder; DNS `127.0.0.1`'de ama çözümleyici kapalıysa kendi kendine geri alır.
3. **Açılışta onarım** — uygulama yönetici olarak açıldığında yedekteki orijinal DNS'i geri yükler.

Yine de elle düzeltmek istersen, yönetici komut isteminde:

```bash
netsh interface ipv4 set dns name="Wi-Fi" dhcp
```

```bash
netsh interface ipv6 set dns name="Wi-Fi" dhcp
```

---

## 🚀 Hızlı Başlangıç (Executable / Derlenmiş Sürüm)

Derlenmiş ve kuruluma ihtiyaç duymayan taşınabilir sürümü kullanmak için:

1. **[Releases](../../releases)** bölümünden en son sürümün `.exe` dosyasını indirin.
2. Dosyaya sağ tıklayıp **"Yönetici olarak çalıştır"** (Run as Administrator) deyin *(Ağ ayarlarını değiştirmek için Yönetici yetkisi gereklidir)*.
3. Otomatik tespit edilen kanal ile **`⚡ BAĞLAN`** butonuna basın.

> Executable artık depoda tutulmuyor, sürüm varlığı (release asset) olarak yayımlanıyor: her derleme depoya ~31 MB ekliyordu. Kaynaktan kendiniz derlemek isterseniz `python build_exe.py` yeterli.

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
Derlenmiş executable `dist/Discord_DNS_v3.exe` konumunda oluşturulacaktır (bu klasör sürüm kontrolüne dahil değildir).

---

## 📂 Proje Mimarisi

```text
Discord-DNS/
├── main.py              # Uygulama giriş noktası (Auto UAC Admin Elevation)
├── gui.py               # CustomTkinter Dark Mode Discord Arayüzü & Kanal Yönetimi
├── dns_manager.py       # PowerShell & netsh DNS okuma, yazma ve yerel çözümleyici yönlendirmesi
├── dpi_bypass.py        # İSS tespiti & motor seçimi (yerel motor / yedek goodbyedpi)
├── dpi_engine.py        # Yerel DPI bypass motoru (paket bölme, sahte paket, ters sıra)
├── dpi_packets.py       # IPv4/IPv6 + TCP, TLS ClientHello (SNI) ve HTTP paket cerrahisi
├── windivert.py         # WinDivert 2.2 sürücüsüne ctypes bağlayıcısı (harici bağımlılık yok)
├── doh_proxy.py         # Yerel DNS-over-HTTPS çözümleyici (127.0.0.1:53 → 443/TLS)
├── strategy_finder.py   # Otomatik strateji bulucu (profilleri ölçerek seçer)
├── diagnostics.py       # Paylaşılabilir tanılama raporu (kişisel veri maskeli)
├── discord_checker.py   # Discord HTTP & Ses Bölgesi Ping ölçüm modülü
├── heartbeat_guard.py   # Kesintisiz bağlantı bekçi daemoni (Smart Failover)
├── dns_benchmark.py     # Multi-DNS ping & gecikme kıyaslama motoru
├── admin_utils.py       # Windows UAC Yönetici izni doğrulama & yükseltme
├── build_exe.py         # PyInstaller tek-dosya derleme betiği
├── requirements.txt     # Python bağımlılıkları
├── tests/               # Tanılama ve birim testleri (test_dpi_engine, test_dpi_live)
└── assets/              # İkonlar + WinDivert 2.2 sürücü dosyaları (x64/x86)
```

---

## 🔒 Güvenlik & Antivirüs Uyarısı (False Positives)

Uygulama, Windows ağ kartı DNS adreslerini düzenlemek ve **WinDivert 2.2** ağ sürücüsünü yüklemek için **Yönetici Yetkisi (Administrator Privileges)** gerektirir. Sürücü dosyaları `assets/windivert/` altında imzalı olarak gelir; çalışırken `%APPDATA%\DiscordDNS\bin\windivert\` klasörüne kopyalanır ve son tanıtıcı kapandığında Windows tarafından kaldırılır. 

Derlenmiş `.exe` dosyaları imzasız (unsigned executable) olduğu için Windows Defender veya bazı antivirüs yazılımları ağ sürücüsü müdahalesinden dolayı "yalancı pozitif" (false-positive) uyarısı verebilir. Kodların tamamı açık kaynaklıdır ve incelemenize açıktır.

---

## 📜 Lisans & Atıf Zorunluluğu (Attribution Requirement)

Bu proje **Berk Elmalı** tarafından geliştirilmiş olup [Zorunlu Atıf Şartlı MIT Lisansı](LICENSE) altında açık kaynak olarak paylaşılmıştır.

> [!IMPORTANT]
> **Atıf (Credit) Zorunluluğu**: Bu projenin kodlarını veya herhangi bir bölümünü kopyalayan, özelleştiren, yeniden dağıtan veya çatal (fork) oluşturan herkes, projenin **Berk Elmalı** tarafından geliştirildiğini ve orijinal depo bağlantısını (**https://github.com/berkelmali/Discord-DNS**) açıkça belirtmek **ZORUNDADIR**.
