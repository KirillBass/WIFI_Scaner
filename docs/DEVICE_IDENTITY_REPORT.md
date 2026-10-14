# Device Identity - расширение Milestone 4

ТЗ `WirelessSecurityAnalyzer_DeviceIdentity_Codex.docx` полностью прочитано. Изменения выполнены поверх существующего solution с тремя проектами. WLAN scanner, RSSI, channel analysis, ICMP/neighbor discovery и правила состояний сохранены. Ниже описаны файлы, алгоритмы и ограничения реализации.

Идентификация впервые включена в [Version 5](https://github.com/KirillBass/WIFI_Scanner/releases/tag/v5.0.0). В Version 8 улучшены повторный поиск имён и работа через Wi-Fi и Ethernet.

1. **Изменённые файлы.** Пути от корня проекта:

   - `src/WirelessSecurityAnalyzer.Core/Models/NetworkDevice.cs`: immutable identity, display/friendly/vendor/model/source/update и состояние обогащения.
   - `src/WirelessSecurityAnalyzer.Core/Models/DeviceDiscoveryResult.cs`: признак фонового enrichment в snapshot.
   - `src/WirelessSecurityAnalyzer.Core/Network/DeviceStateTracker.cs`: сохранение identity между циклами/DHCP, merge без изменения LastSeen/FirstSeen/evidence/state, защита от ответа для заменённого устройства.
   - `src/WirelessSecurityAnalyzer.Infrastructure.Windows/Network/DeviceMonitorService.cs`: отдельная отменяемая enrichment task после публикации discovery; Stop/shutdown ожидают её завершения.
   - `src/WirelessSecurityAnalyzer.Infrastructure.Windows/Network/HostnameResolver.cs`: существующий resolver переиспользован; PTR направляется только к локальным DNS выбранного интерфейса, короткий timeout, RD=0, раннее завершение по ответу.
   - `src/WirelessSecurityAnalyzer.Infrastructure.Windows/WirelessSecurityAnalyzer.Infrastructure.Windows.csproj`: embedded OUI resource.
   - `src/WirelessSecurityAnalyzer.App/App.axaml.cs`: DI resolver-ов/cache/transport; production `ResolveHostnames=false` исключает старую блокирующую DNS-фазу discovery.
   - `src/WirelessSecurityAnalyzer.App/ViewModels/DeviceRowViewModel.cs`: display name/vendor/private MAC и подробная подсказка.
   - `src/WirelessSecurityAnalyzer.App/ViewModels/DevicesViewModel.cs`: состояние enrichment, Stop, поиск friendly/vendor, сохранение строк и UI Dispatcher.
   - `src/WirelessSecurityAnalyzer.App/Views/DevicesView.axaml`: имя/производитель, tooltip, фоновый индикатор, видимая горизонтальная прокрутка.
   - `README.md`, `docs/IMPLEMENTATION_STATUS.md`: актуальное поведение и ограничения.
   - Учебный `РАЗБОР_ПРОЕКТА_ЛОКАЛЬНО.md` дополнен локально; он исключён из Git и не публикуется.

2. **Добавленные production-файлы.** В Core:

   - `Models/DeviceIdentity.cs`: identity, DeviceNameSource, DeviceVendorSource, IdentificationConfidence и источники отдельных metadata fields.
   - `Interfaces/IDeviceIdentityResolver.cs`: агрегатор, per-host/network resolver contracts, DeviceIdentityUpdate.
   - `Network/DeviceIdentityMerger.cs`: независимый приоритет каждого поля, сохранение предыдущих данных.
   - `Network/MacAddressHelper.cs`: local bit.

   В `Infrastructure.Windows/Network/Identity/`:

   - `DeviceIdentityOptions.cs`, `DeviceIdentityCache.cs`, `DeviceIdentityResolver.cs`.
   - `LocalComputerNameResolver.cs`, `ReverseDnsNameResolver.cs`, `MdnsNameResolver.cs`, `NetBiosNameResolver.cs`, `LlmnrNameResolver.cs`, `SsdpDeviceResolver.cs`, `MacVendorResolver.cs`.
   - `IdentityDatagramClient.cs`, `DnsPacket.cs`, `UpnpDescriptionClient.cs`.
   - `Data/oui.tsv`, `Data/README.md`.

   Добавлен данный `docs/DEVICE_IDENTITY_REPORT.md`. Новых проектов и NuGet-пакетов нет.

3. **Методы идентификации.** LocalComputer, Reverse DNS, mDNS/DNS-SD, NetBIOS NBSTAT, LLMNR PTR, SSDP/UPnP и OUI. Все сетевые методы читают сведения уже найденных устройств; новых устройств по identity alone не создают. Собственный ПК получает Environment.MachineName без сетевого запроса. Используются стандартные .NET NetworkInterface/UdpClient/TcpClient/Socket/HttpClient/XML API; UI не вызывается из resolver-ов.

4. **Приоритеты.** DisplayName: FriendlyName → Hostname → «-», без vendor fallback. Hostname: LocalComputer → mDNS → Reverse DNS → NetBIOS → LLMNR. FriendlyName: SSDP → опубликованный DNS-SD instance/TXT. Vendor: UPnP manufacturer → OUI. ModelName, ModelDescription и DeviceType объединяются независимо: SSDP → явное mDNS metadata; у каждого сохраняется фактический источник. Пустое/менее приоритетное значение не стирает найденное. Например, SSDP «Living room TV» и PTR «android-123456» сосуществуют. Vendor не создаёт модель или тип. Confidence показывает качество источника, а не криптографическую аутентификацию устройства.

5. **mDNS.** Один network-wide cycle через `224.0.0.251:5353`; source socket привязан к выбранному IPv4 и Windows interface index. Используется one-shot legacy-unicast режим с ephemeral port, без занятого Bonjour port 5353. Questions сгруппированы по 16: DNS-SD PTR известных типов и reverse PTR уже найденных IP. Ответы A/PTR/SRV/TXT индексируются и сопоставляются только с найденными IP. ID проверяется; TTL=0 удаляет record внутри цикла. При отсутствующих дополнительных данных выполняются до 3 bounded follow-up раундов: PTR service type → PTR instance → SRV/TXT → A, максимум 64 questions суммарно. DNS codec проверяет границы, RDATA, длину labels/names, compression loops, число records и TXT/SRV encoding. Исходный `.local` сохраняется. Никаких responder/spoof/capture функций.

6. **SSDP/UPnP.** Один M-SEARCH для root devices к `239.255.255.250:1900`, MX=1, окно 2 секунды. LOCATION deduplicated, максимум 64 description URL и 4 параллельных чтения. Ответ должен принадлежать найденному IP. URL только HTTP/HTTPS с literal IPv4 этого ответившего устройства, без credentials/fragment. Socket привязан к выбранному интерфейсу; TTL=1, destination фиксируется без DNS lookup. Proxy/cookies/redirect выключены; HTTP timeout 1 секунда, headers максимум 16 КБ, тело максимум 512 КБ даже без Content-Length. XML parser запрещает DTD/внешние entities и ограничивает документ; извлекается только root device friendlyName/manufacturer/modelName/modelDescription/deviceType. Control/icon/presentation URL не открываются; UPnP actions не выполняются.

7. **Vendor.** Local OUI snapshot содержит 58 242 префикса MA-L/MA-M/MA-S длиной 24/28/36 бит; longest-prefix match. База встроена в DLL, интернет в runtime не нужен. Первичный реестр - IEEE, публичный снимок получен из Wireshark, поскольку прямой сервер IEEE вернул HTTP 418. Источник, дата получения, provenance и SHA-256 записаны в `Data/README.md`. `04:EC:D8` в снимке - Intel Corporate, `10:A3:B8` - Iskratel d.o.o.; учебные примеры ТЗ не подменяют данные. Явный UPnP manufacturer имеет приоритет над OUI; OUI часто указывает изготовителя NIC, а не готового изделия.

8. **Private MAC.** `MacAddressHelper.IsLocallyAdministered` проверяет `bytes[0] & 0x02` для шестибайтного адреса. При local bit OUI не используется; UI показывает «Приватный / случайный MAC», если нет явного manufacturer. Достоверно опубликованный UPnP manufacturer допустим и для такого MAC. Private MAC не означает установленный факт рандомизации: это локальное назначение адреса.

9. **Cache.** Process-local TTL 15 минут для найденного имени и 30 секунд для результата без имени, максимум 4096 записей с вытеснением по expiry. Контекст: interface ID/index + network/prefix + gateway. Ключ устройства - валидный MAC, иначе IP. Тот же MAC после DHCP-смены IP получает прежний identity; другая сеть/другой MAC на том же IP cache не наследуют. Cache hit не вызывает resolver-ы; после TTL разрешено обновление. Пустой завершённый результат кэшируется только на 30 секунд; после этого следующий scan/monitoring допускает повторную попытку. «Обновить имена» адресно делает записи текущих целей устаревшими и запускает lookup сразу, сохраняя прежние хорошие данные. Нулевой ответ не стирает историю. Незавершённое отменённое разрешение не кэшируется; завершённые устройства большого batch сохраняются отдельно после окончания сетевых методов, чтобы следующий цикл продолжал обработку оставшихся адресов.

10. **Задержка discovery и monitoring.** Сам WindowsDeviceDiscoveryService не переписан; в production отключена его необязательная blocking hostname phase. Monitor сначала публикует IP/MAC/latency/state/history, затем Task.Run запускает агрегатор. До 4 per-host name operations и 4 UPnP HTTP reads одновременно; mDNS/SSDP по одному циклу на сеть. Имя обновляет прежний row на UI Dispatcher, без изменения LastSeen или presence. Delay monitoring не ждёт identity; следующий завершённый discovery отменяет прежний незавершённый batch и запускает обработку новых/cache-expired устройств. Stop/context switch/shutdown отменяют и ожидают задачи; late callbacks отклоняются. Независимого бесконечного name-resolution loop нет.

11. **Ограничения.** Только выбранная IPv4-сеть. Private/rotating MAC не даёт устойчивой идентичности между разными адресами. Нет гарантии имени: sleep/isolation/firewall/disabled protocols/устройство без опубликованных сведений дают «-». mDNS legacy-unicast и multi-question ответы поддерживаются не всеми устройствами; стартовый DNS-SD service list дополняется объявленными типами с ограничением 64 follow-up questions и не является сканером служб. LLMNR reverse использует TCP 5355 по RFC 4795, а не недопустимый unicast UDP. Public/VPN/off-subnet DNS пропускается, рекурсивный поиск не запрашивается; пересылку локальным DNS-сервером вопреки RD=0 приложение контролировать не может. PTR CNAME chains/UDP truncation TCP fallback не реализованы. LOCATION hostname URL и HTTPS с недоверенным сертификатом пропускаются; embedded UPnP devices отдельно не идентифицируются. OUI - локальный snapshot без автообновления. Последний хороший identity сохраняется в истории с timestamp; TTL запускает повторную попытку, но сам по себе не доказывает, что старое имя неверно. Отдельная selected-device panel заменена подробным tooltip. Идентификация устройств не использует external web API, telemetry, port/service scanner, SMB/Nmap/capture/poisoning/UPnP control. Аудит портов и служб добавлен отдельно в Milestone 6.

Источники протоколов: [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762), [RFC 6763](https://www.rfc-editor.org/rfc/rfc6763), [RFC 4795 §2.4](https://www.rfc-editor.org/rfc/rfc4795), [RFC 1002](https://www.rfc-editor.org/rfc/rfc1002), [UPnP Device Architecture 2.0](https://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v2.0.pdf), [Microsoft IP_UNICAST_IF](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options).

## Исправление повторного поиска имён - 14.10.2026

По скриншоту видны найденные IP/MAC, но отсутствуют имена у части узлов. Наличие адреса в ARP/neighbor/discovery не гарантирует ответ DNS/mDNS/NBSTAT/LLMNR/SSDP. Собственный ПК получает имя локально, router может публиковать UPnP friendlyName, а другие устройства могут спать, не публиковать имя или не отвечать из-за фильтрации. Приватный MAC отключает вывод производителя по OUI, но сам по себе не запрещает получение имени. Offline-узел не запрашивается, пока снова не станет Online.

В коде исправлены два воспроизводимых недостатка: результат без имени раньше блокировал повторные запросы на 15 минут; mDNS выполнял только один дополнительный запрос и мог не получить A после отдельно пришедшего SRV либо неверно запрашивать SRV вместо PTR для обнаруженного типа службы.

Изменения:

- `DeviceIdentityOptions` / `DeviceIdentityCache`: отдельный `UnresolvedCacheTtl=30s`, адресная invalidation, сохранение предыдущих данных при неудаче. Сетевой контекст, ключ MAC/IP и лимит 4096 сохранены.
- `DeviceIdentityResolver`: принудительная invalidation, объединение устаревших хороших данных до новых запросов; приоритет целей без завершённого lookup перед повторными попытками, чтобы короткий monitoring не оставлял последние устройства без обработки.
- `MdnsNameResolver`: ограниченные последовательные PTR service type / PTR instance / SRV-TXT / host A, без повторов/внешних DNS-имён; адресные записи обрабатываются в первую очередь.
- `IDeviceIdentityResolver`, `IDeviceMonitorService`, `DeviceMonitorService`: отдельная отменяемая операция обновления идентификации существующих устройств без нового discovery. Проверяется текущий контекст; Stop/reset/shutdown отменяют её как прежний enrichment.
- `DevicesViewModel`, `DevicesView.axaml`, `DeviceRowViewModel`: «Обновить имена», пояснение независимости IP/MAC и имени, ясное сообщение об остановке поиска, tooltip для pending/unknown/offline.

## Общий механизм для Ethernet и Wi-Fi

Проблема: кэш был строго привязан к interface ID/index. При смене Ethernet на Wi-Fi имя нужно было получить заново, а новый путь мог не доставлять multicast либо не получать NBSTAT/LLMNR/PTR. При подключении к Wi-Fi весь кэш дополнительно очищался. Кроме того, Unknown-устройства вообще не участвовали в новом поиске имени.

Реализовано поверх прежних сервисов:

- `DeviceIdentityCache`: общий пул до 4096 записей с прежним локальным ключом interface/subnet/gateway/MAC. Дополнительное получение имени по подтверждаемому контексту LAN: subnet/prefix + gateway IP + свежий gateway MAC + target MAC. Нужна Online-запись шлюза с NeighborEntry evidence. При другом шлюзе, MAC, подсети, отсутствии proof, отсутствии target MAC или IsLocalMachine перенос не выполняется.
- `ResetSession` заменяет безусловный Clear при смене Wi-Fi-сессии: локальные hits становятся недействительны; для возможного переноса остаются только недавние имена удалённых устройств с LAN proof. Без нового совпадения шлюза эти записи не читаются. `Clear` по-прежнему полностью удаляет кэш. Discovery/history/port-audit другой сессии не переносятся.
- Перенесённое имя - начальное значение, а не причина пропускать запросы через новый интерфейс. TTL общего имени отсчитывается от реального получения имени, не от последней безуспешной попытки или обновления vendor.
- `DeviceIdentity.NameObservedAt/NameObservedVia`, merger и подсказка строки: время и интерфейс получения именно отображаемого имени, отдельно от остального identity metadata. Нижестоящий hostname не переписывает происхождение отображаемого friendly name. На другом интерфейсе tooltip называет имя сохранённым.
- `MdnsUnicastNameResolver` в существующем файле mDNS: прямой read-only PTR к найденному IP:5353, с привязкой к выбранному IPv4/Windows interface. Проверяются source IP/port, ID, вопрос, DNS-класс и TTL>0; используются только сопоставленные `.local` данные. Socket mDNS использует IP TTL 255; multicast resolver сохранён. Прямые запросы описаны в [RFC 6762 §5.5](https://www.rfc-editor.org/rfc/rfc6762#section-5.5).
- `LocalDnsServerProvider`: проверяет существующий Up-адаптер, его индекс и собственный IPv4; добавляет шлюз в той же подсети как запасной DNS, даже если настроен публичный DNS. Off-subnet/public DNS не опрашивается. До 3 кандидатов в общем прежнем таймауте; ошибка одного DNS допускает следующий. RD=0 сохранён.
- `DeviceIdentityResolver` / `RecentDeviceWindow=2min`: недавние Unknown также допускаются к name lookup. Наличие имени не меняет presence, FirstSeen/LastSeen или ICMP evidence. При разных MAC на одном IP запрос получает только наиболее актуальный occupant; старые записи сохраняются как история, чтобы новый ответ не был присвоен прежнему устройству. Старые Unknown и Offline не опрашиваются.
- DI, строки интерфейса и история состояния адаптированы без нового solution или NuGet-пакетов.

Фактическая доступность протоколов по Wi-Fi всё равно зависит от настроек устройств и сети. Функция не обходит Client Isolation/firewall, не использует внешние web API и не угадывает имя по производителю. Имя, которое нигде не опубликовано и ранее не было получено, гарантированно определить нельзя.
