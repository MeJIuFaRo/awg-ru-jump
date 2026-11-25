# Входной узел в РФ

Клиент сохраняет профиль AmneziaWG и DNS-адрес из приложения. На сервере mosdns разбирает запросы, а nftables выбирает маршрут для нового IPv4-соединения. Сети из GeoIP и адреса, полученные для доменов GeoSite, выходят через российский WAN. Для остальных публичных адресов используется доступный зарубежный путь.

## 1. Проверить исходную конфигурацию

Установите AmneziaWG и AmneziaDNS на этом сервере через официальное приложение AmneziaVPN, включите использование AmneziaDNS в клиентском профиле и проверьте на клиенте работу интернета и DNS. Должны работать контейнеры `amnezia-awg2` и `amnezia-dns`. Для готового примера поднимите IPIP, GRE и зарубежный выход согласно инструкции. Команды ниже выполняются на входном узле из корня копии репозитория. [Туннели и зарубежный узел](exit.md)

```sh
sudo apt-get update
sudo apt-get install -y python3 nftables iptables iproute2 util-linux dnsutils ca-certificates golang-go
sudo systemctl is-active docker.service ru-exit-tunnels.service
sudo docker inspect --format '{{.Name}} running={{.State.Running}}' amnezia-awg2 amnezia-dns
sudo docker inspect --format '{{.Name}} {{range $name,$net := .NetworkSettings.Networks}}network={{$name}} ip={{$net.IPAddress}} gateway={{$net.Gateway}} mac={{$net.MacAddress}} {{end}}' amnezia-awg2 amnezia-dns
pid=$(sudo docker inspect -f '{{.State.Pid}}' amnezia-awg2)
sudo nsenter -t "$pid" -n ip -br -4 address
sudo nsenter -t "$pid" -n ip -4 route
ip -br -4 address
ip -4 route get 1.1.1.1
sudo iptables -S DOCKER-USER
sudo ip -4 rule show
sudo ip -4 nexthop show
sudo sysctl net.ipv4.ip_forward
```

Для команд `iptables` нужен Docker с доступной цепочкой `DOCKER-USER` и средствами `iptables`/`iptables-legacy` для действующего контейнера. Значение `net.ipv4.ip_forward` должно быть `1`. IPIP и GRE используют nexthop `65101` и `65102`, группа ECMP — `65100`. Маршрутизатор занимает приоритеты правил `9160–9164`, таблицы `61570–61572` на хосте и `61573` в пространстве имён AWG, а также таблицу `inet awg_geo` в nftables. Перед установкой проверьте, свободны ли эти ресурсы.

## 2. Указать параметры своего узла

```sh
sudo install -d -m 0755 /etc/awg-geo
sudo install -m 0640 ru/site.example.json /etc/awg-geo/site.json
sudoedit /etc/awg-geo/site.json
```

| Поле | Что указать |
|---|---|
| `INGRESS_PUBLIC` и `EXIT_PUBLIC` | Внешние IPv4 входного и зарубежного узлов. `198.51.100.206` и `203.0.113.124` приведены для документации. Для `EXIT_PUBLIC` важен адрес, который виден снаружи при выходе через WAN зарубежного узла. Если у провайдера NAT, адрес на интерфейсе может отличаться. |
| `WAN_IF` | Интерфейс основного выхода входного узла по `ip -4 route get`. Сверьте с `WAN_IF` в `/etc/ru-exit/tunnels.env`. |
| `AWG_IF` и `CLIENT_NET` | Имя VPN-интерфейса внутри `amnezia-awg2` и его клиентский префикс. По умолчанию в примере `awg0` и `10.8.1.0/24`. Тот же префикс указывается как `CLIENT_CIDR` на зарубежном узле. |
| `DOCKER_NET` | Имя общей сети обоих контейнеров в выводе `docker inspect`. |
| `BRIDGE_GW` и `BRIDGE_IF` | Адрес шлюза этой сети и интерфейс Linux-моста на хосте, которому назначен этот адрес. Найдите его в `ip -br -4 address`. |
| `DNS_IP` | IPv4 контейнера `amnezia-dns` в общей сети. Этот адрес должен быть DNS-сервером в профиле клиента. Если контейнер DNS получит другой адрес, обновите профиль и конфигурацию сервера. IPv4 и MAC контейнера AWG скрипт определяет автоматически. |
| `BYPASS_IPV4` | Дополнительные назначения, которым нужна исходная маршрутизация Amnezia, например инфраструктурный IPv4 как `/32`. Для обычной установки оставьте пустой список. Оба адреса узлов и служебные сети уже исключены. |

На входном мосту проход к mosdns (UDP/TCP `1053` на `BRIDGE_GW`) разрешён для сетевого интерфейса самого хоста по loopback и для пакетов с MAC контейнера AWG. Для пакетов с моста источником должен быть либо его Docker-адрес, либо `CLIENT_NET`. Существующий входной межсетевой экран хоста также должен разрешать эти запросы. На зарубежный узел из туннелей разрешены `CLIENT_CIDR` и российские `100.65.1.1/32`, `100.65.2.1/32`, которыми подписаны пробы и запросы к Cloudflare DNS. Внешней системе мониторинга достаточно читать результаты локальных проверок предусмотренным у вас способом. Прослушивание DNS на публичном WAN для этого не требуется.

## 3. Собрать DNS и загрузить базы

Выполните этот блок в одной оболочке. Для mosdns `v5.3.4` нужен Go **1.24.9 или новее**. Проверьте версию командой `go version`. На Ubuntu с Go 1.21+ можно получить минимальную версию через механизм Go toolchains. Если установлен подходящий Go, пропустите команду с `GOTOOLCHAIN`. [Версия в go.mod](https://github.com/IrineSistiana/mosdns/blob/v5.3.4/go.mod)

```sh
set -eu
export PATH="$(GOTOOLCHAIN=go1.24.9 go env GOROOT)/bin:$PATH"
go version
build=$(mktemp -d)
sudo cat /etc/awg-geo/site.json > "$build/site.json"
python3 ru/render.py "$build/site.json" "$build/config"
sh ru/mosdns-ipv6hint/build.sh "$build/mosdns"
python3 -B ru/mosdns-ipv6hint/verify_wire.py --mosdns "$build/mosdns"

sudo install -d -m 0755 /usr/local/lib/awg-geo /var/lib/awg-geo
sudo install -m 0755 "$build/mosdns" "$build/config/router" "$build/config/apply-data" ru/geo_update.py ru/health ru/rollback /usr/local/lib/awg-geo/
sudo install -m 0644 "$build/config/routing.nft" "$build/config/cloudflare.nft" /usr/local/lib/awg-geo/
sudo install -m 0644 "$build/config/mosdns.yaml" /etc/awg-geo/
sudo python3 /usr/local/lib/awg-geo/geo_update.py --no-apply
sudo test -s /var/lib/awg-geo/geoip/current/rules.txt
sudo test -s /var/lib/awg-geo/geosite/current/rules.txt
```

Скрипт сверяет контрольную сумму модуля mosdns, проверяет зависимости по `go.sum` и запускает Go-тесты фильтра. Тест `verify_wire.py` проверяет собранный бинарник на синтетических DNS-ответах по UDP и TCP. Фильтр возвращает локальный пустой NOERROR для AAAA, удаляет адресные IPv6-записи из секций ответа и `ipv6hint` из HTTPS/SVCB с учётом обязательных параметров. Для изменённых наборов снимаются подписи RRSIG и флаг AD ответа. IPv4-адреса продолжают выдаваться. [Исходник и тесты фильтра](../ru/mosdns-ipv6hint/)

При первой загрузке `--no-apply` записывает проверенные базы на диск. Если один источник недоступен, команда завершится с ошибкой. Повторите её и проверьте оба файла перед включением служб.

## 4. Запустить службы

```sh
set -eu
sudo install -m 0644 ru/systemd/*.service ru/systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now awg-geo-base.service awg-geo-dns.service
sudo systemctl enable --now awg-geo-router.service
sudo systemctl enable --now awg-geo-reconcile.timer awg-geo-health.timer awg-geo-update.timer
sudo systemctl start awg-geo-health.service
sudo systemctl list-timers --all 'awg-geo-*'
```

На мосту правила nftables различают пакеты клиентов по исходной сети и MAC контейнера. В пространстве имён AWG собственная цепочка NAT сохраняет адрес клиента для публичных назначений, а запросы к `DNS_IP:53` передаются в mosdns. Для российских доменов mosdns обращается к базовому Яндекс DNS по TLS и заносит IPv4 ответа в оба набора nftables. Остальные имена он передаёт штатному AmneziaDNS. Отдельные правила для `1.1.1.1` и `1.0.0.1` охватывают исходящие запросы самого хоста и контейнера AmneziaDNS.

`awg-geo-reconcile.timer` запускает сверку через 15 секунд после предыдущего завершения. Если Docker пересоздал AWG, скрипт заново находит его сетевое пространство, адрес и MAC и восстанавливает правила. Раз в пять минут при работающей сверке сохраняется копия двух DNS-наборов для следующей загрузки.

## 5. Проверить маршруты, DNS и переключение

```sh
sudo systemctl is-active awg-geo-base.service awg-geo-dns.service awg-geo-router.service
sudo cat /run/awg-geo/health.json
sudo nft list set inet awg_geo exit_ready
sudo ip -4 route show table 61570
for counter in geo_ru_net geo_ru_dns geo_exit geo_ru_fallback; do
    sudo nft list counter inet awg_geo "$counter"
done
gateway=$(sudo python3 -c 'import json; print(json.load(open("/etc/awg-geo/site.json"))["BRIDGE_GW"])')
dig @"$gateway" -p 1053 ya.ru A
dig +tcp @"$gateway" -p 1053 ya.ru A
dig @"$gateway" -p 1053 ya.ru AAAA
```

Ожидайте A-ответ по обоим транспортам. Для AAAA ожидаются `status: NOERROR` и `ANSWER: 0`. Выполните те же запросы **с подключённого клиента** к `DNS_IP` на обычном порту `53`. Счётчики `geo_ru_net`, `geo_ru_dns`, `geo_exit` и `geo_ru_fallback` меняются при классификации новых потоков. Если адрес уже попадает в `ru_nets`, сработает `geo_ru_net`, даже если DNS также записал его в набор.

Каждые 10 секунд монитор открывает отдельное HTTPS-соединение к `1.1.1.1/cdn-cgi/trace` через каждый туннель. Проверяется выбранный интерфейс, сертификат, HTTP 200 и ответ Cloudflare. Допустимы `warp=on`/`plus` либо совпадение поля `ip` с `EXIT_PUBLIC` при обычном выходе через зарубежный WAN. Два одинаковых результата подряд меняют состояние пути. Заполненный `exit_ready` и `new_flow_nhid` в `health.json` показывают, куда пойдут новые соединения.

| Доступные пути | Маршрут новых зарубежных соединений |
|---|---|
| Оба | ECMP, `nhid 65100`. Потоки распределяются по хешу. |
| Один | `65101` для IPIP или `65102` для GRE. |
| Ни одного | Прямой выход через российский WAN. Установленные потоки сохраняют метки conntrack и могут потребовать переподключения. |

При восстановлении двух успешных проб достаточно, чтобы путь снова принимал новые потоки. Российские назначения продолжают выходить напрямую. Пошаговые проверки с клиента, переключение и наблюдение после перезагрузки приведены отдельно. [Приёмка и диагностика](verify.md)

## 6. Ежедневное обновление

`awg-geo-update.timer` запускает обновление в **01:15 UTC** (04:15 UTC+3). `Persistent=true` позволяет наверстать пропущенный запуск после простоя. Обновлятор загружает `geoip.dat` и `geosite.dat` из последнего релиза, проверяет размер и SHA-256, извлекает IPv4 категории `RU` и доменные правила `CATEGORY-RU`. Для каждой базы отдельно хранятся `current` и при наличии `previous`. [Релизы RunetFreedom](https://github.com/runetfreedom/russia-v2ray-rules-dat/releases)

GeoIP заменяется одной транзакцией nftables. Для новой GeoSite предварительно проверяется кандидат mosdns на loopback, затем перезапускается рабочая DNS-служба и проверяется её ответ. Ошибка применения возвращает предыдущую версию затронутой базы. После успешной проверки GeoSite обновлятор раз в день по UTC очищает один из двух чередующихся DNS-наборов. Второй продолжает обслуживать уже известные адреса. Сбой одного источника допускает обновление второго и отражается в статусе systemd.

```sh
sudo systemctl start awg-geo-update.service
sudo journalctl -u awg-geo-update.service -n 25 --no-pager
sudo cat /var/lib/awg-geo/geoip/current/metadata.json /var/lib/awg-geo/geosite/current/metadata.json
```

## 7. Откат и повторный запуск

Чтобы вернуть обычную обработку трафика Amnezia на входном узле, выполните команду с установленными параметрами действующей конфигурации. Она остановит три таймера и собственные службы, снимет правила проекта в контейнере и на хосте и удалит `inet awg_geo` после сохранения DNS-наборов. Файлы баз и конфигурация останутся для восстановления. Переподключите тестового клиента и проверьте DNS, прямой выход и отсутствие таблицы.

```sh
sudo /usr/local/lib/awg-geo/rollback
sudo nft list tables
sudo systemctl is-active docker.service
```

Если меняются мост, шлюз, сеть клиентов или интерфейс WAN, сначала выполните откат со старыми файлами. Затем отредактируйте `site.json`, сгенерируйте и установите новые файлы по разделу 3. При сохранённых проверенных базах достаточно повторить разделы 4 и 5. Для полного вывода из эксплуатации остановите службы зарубежного выхода и туннелей по инструкции второго узла. [Управление туннелями и WARP](exit.md)

## Тесты без клиентского трафика

Для интеграционного теста на Linux нужны `nft`, `ip`, `unshare` и собранный mosdns. Тест создаёт таблицу и локальные маршруты внутри нового сетевого пространства, поднимает два имитатора DNS и проверяет четыре комбинации доступности обновлений.

```sh
(cd ru && python3 -B -m unittest -v test_geo_update)
sudo unshare --net python3 -B ru/integration_geo.py --mosdns /usr/local/lib/awg-geo/mosdns
```
