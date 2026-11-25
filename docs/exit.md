# Туннели между узлами и выход через WARP

Между узлом в РФ и зарубежным сервером можно поднять любой туннель с маршрутизацией IPv4. С одним туннелем достаточно обычного маршрута через него. Несколько туннелей должны заканчиваться на одном зарубежном сервере. В этом случае можно использовать ECMP для распределения потоков.

Ниже разобран пример с IPIP, GRE и ECMP. Для адресации выбраны две свободные подсети `/30` из **`100.64.0.0/10`**. Зарубежный узел выполняет NAT и возвращает ответ по тому туннелю, которым пришёл первый пакет соединения. WARP служит основным выходом, WAN зарубежного узла — резервным. Собственный трафик зарубежного сервера использует его обычный маршрут по умолчанию.

Если вы выбираете другой транспорт или число туннелей, адаптируйте создание интерфейсов, MTU, маршруты и проверки доступности на узле РФ. На зарубежном узле согласуйте имена входных интерфейсов, разрешённые исходные адреса и обратные маршруты. Готовые скрипты используют конкретные имена, адреса и идентификаторы из таблицы ниже.

| Параметр | Узел в РФ | Зарубежный узел |
|---|---|---|
| Публичный IPv4 для примера | `198.51.100.206` | `203.0.113.124` |
| `rn-ipip` | `100.65.1.1/30` | `100.65.1.2/30` |
| `rn-gre` | `100.65.2.1/30` | `100.65.2.2/30` |
| MTU IPIP и GRE | 1476 | 1476 |
| Идентификаторы nexthop | IPIP 65101, GRE 65102, группа 65100 | те же, с обратными адресами |

## 1. Подготовить оба узла

Команды рассчитаны на Debian или Ubuntu с systemd, современным ядром Linux и исходным MTU между узлами не менее 1500. Первые блоки выполняйте из корня копии репозитория на каждом узле. Адреса `198.51.100.206` и `203.0.113.124` принадлежат документационным диапазонам. Замените их реальными адресами. При NAT 1:1 в `LOCAL_IPV4` укажите назначенный на WAN локальный адрес, а в `PEER_IPV4` — доступный извне адрес соседа. NAT и межсетевые экраны по пути должны пропускать **IP-протоколы 4 (IPIP) и 47 (GRE)** в обе стороны. В существующей входной политике узла разрешите их только с адреса соседа. IPIP и GRE сами по себе передают данные без шифрования и проверки подлинности.

```sh
sudo apt-get update
sudo apt-get install -y iproute2 procps iputils-ping
ip -br -4 addr
ip -4 route show table main
ip -4 route show table all | grep -E '100\.65\.[12]\.' || true
ip nexthop show
ip link show type ipip
ip link show type gre
```

Для первой установки нужны свободные подсети из таблицы, имена `rn-ipip`, `rn-gre` и ID 65100–65102. Зарубежному узлу дополнительно нужны свободные таблицы 51873–51875, приоритеты правил 18570–18574, биты маркировки `0xf0000`, интерфейс `exit-warp` и таблица nftables `ip exit_transit`. Проверьте их перед установкой. Просмотрите пользовательские правила `fwmark` и `ct mark` на пересечение масок.

```sh
# Только на зарубежном узле
sudo apt-get install -y wireguard-tools nftables iptables conntrack curl python3 ca-certificates
ip -4 rule show
for table in 51873 51874 51875; do ip -4 route show table "$table" 2>/dev/null || true; done
ip -br link show
sudo nft list ruleset
```

Перед первой установкой сохраните действующие значения sysctl на каждом узле. Включение IPv4 forwarding меняет роль ядра на маршрутизатор. Если путь или имя unit уже заняты локальной конфигурацией, сначала согласуйте значения с ней.

```sh
sudo install -d -m 0755 /etc/ru-exit
sudo sh -c 'set -Ce; umask 077; sysctl net.ipv4.ip_forward net.ipv4.fib_multipath_hash_policy net.ipv4.conf.all.rp_filter > /etc/ru-exit/before.sysctl'
sudo install -m 0755 tunnels/ru-exit-tunnels /usr/local/sbin/
sudo install -m 0644 tunnels/ru-exit-tunnels.service /etc/systemd/system/
sudo install -m 0644 tunnels/90-ru-exit.conf /etc/sysctl.d/
```

На узле в РФ выполните:

```sh
sudo install -m 0600 tunnels/ingress.env.example /etc/ru-exit/tunnels.env
sudoedit /etc/ru-exit/tunnels.env
```

На зарубежном узле выполните:

```sh
sudo install -m 0600 tunnels/exit.env.example /etc/ru-exit/tunnels.env
sudoedit /etc/ru-exit/tunnels.env
```

Заполните `WAN_IF`, `LOCAL_IPV4` и `PEER_IPV4` на обоих узлах. На зарубежном узле задайте в `CLIENT_CIDR` фактическую клиентскую сеть AWG в РФ. Пример использует `10.8.1.0/24`. Параметры имеют формат присваиваний POSIX shell. Файл принадлежит root и доступен для записи только владельцу.

```sh
sudo sysctl -p /etc/sysctl.d/90-ru-exit.conf
sudo systemctl daemon-reload
sudo systemctl enable --now ru-exit-tunnels.service
ip -br -4 addr show | grep -E 'rn-ipip|rn-gre'
ip nexthop show
```

С узла в РФ проверьте `ping -I rn-ipip -c 3 100.65.1.2` и `ping -I rn-gre -c 3 100.65.2.2`. С зарубежного узла повторите пробы к адресам `.1` соответствующих подсетей. Если проходят пакеты обычного размера, а крупные зависают, повторите пробу с `-M do -s 1448`. Это 1476 байт вместе с заголовками IPv4 и ICMP. При меньшем MTU внешнего пути подберите меньший MTU для обоих концов в скрипте туннелей. Проверьте также доставку ICMP fragmentation needed.

## 2. Зарегистрировать WARP на зарубежном узле

Скачайте закреплённую версию wgcf для Linux x86-64 и сверьте SHA-256 **до запуска**. Для другой архитектуры выберите её бинарный файл и соответствующий digest в том же выпуске. [Выпуск wgcf v2.3.1](https://github.com/ViRb3/wgcf/releases/tag/v2.3.1).

```sh
(
  set -eu
  test "$(uname -m)" = x86_64
  tmp=$(mktemp)
  trap 'rm -f "$tmp"' EXIT
  curl --proto '=https' -fsSL https://github.com/ViRb3/wgcf/releases/download/v2.3.1/wgcf_2.3.1_linux_amd64 -o "$tmp"
  printf '%s  %s\n' 4fb7a136aa470ece11d17949c7db07b040ec9c604742dc8680bcf1889f85d0c8 "$tmp" | sha256sum -c -
  sudo install -m 0755 "$tmp" /usr/local/bin/wgcf
)
sudo install -d -m 0700 /etc/ru-exit/wgcf /etc/wireguard
sudo install -m 0755 exit/make-warp-profile /usr/local/sbin/
sudo sh -ec 'cd /etc/ru-exit/wgcf; umask 077; test -s wgcf-account.toml || /usr/local/bin/wgcf register'
sudo sh -ec 'cd /etc/ru-exit/wgcf; umask 077; /usr/local/bin/wgcf generate --keepalive'
sudo /usr/local/sbin/make-warp-profile /etc/ru-exit/wgcf/wgcf-profile.conf /etc/wireguard/exit-warp.conf
sudo wg-quick strip /etc/wireguard/exit-warp.conf >/dev/null
sudo systemctl enable --now wg-quick@exit-warp.service
```

При регистрации wgcf покажет условия WARP и запросит их принятие. У каждого узла свой профиль. Каталог `/etc/ru-exit/wgcf` и файл `/etc/wireguard/exit-warp.conf` содержат секреты. Генератор извлекает IPv4-адрес и ключи зарегистрированного устройства, определяет IPv4 endpoint, выставляет `Table = off`, `AllowedIPs = 0.0.0.0/0`, MTU 1280 и keepalive 25 секунд. Он завершится с ошибкой при существующем целевом файле. Для смены endpoint сохраните профиль под другим закрытым именем, проверьте его и замените действующий файл во время обслуживания. WARP должен иметь исходящий доступ по UDP к выбранному endpoint.

## 3. Включить выбор выхода и симметричный возврат

Выполните на зарубежном узле:

```sh
sudo install -m 0755 exit/exit-router exit/exit-health /usr/local/sbin/
sudo install -m 0644 exit/exit-policy.nft /etc/ru-exit/
sudo install -m 0644 exit/exit-router.service exit/exit-health.service exit/exit-health.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now exit-router.service
sudo systemctl enable --now exit-health.timer
sudo systemctl start exit-health.service
sudo nft list set ip exit_transit warp_ingress
sudo wg show exit-warp latest-handshakes
ip -4 rule show
```

Проверка привязывает HTTPS-запрос к интерфейсу `exit-warp` через правило `oif`, сверяет сертификат и ищет строку `warp=on` или `warp=plus` в ответе. Следующая проверка начинается через восемь секунд после окончания предыдущей. При успехе в наборе `warp_ingress` видны оба туннеля. Пустой набор выбирает WAN для новых потоков.

Для первого пакета conntrack сохраняет входной интерфейс и выбранный выход. Метка пакета выбирает таблицу 51873 для WARP или `main` для WAN. В обратном направлении таблица 51874 возвращает ответ в GRE, таблица 51875 — в IPIP. Обе таблицы указывают на соответствующий адрес узла в РФ. Резервный выход берётся из IPv4 default в `main` и должен вести через `WAN_IF`. NAT действует при выходе через WARP и через WAN. В обоих направлениях TCP MSS ограничен 1240 байтами. Для TCP сохраняется прежняя привязка до завершения соединения. При обрыве WARP клиент открывает новое соединение. Для UDP и ICMP монитор удаляет только записи, привязанные к потерянному WARP, чтобы повторный запрос с теми же портами мог сразу использовать WAN.

На узлах с Docker и цепочкой `DOCKER-USER` скрипт добавляет в эту цепочку разрешения для маркированного транзита и его ответов. Если фильтрацией управляет отдельный межсетевой экран, разрешите в его цепочке FORWARD трафик из `rn-ipip` и `rn-gre` через WARP и WAN и ответы established/related в обратную сторону. При перезагрузке правил, которая очищает весь ruleset или цепочку Docker, выполните `sudo systemctl reload exit-router && sudo systemctl start exit-health`.

## 4. Проверить выход

На зарубежном узле команды ниже показывают WARP и оба обратных пути:

```sh
curl --noproxy '*' -4fsS --interface 'if!exit-warp' https://1.1.1.1/cdn-cgi/trace | grep -E '^(ip|warp)='
ip -4 route get 10.8.1.2 mark 0x10000
ip -4 route get 10.8.1.2 mark 0x20000
ip -4 route get 1.1.1.1 mark 0x40000
ip -4 route get 1.1.1.1 mark 0x80000
sudo nft list chain ip exit_transit nat
```

Ожидаются соответственно `rn-gre`, `rn-ipip`, `exit-warp` и ваш WAN. С реального клиента AWG после включения правил на узле в РФ выполните новый запрос к адресу, для которого выбран зарубежный путь, и проверьте внешний IP или счётчик NAT на зарубежном узле. Для проверки TCP без влияния DNS и отдельного правила для DNS-серверов можно использовать `curl -4fsS https://www.cloudflare.com/cdn-cgi/trace | grep -E '^(ip|warp)='`, если IPv4 этого имени входит в политику зарубежного пути.

Для контролируемой проверки резерва на зарубежном узле выполните `sudo systemctl stop wg-quick@exit-warp`. Это прервёт соединения через WARP. Запустите `sudo systemctl start exit-health`, убедитесь в пустом `warp_ingress` и повторите запрос **новым** соединением с клиента. Должны появиться внешний IPv4 зарубежного WAN и `warp=off`. Восстановите `sudo systemctl start wg-quick@exit-warp && sudo systemctl start exit-health` и повторите проверку новым соединением. Поднятый интерфейс сам по себе ещё не подтверждает успешный транзит.

## 5. Откат

Сначала остановите на узле в РФ компоненты клиентской маршрутизации, использующие nexthop 65100–65102. На зарубежном узле отключите монитор, удалите правила из пакета и остановите WARP:

```sh
sudo systemctl disable --now exit-health.timer
sudo systemctl stop exit-health.service
sudo systemctl disable --now exit-router.service
sudo /usr/local/sbin/exit-router down
sudo systemctl disable --now wg-quick@exit-warp.service
```

На каждом узле остановите сервис туннелей. Удаление группы nexthop влияет на все маршруты, которые её используют. Предварительно убедитесь, что остальные сервисы освободили ID:

```sh
ip -4 route show table all | grep -E 'nhid 6510[012]( |$)' || true
sudo systemctl disable --now ru-exit-tunnels.service
sudo ip nexthop del id 65100
sudo ip nexthop del id 65101
sudo ip nexthop del id 65102
sudo ip link del dev rn-ipip
sudo ip link del dev rn-gre
sudo rm /etc/sysctl.d/90-ru-exit.conf
sudo sysctl -p /etc/ru-exit/before.sysctl
```

Изменение forwarding и multipath действует на весь узел. Восстанавливайте их прежние значения, если они по-прежнему подходят остальным службам. Приватные данные регистрации можно сохранить для повторной установки.
