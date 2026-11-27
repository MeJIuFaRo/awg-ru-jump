# Резервный WARP через официальный клиент Cloudflare

Выполняйте команды на зарубежном узле из корня копии репозитория. Основной выход — WireGuard-интерфейс `exit-warp` с профилем от wgcf. Резервный — официальный Linux-клиент Cloudflare в режиме MASQUE. Для него используется отдельная регистрация и отдельное сетевое пространство Docker. На узле РФ и в клиентских профилях AmneziaWG ничего менять не требуется. [Установка основного выхода](exit.md) · [Официальный Linux-клиент](https://developers.cloudflare.com/warp-client/get-started/linux/)

## 1. Проверить ресурсы

На чистом зарубежном узле установите Docker Engine и запустите его службу командой `sudo systemctl enable --now docker.service`. Если Docker уже обслуживает другие контейнеры, используйте имеющуюся установку. [Установка Docker Engine на Ubuntu](https://docs.docker.com/engine/install/ubuntu/)

Пример рассчитан на Ubuntu с systemd, Docker Engine и архитектурой `amd64`. Нужны `/dev/net/tun`, исходящий доступ к репозиториям и Cloudflare и установленные на хосте `iproute2`, `nftables`, `util-linux` и `curl`. Проверьте, что подсеть `10.254.247.0/30` свободна, в том числе в маршрутах других VPN и сетях Docker. Имена `cfw-host`, `cfw-in`, таблица 51876 и приоритет 18554 служат для связи с контейнером. Внутри его пространства используются отдельная таблица 51907 и собственные правила.

```sh
uname -m
sudo docker version --format '{{.Server.Version}}'
test -c /dev/net/tun
ip -br -4 addr
ip -4 rule show
ip -4 route show table all match 10.254.247.0/30
ip -4 route show table 51876 2>/dev/null || true
sudo docker network ls
```

## 2. Собрать образ и зарегистрировать клиент

[Dockerfile](../exit/official/Dockerfile) использует Ubuntu 24.04 и пакет `cloudflare-warp` закреплённой версии из подписанного APT-репозитория Cloudflare. Команды рассчитаны на первую установку. Для повторного запуска существующего контейнера используйте `sudo docker start exit-official-warp`. При пересоздании подключите тот же том регистрации. [Репозиторий пакетов Cloudflare](https://pkg.cloudflareclient.com/)

```sh
sudo docker build --platform linux/amd64 -t exit-official-warp:2026.8.2115.0 exit/official
sudo docker volume create exit-official-warp-state
sudo docker run -d --name exit-official-warp --restart unless-stopped \
  --network bridge --dns 1.1.1.1 --dns 1.0.0.1 \
  --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 \
  --sysctl net.ipv4.conf.all.rp_filter=2 --sysctl net.ipv4.conf.default.rp_filter=2 \
  --sysctl net.ipv6.conf.all.disable_ipv6=0 \
  --log-opt max-size=8m --log-opt max-file=2 \
  --mount type=volume,src=exit-official-warp-state,dst=/var/lib/cloudflare-warp \
  exit-official-warp:2026.8.2115.0
sudo docker exec exit-official-warp warp-cli --version
```

Один раз на новом томе зарегистрируйте устройство. Флаг `--accept-tos` подтверждает принятие условий WARP. Том содержит состояние устройства, используйте его только на своём узле. Если клиент ещё запускается, дождитесь ответа `warp-cli status` перед регистрацией.

```sh
sudo docker exec exit-official-warp warp-cli --accept-tos registration new
sudo docker exec exit-official-warp warp-cli --accept-tos mode warp
sudo docker exec exit-official-warp warp-cli --accept-tos tunnel protocol set MASQUE
sudo docker exec exit-official-warp warp-cli --accept-tos connect
sudo docker exec exit-official-warp warp-cli --accept-tos status
sudo docker exec exit-official-warp warp-cli --accept-tos tunnel stats
```

Дождитесь `Connected` и проверьте, что `Tunnel Protocol` показывает MASQUE. Режим `warp` предназначен для IP-трафика. Внешнее соединение самого `warp-svc` идёт через обычную сеть Docker и WAN зарубежного узла.

## 3. Подключить транзитный интерфейс

```sh
sudo install -d -m 0755 /usr/local/lib/ru-exit-official
sudo install -m 0755 exit/official/gateway /usr/local/lib/ru-exit-official/
sudo install -m 0644 exit/official/inside.nft /usr/local/lib/ru-exit-official/
sudo install -m 0644 exit/official/exit-official-gateway.service exit/official/exit-official-gateway.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now exit-official-gateway.timer
sudo systemctl start exit-official-gateway.service
ip -4 route get 1.1.1.1 oif cfw-host
curl --noproxy '*' -4fsS --interface 'if!cfw-host' --connect-timeout 3 --max-time 8 \
  https://1.1.1.1/cdn-cgi/trace | grep -E '^(ip|warp)='
```

Ожидаемый маршрут — через `10.254.247.2 dev cfw-host`, ответ — `warp=on` или `warp=plus`. Эта проба начинается на хосте и действительно проходит **через** контейнер. Внутри контейнера пакет с транзитного интерфейса `cfw-in` разрешён только в `CloudflareWARP`. NAT обеспечивает обратный путь через ту же пару veth. Таймер восстанавливает соединение с актуальным сетевым пространством при пересоздании контейнера.

## 4. Включить автоматический выбор

При первой установке продолжите с раздела 3 [руководства зарубежного узла](exit.md). Для действующей двухступенчатой установки используйте там же блок обновления: нужны новые `exit-health`, `exit-router` и `exit-policy.nft`. После применения выполните:

```sh
sudo systemctl start exit-health.service
sudo /usr/local/sbin/exit-health status
sudo systemctl list-timers exit-health.timer exit-official-gateway.timer
```

Ожидаемый порядок для **новых соединений**:

| Доступность | Выход |
|---|---|
| Оба WARP работают | wgcf |
| wgcf недоступен, MASQUE работает | Официальный клиент |
| Оба WARP недоступны | WAN зарубежного узла |
| MASQUE восстановился первым | MASQUE до восстановления wgcf |
| wgcf снова работает | wgcf, включая случай, когда MASQUE тоже здоров |

Оба клиента WARP могут дать одинаковый публичный IP. Чтобы подтвердить именно MASQUE, посмотрите `effective_backend` и сравните счётчики до и после нового соединения с устройства AmneziaWG:

```sh
sudo /usr/local/sbin/exit-health status
sudo nft list chain ip exit_transit nat
sudo docker exec exit-official-warp nft list chain inet exit_official_forward nat
```

Для официального выхода увеличатся счётчики NAT на `cfw-host` и внутри контейнера на `CloudflareWARP`. [Проверка всех переходов](verify.md#4-проверить-автоматическое-переключение)

## Отключить только официальный резерв

Для планового снятия резерва дождитесь восстановления wgcf и проверьте `effective_backend`. Соединения, всё ещё проходящие через MASQUE, могут прерваться при отключении. Оставьте монитор основного выхода включённым. Сначала снимите транзитный интерфейс при работающем контейнере, затем остановите контейнер. В отсутствие wgcf для новых соединений будет выбран WAN.

```sh
sudo systemctl disable --now exit-official-gateway.timer
sudo systemctl stop exit-official-gateway.service
sudo /usr/local/lib/ru-exit-official/gateway down
sudo systemctl start exit-health.service
sudo /usr/local/sbin/exit-health status
sudo docker stop exit-official-warp
```

Том регистрации сохраняется. Для повторного включения запустите контейнер, включите таймер шлюза, выполните разделы 3–4 и проверьте `warp=on` через `cfw-host`.
