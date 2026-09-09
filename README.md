# gcs-tcpip

Учебная реализация стека TCP/IP поверх Ethernet на C11. Разбор и сборка кадров
выполняются вручную, без использования сокетов ядра: стек получает на вход
сырой Ethernet-кадр и возвращает готовый кадр ответа.

Проект выполнен в рамках проектной практики, тема взята из раздела
**Network Stack** каталога [build-your-own-x][byox].

## Что реализовано

| Уровень | Протокол | Состояние |
| --- | --- | --- |
| Канальный | Ethernet II | разбор и сборка заголовка, фильтрация по MAC |
| Сетевой | ARP (RFC 826) | запрос, ответ, таблица соответствий с логикой merge |
| Сетевой | IPv4 (RFC 791) | разбор, контрольная сумма заголовка, сборка |
| Транспортный | ICMPv4 (RFC 792) | echo request и echo reply |
| Транспортный | TCP (RFC 793) | рукопожатие, передача данных, закрытие, RST |

## Сборка

```
git submodule update --init --recursive
GCST_WERROR=ON ./build.sh --preset unix-gcc-libstdc++
```

## Запуск

Основной режим — прогон по заранее записанному захвату. Привилегий не требует
и полностью воспроизводим:

```
python3 tools/gcs_make_sample.py data/sample.pcap
./bin/GCS.Replay --in data/sample.pcap --out data/replies.pcap
tcpdump -r data/replies.pcap -n -vv
```

Второй режим — живой интерфейс TAP. Требует `CAP_NET_ADMIN`:

```
sudo setcap cap_net_admin+ep ./bin/GCS.Tapd
./bin/GCS.Tapd --dev gcstap0 --ip 10.0.0.2 &
sudo ip addr add 10.0.0.1/24 dev gcstap0
sudo ip link set gcstap0 up
ping 10.0.0.2
```

## Структура

```
.gcst/            presets.json и скрипты конвейера (владеет шаблон)
cmake/gcst/       утилиты и наборы предупреждений (владеет шаблон)
cmake/gcs/        проектный слой поверх шаблона
external/         CMakeAutoBuild как submodule
include/gcstcpip/ публичные заголовки
src/              реализация, модуль gcsll_tcpip -> gcsll::tcpip
app/              GCS.Replay (pcap) и GCS.Tapd (живой TAP)
tools/            генератор эталонного захвата
data/             эталонные захваты
docs/             техническое руководство
```

## Документация

Пошаговое руководство по построению стека: [docs/guide.md](docs/guide.md).

[byox]: https://github.com/codecrafters-io/build-your-own-x
[template]: https://github.com/Gaymocoder/CMakeAutoBuild
