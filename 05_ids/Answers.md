# Мониторинг сетевых событий (Suricata)

### Задание 1
### Напишите правило для детектирования Xmas-сканирования.

Сканирование Xmas заключается в очистке заголовка SYN из TCP-пакета и замене его битами FIN, PSH и URG (или заголовками Or) в обход брандмауэра.
```
#alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SCAN nmap XMAS"; flow:stateless; flags:FPU,12; sid:1;)
```

### Задание 2

Напишите правило для детектирования стороннего трафика, передающегося службой DNS.
```
alert dns $EXTERNAL_NET any -> $HOME_NET any (msg:"Test dns.query option"; dns.query; content:"../../../"; nocase; sid:1;)
```

### Задание 3*

Напишите правило для детектирования файлов или документов в сетевом трафике.

#alert http $EXTERNAL_NET any -> $HOME_NET (msg:"incorrect magic byte"; flow:established,to_client; fileext:"pdf"; filemagic:!"PDF document"; filestore; sid:1;)
